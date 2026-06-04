/**
 * Hybrid Search Service
 * Phase 1: SOTA Upgrade - Semantic Search Foundation
 *
 * Implements hybrid search combining:
 * 1. Keyword search (BM25-like via PostgreSQL full-text)
 * 2. Semantic search (vector similarity using pgvector)
 * 3. Metadata filtering (dates, types, confidence levels)
 *
 * Uses Reciprocal Rank Fusion (RRF) to combine results
 */

import { db } from "./db";
import { timelineEntries, type TimelineEntry } from "@shared/schema";
import { sql, and, or, like, isNull, desc, eq, gte, lte, inArray } from "drizzle-orm";
import { embeddingService } from "./embeddingService";

export interface HybridSearchOptions {
  caseId: string;
  query: string;
  topK?: number;
  alpha?: number; // 0 = pure keyword, 1 = pure semantic, 0.5 = balanced
  filters?: {
    entryType?: 'task' | 'event';
    dateFrom?: string;
    dateTo?: string;
    confidenceLevel?: string[];
    tags?: string[];
    eventSubtype?: string;
    taskSubtype?: string;
  };
}

export interface SearchResult {
  entry: TimelineEntry;
  score: number;
  matchType: 'keyword' | 'semantic' | 'hybrid';
  highlights?: string[];
  similarity?: number; // For semantic matches
}

export interface SearchResponse {
  results: SearchResult[];
  metadata: {
    query: string;
    totalResults: number;
    searchType: 'keyword' | 'semantic' | 'hybrid';
    executionTimeMs: number;
    alpha: number;
  };
}

/**
 * Perform hybrid search on timeline entries
 */
export async function hybridSearch(
  options: HybridSearchOptions
): Promise<SearchResponse> {
  const startTime = Date.now();

  const {
    caseId,
    query,
    topK = 20,
    alpha = 0.6, // Default: 60% semantic, 40% keyword
    filters,
  } = options;

  // Validate query
  if (!query || query.trim().length === 0) {
    throw new Error("Search query cannot be empty");
  }

  try {
    // 1. Generate query embedding for semantic search
    const queryEmbedding = await embeddingService.generateEmbedding(query);
    const queryVector = `[${queryEmbedding.embedding.join(",")}]`;

    // 2. Perform keyword search
    const keywordResults = await keywordSearch(caseId, query, filters, topK * 2); // Get more for fusion

    // 3. Perform semantic search
    const semanticResults = await semanticSearch(
      caseId,
      queryVector,
      filters,
      topK * 2 // Get more for fusion
    );

    // 4. Fuse results using Reciprocal Rank Fusion
    const fusedResults = reciprocalRankFusion(
      keywordResults,
      semanticResults,
      alpha,
      60 // RRF constant k
    );

    // 5. Take top K results
    const finalResults = fusedResults.slice(0, topK);

    const executionTime = Date.now() - startTime;

    return {
      results: finalResults,
      metadata: {
        query,
        totalResults: finalResults.length,
        searchType: 'hybrid',
        executionTimeMs: executionTime,
        alpha,
      },
    };

  } catch (error) {
    console.error("Error in hybrid search:", error);

    // Fallback to keyword-only search if embedding fails
    console.log("Falling back to keyword-only search");
    const keywordResults = await keywordSearch(caseId, query, filters, topK);

    return {
      results: keywordResults,
      metadata: {
        query,
        totalResults: keywordResults.length,
        searchType: 'keyword',
        executionTimeMs: Date.now() - startTime,
        alpha: 0,
      },
    };
  }
}

/**
 * Keyword search using PostgreSQL LIKE (future: full-text search)
 */
async function keywordSearch(
  caseId: string,
  query: string,
  filters: HybridSearchOptions['filters'],
  topK: number
): Promise<SearchResult[]> {

  const whereConditions: any[] = [
    eq(timelineEntries.caseId, caseId),
    isNull(timelineEntries.deletedAt),
    or(
      like(timelineEntries.description, `%${query}%`),
      like(timelineEntries.detailedNotes, `%${query}%`)
    ),
  ];

  // Apply filters
  if (filters?.entryType) {
    whereConditions.push(eq(timelineEntries.entryType, filters.entryType));
  }

  if (filters?.dateFrom) {
    whereConditions.push(gte(timelineEntries.date, filters.dateFrom));
  }

  if (filters?.dateTo) {
    whereConditions.push(lte(timelineEntries.date, filters.dateTo));
  }

  if (filters?.confidenceLevel && filters.confidenceLevel.length > 0) {
    whereConditions.push(
      inArray(timelineEntries.confidenceLevel, filters.confidenceLevel as any[])
    );
  }

  const results = await db
    .select()
    .from(timelineEntries)
    .where(and(...whereConditions))
    .limit(topK)
    .orderBy(desc(timelineEntries.date));

  return results.map((entry, idx) => ({
    entry,
    score: 1.0 / (idx + 1), // Simple scoring: 1/rank
    matchType: 'keyword' as const,
    highlights: extractHighlights(entry, query),
  }));
}

/**
 * Semantic search using pgvector similarity
 */
async function semanticSearch(
  caseId: string,
  queryVector: string,
  filters: HybridSearchOptions['filters'],
  topK: number
): Promise<SearchResult[]> {

  // Build parameterized conditions (no string interpolation of user input)
  const conditions: ReturnType<typeof sql>[] = [
    sql`${timelineEntries.caseId} = ${caseId}`,
    sql`${timelineEntries.deletedAt} IS NULL`,
    sql`${timelineEntries.contentEmbedding} IS NOT NULL`,
  ];

  if (filters?.entryType) {
    conditions.push(sql`${timelineEntries.entryType} = ${filters.entryType}`);
  }
  if (filters?.dateFrom) {
    conditions.push(sql`${timelineEntries.date} >= ${filters.dateFrom}`);
  }
  if (filters?.dateTo) {
    conditions.push(sql`${timelineEntries.date} <= ${filters.dateTo}`);
  }

  const whereClause = sql.join(conditions, sql` AND `);

  // Execute semantic search with parameterized vector binding
  const results = await db.execute(sql`
    SELECT
      *,
      1 - (content_embedding <=> ${queryVector}::vector) as similarity
    FROM timeline_entries
    WHERE ${whereClause}
    ORDER BY content_embedding <=> ${queryVector}::vector
    LIMIT ${topK}
  `);

  return results.rows.map((row: any) => ({
    entry: row as TimelineEntry,
    score: row.similarity || 0,
    matchType: 'semantic' as const,
    similarity: row.similarity || 0,
  }));
}

/**
 * Reciprocal Rank Fusion algorithm
 * Combines keyword and semantic search results
 *
 * RRF Score = Σ 1 / (k + rank)
 * where k is a constant (typically 60)
 */
function reciprocalRankFusion(
  keywordResults: SearchResult[],
  semanticResults: SearchResult[],
  alpha: number,
  k: number = 60
): SearchResult[] {

  const scoreMap = new Map<string, {
    entry: TimelineEntry;
    score: number;
    matchType: 'keyword' | 'semantic' | 'hybrid';
    highlights?: string[];
    similarity?: number;
  }>();

  // Score keyword results with weight (1 - alpha)
  keywordResults.forEach((result, idx) => {
    const rrfScore = (1 - alpha) / (k + idx + 1);
    scoreMap.set(result.entry.id, {
      entry: result.entry,
      score: rrfScore,
      matchType: 'keyword',
      highlights: result.highlights,
    });
  });

  // Add/merge semantic results with weight alpha
  semanticResults.forEach((result, idx) => {
    const rrfScore = alpha / (k + idx + 1);
    const existing = scoreMap.get(result.entry.id);

    if (existing) {
      // Entry found in both searches - combine scores
      scoreMap.set(result.entry.id, {
        entry: result.entry,
        score: existing.score + rrfScore,
        matchType: 'hybrid',
        highlights: existing.highlights,
        similarity: result.similarity,
      });
    } else {
      // Entry only in semantic search
      scoreMap.set(result.entry.id, {
        entry: result.entry,
        score: rrfScore,
        matchType: 'semantic',
        similarity: result.similarity,
      });
    }
  });

  // Convert to array and sort by combined score
  return Array.from(scoreMap.values())
    .sort((a, b) => b.score - a.score)
    .map(item => ({
      entry: item.entry,
      score: item.score,
      matchType: item.matchType,
      highlights: item.highlights,
      similarity: item.similarity,
    }));
}

/**
 * Extract highlighted snippets from entry matching the query
 */
function extractHighlights(entry: TimelineEntry, query: string): string[] {
  const highlights: string[] = [];
  const queryLower = query.toLowerCase();

  // Extract snippets from description
  if (entry.description?.toLowerCase().includes(queryLower)) {
    highlights.push(createSnippet(entry.description, query, 100));
  }

  // Extract snippets from detailed notes
  if (entry.detailedNotes?.toLowerCase().includes(queryLower)) {
    highlights.push(createSnippet(entry.detailedNotes, query, 100));
  }

  return highlights;
}

/**
 * Create a snippet with context around the query match
 */
function createSnippet(
  text: string,
  query: string,
  contextChars: number = 100
): string {
  const queryLower = query.toLowerCase();
  const textLower = text.toLowerCase();
  const idx = textLower.indexOf(queryLower);

  if (idx === -1) return text.substring(0, 200) + '...';

  const start = Math.max(0, idx - contextChars);
  const end = Math.min(text.length, idx + query.length + contextChars);

  return (
    (start > 0 ? '...' : '') +
    text.substring(start, end) +
    (end < text.length ? '...' : '')
  );
}

/**
 * Keyword-only search (fallback when semantic search unavailable)
 */
export async function keywordOnlySearch(
  caseId: string,
  query: string,
  topK: number = 20,
  filters?: HybridSearchOptions['filters']
): Promise<SearchResponse> {

  const startTime = Date.now();
  const results = await keywordSearch(caseId, query, filters, topK);

  return {
    results,
    metadata: {
      query,
      totalResults: results.length,
      searchType: 'keyword',
      executionTimeMs: Date.now() - startTime,
      alpha: 0,
    },
  };
}

/**
 * Semantic-only search (for testing/debugging)
 */
export async function semanticOnlySearch(
  caseId: string,
  query: string,
  topK: number = 20,
  filters?: HybridSearchOptions['filters']
): Promise<SearchResponse> {

  const startTime = Date.now();

  try {
    const queryEmbedding = await embeddingService.generateEmbedding(query);
    const queryVector = `[${queryEmbedding.embedding.join(",")}]`;
    const results = await semanticSearch(caseId, queryVector, filters, topK);

    return {
      results,
      metadata: {
        query,
        totalResults: results.length,
        searchType: 'semantic',
        executionTimeMs: Date.now() - startTime,
        alpha: 1.0,
      },
    };
  } catch (error) {
    console.error("Error in semantic search:", error);
    throw error;
  }
}

export const searchService = {
  hybridSearch,
  keywordOnlySearch,
  semanticOnlySearch,
};
