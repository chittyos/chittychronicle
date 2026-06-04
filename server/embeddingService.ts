/**
 * Embedding Service for Semantic Search
 * Phase 1: SOTA Upgrade - Semantic Search Foundation
 *
 * Generates vector embeddings for legal documents using:
 * - OpenAI text-embedding-3-small (1536 dimensions, general-purpose)
 * - Future: Legal-BERT (768 dimensions, legal-specific)
 */

import OpenAI from "openai";
import { db } from "./db";
import { timelineEntries, timelineSources } from "@shared/schema";
import { eq, isNull, sql } from "drizzle-orm";

// Initialize OpenAI client only if API key is available
const openai = process.env.OPENAI_API_KEY
  ? new OpenAI({
      apiKey: process.env.OPENAI_API_KEY,
    })
  : null;

// Helper to check if embedding service is available
function ensureEmbeddingServiceAvailable(): void {
  if (!openai) {
    throw new Error(
      "Embedding service unavailable: OPENAI_API_KEY not configured. " +
      "Please set the OPENAI_API_KEY environment variable to enable semantic search features."
    );
  }
}

// Configuration
const EMBEDDING_CONFIG = {
  model: process.env.EMBEDDING_MODEL || "text-embedding-3-small",
  dimensions: parseInt(process.env.EMBEDDING_DIMENSIONS || "1536"),
  batchSize: 100, // Process this many texts at once
  maxTokens: 8000, // OpenAI limit per request
  enableLegalBert: process.env.ENABLE_LEGAL_BERT === "true",
};

export interface EmbeddingResult {
  embedding: number[];
  model: string;
  dimensions: number;
  tokensUsed: number;
}

export interface BatchEmbeddingResult {
  embeddings: number[][];
  model: string;
  totalTokens: number;
  processedCount: number;
}

/**
 * Generate embedding for a single text using OpenAI
 */
export async function generateEmbedding(
  text: string,
  model: string = EMBEDDING_CONFIG.model
): Promise<EmbeddingResult> {
  ensureEmbeddingServiceAvailable();

  if (!text || text.trim().length === 0) {
    throw new Error("Text cannot be empty for embedding generation");
  }

  // Truncate if too long (OpenAI has token limits)
  const truncatedText = text.substring(0, 32000); // Approx 8000 tokens

  try {
    const response = await openai.embeddings.create({
      model,
      input: truncatedText,
      encoding_format: "float",
    });

    return {
      embedding: response.data[0].embedding,
      model: response.model,
      dimensions: response.data[0].embedding.length,
      tokensUsed: response.usage.total_tokens,
    };
  } catch (error) {
    console.error("Error generating embedding:", error);
    throw new Error(`Failed to generate embedding: ${error.message}`);
  }
}

/**
 * Generate embeddings for multiple texts in batch
 * More efficient for processing many documents
 */
export async function generateBatchEmbeddings(
  texts: string[],
  model: string = EMBEDDING_CONFIG.model
): Promise<BatchEmbeddingResult> {

  if (texts.length === 0) {
    return {
      embeddings: [],
      model,
      totalTokens: 0,
      processedCount: 0,
    };
  }

  // Filter out empty texts
  const validTexts = texts
    .map(t => t?.trim() || "")
    .filter(t => t.length > 0)
    .map(t => t.substring(0, 32000)); // Truncate

  if (validTexts.length === 0) {
    throw new Error("No valid texts to embed");
  }

  try {
    const response = await openai.embeddings.create({
      model,
      input: validTexts,
      encoding_format: "float",
    });

    return {
      embeddings: response.data.map(d => d.embedding),
      model: response.model,
      totalTokens: response.usage.total_tokens,
      processedCount: validTexts.length,
    };
  } catch (error) {
    console.error("Error generating batch embeddings:", error);
    throw new Error(`Failed to generate batch embeddings: ${error.message}`);
  }
}

/**
 * Generate embedding for a timeline entry's description
 */
export async function embedTimelineEntry(entryId: string): Promise<void> {
  // Fetch the entry
  const entries = await db
    .select()
    .from(timelineEntries)
    .where(eq(timelineEntries.id, entryId))
    .limit(1);

  if (entries.length === 0) {
    throw new Error(`Timeline entry ${entryId} not found`);
  }

  const entry = entries[0];

  // Prepare text for embedding
  // Combine description and detailed notes for richer semantic representation
  const textToEmbed = [
    entry.description,
    entry.detailedNotes,
    // Include tags for additional context
    entry.tags?.join(", "),
  ]
    .filter(Boolean)
    .join("\n\n");

  if (!textToEmbed.trim()) {
    console.warn(`Entry ${entryId} has no text to embed`);
    return;
  }

  // Generate embedding
  const result = await generateEmbedding(textToEmbed);

  // Update the entry with embedding (customType handles vector serialization)
  await db
    .update(timelineEntries)
    .set({
      contentEmbedding: result.embedding,
      embeddingModel: result.model,
      embeddingGeneratedAt: new Date(),
    })
    .where(eq(timelineEntries.id, entryId));

  console.log(
    `Generated embedding for entry ${entryId} (${result.dimensions}D, ${result.tokensUsed} tokens)`
  );
}

/**
 * Generate embeddings for all timeline entries that don't have them yet
 * Processes in batches for efficiency
 */
export async function embedAllMissingEntries(
  caseId?: string,
  batchSize: number = EMBEDDING_CONFIG.batchSize
): Promise<{
  processed: number;
  totalTokens: number;
  errors: number;
}> {
  let stats = {
    processed: 0,
    totalTokens: 0,
    errors: 0,
  };

  console.log("Finding timeline entries without embeddings...");

  // Find entries without embeddings
  let whereConditions = [
    isNull(timelineEntries.contentEmbedding),
    isNull(timelineEntries.deletedAt),
  ];

  if (caseId) {
    whereConditions.push(eq(timelineEntries.caseId, caseId));
  }

  const entriesToEmbed = await db
    .select({
      id: timelineEntries.id,
      description: timelineEntries.description,
      detailedNotes: timelineEntries.detailedNotes,
      tags: timelineEntries.tags,
    })
    .from(timelineEntries)
    .where(sql`${sql.join(whereConditions, sql` AND `)}`);

  console.log(`Found ${entriesToEmbed.length} entries to embed`);

  if (entriesToEmbed.length === 0) {
    return stats;
  }

  // Process in batches
  for (let i = 0; i < entriesToEmbed.length; i += batchSize) {
    const batch = entriesToEmbed.slice(i, i + batchSize);

    console.log(
      `Processing batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(entriesToEmbed.length / batchSize)}...`
    );

    try {
      // Prepare texts
      const texts = batch.map(entry =>
        [entry.description, entry.detailedNotes, entry.tags?.join(", ")]
          .filter(Boolean)
          .join("\n\n")
      );

      // Generate embeddings
      const result = await generateBatchEmbeddings(texts);
      stats.totalTokens += result.totalTokens;

      // Update entries
      for (let j = 0; j < batch.length; j++) {
        const entry = batch[j];
        const embedding = result.embeddings[j];

        try {
          await db
            .update(timelineEntries)
            .set({
              contentEmbedding: embedding,
              embeddingModel: result.model,
              embeddingGeneratedAt: new Date(),
            })
            .where(eq(timelineEntries.id, entry.id));

          stats.processed++;
        } catch (updateError) {
          console.error(`Error updating entry ${entry.id}:`, updateError);
          stats.errors++;
        }
      }

      console.log(
        `Batch complete: ${batch.length} entries, ${result.totalTokens} tokens`
      );

      // Rate limiting: wait 1 second between batches to avoid hitting API limits
      if (i + batchSize < entriesToEmbed.length) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

    } catch (batchError) {
      console.error(`Error processing batch starting at index ${i}:`, batchError);
      stats.errors += batch.length;
    }
  }

  console.log(
    `Embedding generation complete: ${stats.processed} processed, ${stats.errors} errors, ${stats.totalTokens} total tokens`
  );

  return stats;
}

/**
 * Generate embedding for a timeline source excerpt
 */
export async function embedTimelineSource(sourceId: string): Promise<void> {
  const sources = await db
    .select()
    .from(timelineSources)
    .where(eq(timelineSources.id, sourceId))
    .limit(1);

  if (sources.length === 0) {
    throw new Error(`Timeline source ${sourceId} not found`);
  }

  const source = sources[0];

  // Use excerpt for embedding
  if (!source.excerpt || source.excerpt.trim().length === 0) {
    console.warn(`Source ${sourceId} has no excerpt to embed`);
    return;
  }

  const result = await generateEmbedding(source.excerpt);

  await db
    .update(timelineSources)
    .set({
      excerptEmbedding: result.embedding,
      embeddingModel: result.model,
      embeddingGeneratedAt: new Date(),
    })
    .where(eq(timelineSources.id, sourceId));

  console.log(
    `Generated embedding for source ${sourceId} (${result.dimensions}D, ${result.tokensUsed} tokens)`
  );
}

/**
 * Get embedding coverage statistics
 */
export async function getEmbeddingCoverage(): Promise<{
  timelineEntries: {
    total: number;
    embedded: number;
    percentage: number;
  };
  timelineSources: {
    total: number;
    embedded: number;
    percentage: number;
  };
}> {
  // Query embedding coverage view (created in migration)
  const coverageData = await db.execute(sql`
    SELECT * FROM embedding_coverage
  `);

  const entriesCoverage = coverageData.rows.find(
    (row: any) => row.table_name === "timeline_entries"
  ) || { total_records: 0, embedded_records: 0, coverage_percentage: 0 };

  const sourcesCoverage = coverageData.rows.find(
    (row: any) => row.table_name === "timeline_sources"
  ) || { total_records: 0, embedded_records: 0, coverage_percentage: 0 };

  return {
    timelineEntries: {
      total: Number(entriesCoverage.total_records) || 0,
      embedded: Number(entriesCoverage.embedded_records) || 0,
      percentage: Number(entriesCoverage.coverage_percentage) || 0,
    },
    timelineSources: {
      total: Number(sourcesCoverage.total_records) || 0,
      embedded: Number(sourcesCoverage.embedded_records) || 0,
      percentage: Number(sourcesCoverage.coverage_percentage) || 0,
    },
  };
}

/**
 * Estimate cost for embedding a batch of texts
 */
export function estimateEmbeddingCost(
  textCount: number,
  avgTokensPerText: number = 500
): {
  estimatedTokens: number;
  estimatedCostUSD: number;
} {
  const estimatedTokens = textCount * avgTokensPerText;

  // OpenAI text-embedding-3-small pricing: $0.02 per 1M tokens
  const costPer1MTokens = 0.02;
  const estimatedCostUSD = (estimatedTokens / 1000000) * costPer1MTokens;

  return {
    estimatedTokens,
    estimatedCostUSD: Math.round(estimatedCostUSD * 100) / 100, // Round to 2 decimals
  };
}

export const embeddingService = {
  generateEmbedding,
  generateBatchEmbeddings,
  embedTimelineEntry,
  embedTimelineSource,
  embedAllMissingEntries,
  getEmbeddingCoverage,
  estimateEmbeddingCost,
};
