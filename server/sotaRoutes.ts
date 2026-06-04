/**
 * SOTA Upgrade API Routes
 * Phase 1: Semantic Search Foundation
 *
 * New endpoints for:
 * - Hybrid search (keyword + semantic)
 * - RAG document Q&A
 * - Embedding generation and management
 */

import type { Express } from "express";
import { searchService } from "./hybridSearchService";
import { ragService } from "./ragService";
import { embeddingService } from "./embeddingService";
import { requireServiceToken } from "./middleware/authz";

export function registerSOTARoutes(app: Express) {

  /**
   * Enhanced Hybrid Search Endpoint
   * GET /api/timeline/search/hybrid
   *
   * Query Parameters:
   * - caseId (required): UUID of the case
   * - query (required): Search query text
   * - topK (optional): Number of results to return (default: 20)
   * - alpha (optional): Search balance 0-1 (default: 0.6)
   *   - 0 = pure keyword
   *   - 1 = pure semantic
   *   - 0.6 = 60% semantic, 40% keyword (recommended)
   * - entryType (optional): 'task' or 'event'
   * - dateFrom (optional): ISO date string
   * - dateTo (optional): ISO date string
   *
   * Example: /api/timeline/search/hybrid?caseId=123&query=contract%20breach&alpha=0.6
   */
  app.get('/api/timeline/search/hybrid', requireServiceToken, async (req: any, res) => {
    try {
      const { caseId, query, topK, alpha, entryType, dateFrom, dateTo, confidenceLevel } = req.query;

      if (!caseId || !query) {
        return res.status(400).json({
          error: "caseId and query are required",
        });
      }

      // Parse query parameters
      const options = {
        caseId: caseId as string,
        query: query as string,
        topK: topK ? parseInt(topK as string) : 20,
        alpha: alpha ? parseFloat(alpha as string) : 0.6,
        filters: {
          entryType: entryType as 'task' | 'event' | undefined,
          dateFrom: dateFrom as string | undefined,
          dateTo: dateTo as string | undefined,
          confidenceLevel: confidenceLevel ? (confidenceLevel as string).split(',') : undefined,
        },
      };

      // Validate alpha parameter
      if (options.alpha < 0 || options.alpha > 1) {
        return res.status(400).json({
          error: "alpha must be between 0 and 1",
        });
      }

      const response = await searchService.hybridSearch(options);

      res.json(response);

    } catch (error) {
      console.error("Error in hybrid search:", error);
      res.status(500).json({
        error: "Failed to perform hybrid search",
        message: error.message,
      });
    }
  });

  /**
   * RAG Document Q&A Endpoint
   * POST /api/timeline/ask
   *
   * Request Body:
   * {
   *   "caseId": "uuid",
   *   "question": "What evidence supports the breach claim?",
   *   "topK": 5,  // optional
   *   "alpha": 0.6  // optional
   * }
   *
   * Response:
   * {
   *   "answer": "Based on the timeline entries...",
   *   "sources": [...],
   *   "confidence": 0.85
   * }
   */
  app.post('/api/timeline/ask', requireServiceToken, async (req: any, res) => {
    try {
      const { caseId, question, topK, alpha, includeMetadata } = req.body;

      if (!caseId || !question) {
        return res.status(400).json({
          error: "caseId and question are required",
        });
      }

      const response = await ragService.queryDocuments({
        caseId,
        question,
        topK: topK || 5,
        alpha: alpha || 0.6,
        includeMetadata: includeMetadata || false,
      });

      res.json(response);

    } catch (error) {
      console.error("Error in RAG query:", error);
      res.status(500).json({
        error: "Failed to answer question",
        message: error.message,
      });
    }
  });

  /**
   * Generate Timeline Summary
   * GET /api/timeline/summary/:caseId
   *
   * Generates a comprehensive chronological summary of the case timeline
   */
  app.get('/api/timeline/summary/:caseId', async (req: any, res) => {
    try {
      const { caseId } = req.params;

      if (!caseId) {
        return res.status(400).json({ error: "caseId is required" });
      }

      const summary = await ragService.generateTimelineSummary(caseId);

      res.json({
        caseId,
        summary,
        generatedAt: new Date().toISOString(),
      });

    } catch (error) {
      console.error("Error generating summary:", error);
      res.status(500).json({
        error: "Failed to generate timeline summary",
        message: error.message,
      });
    }
  });

  /**
   * Analyze Timeline Gaps
   * GET /api/timeline/analyze/gaps/:caseId
   *
   * Identifies potential gaps, missing information, or issues in the timeline
   */
  app.get('/api/timeline/analyze/gaps/:caseId', async (req: any, res) => {
    try {
      const { caseId } = req.params;

      if (!caseId) {
        return res.status(400).json({ error: "caseId is required" });
      }

      const analysis = await ragService.analyzeTimelineGaps(caseId);

      res.json({
        caseId,
        analysis,
        analyzedAt: new Date().toISOString(),
      });

    } catch (error) {
      console.error("Error analyzing gaps:", error);
      res.status(500).json({
        error: "Failed to analyze timeline gaps",
        message: error.message,
      });
    }
  });

  /**
   * Batch RAG Queries
   * POST /api/timeline/ask/batch
   *
   * Request Body:
   * {
   *   "caseId": "uuid",
   *   "questions": ["Question 1?", "Question 2?"],
   *   "topK": 5  // optional
   * }
   */
  app.post('/api/timeline/ask/batch', async (req: any, res) => {
    try {
      const { caseId, questions, topK } = req.body;

      if (!caseId || !questions || !Array.isArray(questions)) {
        return res.status(400).json({
          error: "caseId and questions array are required",
        });
      }

      if (questions.length > 10) {
        return res.status(400).json({
          error: "Maximum 10 questions per batch",
        });
      }

      const responses = await ragService.batchQuery(
        caseId,
        questions,
        topK || 5
      );

      res.json({
        caseId,
        results: responses,
        processedAt: new Date().toISOString(),
      });

    } catch (error) {
      console.error("Error in batch query:", error);
      res.status(500).json({
        error: "Failed to process batch queries",
        message: error.message,
      });
    }
  });

  /**
   * Generate Embedding for Timeline Entry
   * POST /api/admin/embeddings/entry/:entryId
   *
   * Generates or regenerates embedding for a specific timeline entry
   */
  app.post('/api/admin/embeddings/entry/:entryId', async (req: any, res) => {
    try {
      const { entryId } = req.params;

      if (!entryId) {
        return res.status(400).json({ error: "entryId is required" });
      }

      await embeddingService.embedTimelineEntry(entryId);

      res.json({
        success: true,
        entryId,
        message: "Embedding generated successfully",
      });

    } catch (error) {
      console.error("Error generating embedding:", error);
      res.status(500).json({
        error: "Failed to generate embedding",
        message: error.message,
      });
    }
  });

  /**
   * Generate Embeddings for All Missing Entries
   * POST /api/admin/embeddings/generate
   *
   * Request Body (optional):
   * {
   *   "caseId": "uuid",  // Optional: limit to specific case
   *   "batchSize": 100   // Optional: batch size for processing
   * }
   */
  app.post('/api/admin/embeddings/generate', async (req: any, res) => {
    try {
      const { caseId, batchSize } = req.body;

      // Start async job (don't wait for completion)
      const jobPromise = embeddingService.embedAllMissingEntries(
        caseId,
        batchSize || 100
      );

      // Return immediately with job ID
      res.json({
        success: true,
        message: "Embedding generation started",
        caseId: caseId || "all",
        status: "processing",
      });

      // Process in background
      jobPromise
        .then(stats => {
          console.log("Embedding generation completed:", stats);
        })
        .catch(error => {
          console.error("Embedding generation failed:", error);
        });

    } catch (error) {
      console.error("Error starting embedding generation:", error);
      res.status(500).json({
        error: "Failed to start embedding generation",
        message: error.message,
      });
    }
  });

  /**
   * Get Embedding Coverage Statistics
   * GET /api/admin/embeddings/coverage
   *
   * Returns statistics about embedding coverage across timeline entries and sources
   */
  app.get('/api/admin/embeddings/coverage', async (req: any, res) => {
    try {
      const coverage = await embeddingService.getEmbeddingCoverage();

      res.json({
        coverage,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      console.error("Error getting coverage:", error);
      res.status(500).json({
        error: "Failed to get embedding coverage",
        message: error.message,
      });
    }
  });

  /**
   * Estimate Embedding Cost
   * POST /api/admin/embeddings/estimate-cost
   *
   * Request Body:
   * {
   *   "textCount": 1000,
   *   "avgTokensPerText": 500  // optional, defaults to 500
   * }
   */
  app.post('/api/admin/embeddings/estimate-cost', async (req: any, res) => {
    try {
      const { textCount, avgTokensPerText } = req.body;

      if (!textCount || textCount < 1) {
        return res.status(400).json({
          error: "textCount must be a positive number",
        });
      }

      const estimate = embeddingService.estimateEmbeddingCost(
        textCount,
        avgTokensPerText || 500
      );

      res.json(estimate);

    } catch (error) {
      console.error("Error estimating cost:", error);
      res.status(500).json({
        error: "Failed to estimate cost",
        message: error.message,
      });
    }
  });

  /**
   * Keyword-Only Search (Fallback)
   * GET /api/timeline/search/keyword
   *
   * Provides keyword-only search without semantic capabilities
   * Useful for testing or when embeddings are unavailable
   */
  app.get('/api/timeline/search/keyword', requireServiceToken, async (req: any, res) => {
    try {
      const { caseId, query, topK } = req.query;

      if (!caseId || !query) {
        return res.status(400).json({
          error: "caseId and query are required",
        });
      }

      const response = await searchService.keywordOnlySearch(
        caseId as string,
        query as string,
        topK ? parseInt(topK as string) : 20
      );

      res.json(response);

    } catch (error) {
      console.error("Error in keyword search:", error);
      res.status(500).json({
        error: "Failed to perform keyword search",
        message: error.message,
      });
    }
  });

  /**
   * Semantic-Only Search (Testing/Debugging)
   * GET /api/timeline/search/semantic
   *
   * Provides pure semantic search without keyword matching
   * Useful for testing or comparing search strategies
   */
  app.get('/api/timeline/search/semantic', requireServiceToken, async (req: any, res) => {
    try {
      const { caseId, query, topK } = req.query;

      if (!caseId || !query) {
        return res.status(400).json({
          error: "caseId and query are required",
        });
      }

      const response = await searchService.semanticOnlySearch(
        caseId as string,
        query as string,
        topK ? parseInt(topK as string) : 20
      );

      res.json(response);

    } catch (error) {
      console.error("Error in semantic search:", error);
      res.status(500).json({
        error: "Failed to perform semantic search",
        message: error.message,
      });
    }
  });

  console.log("✅ SOTA Phase 1 routes registered:");
  console.log("   - GET  /api/timeline/search/hybrid");
  console.log("   - POST /api/timeline/ask");
  console.log("   - GET  /api/timeline/summary/:caseId");
  console.log("   - GET  /api/timeline/analyze/gaps/:caseId");
  console.log("   - POST /api/timeline/ask/batch");
  console.log("   - POST /api/admin/embeddings/entry/:entryId");
  console.log("   - POST /api/admin/embeddings/generate");
  console.log("   - GET  /api/admin/embeddings/coverage");
  console.log("   - POST /api/admin/embeddings/estimate-cost");
  console.log("   - GET  /api/timeline/search/keyword");
  console.log("   - GET  /api/timeline/search/semantic");
}
