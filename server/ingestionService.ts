import { storage } from "./storage";
import type { InsertDataIngestionJob, InsertTimelineEntry, InsertTimelineSource } from "@shared/schema";
import { r2Storage } from "./r2Storage";
import { embedTimelineEntry } from "./embeddingService";

export interface DocumentAnalysisResult {
  dates: Date[];
  entities: string[];
  events: string[];
  keyFindings: string[];
  contradictions?: string[];
  confidence: 'high' | 'medium' | 'low';
}

export interface IngestionResult {
  documentsProcessed: number;
  entriesCreated: number;
  errors: string[];
  warnings: string[];
}

export class DataIngestionService {
  
  // Simulate document analysis using AI (would integrate with actual AI service)
  async analyzeDocument(documentContent: string, fileName: string): Promise<DocumentAnalysisResult> {
    // This would integrate with an actual AI service like OpenAI, Claude, etc.
    // For now, we'll simulate intelligent document analysis
    
    const dateRegex = /\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{2,4}\b/gi;
    const dates = documentContent.match(dateRegex)?.map(date => new Date(date)).filter(d => !isNaN(d.getTime())) || [];
    
    // Extract potential entities (names, organizations, etc.)
    const entityPatterns = [
      /\b[A-Z][a-z]+ [A-Z][a-z]+\b/g, // Names
      /\b[A-Z][A-Z\s&]+(?:LLC|Inc|Corp|Company|Co\.)\b/g, // Companies
      /\b(?:Case No\.|Civil No\.|Criminal No\.)\s*[A-Z0-9\-]+/gi, // Case numbers
    ];
    
    const entities: string[] = [];
    entityPatterns.forEach(pattern => {
      const matches = documentContent.match(pattern);
      if (matches) entities.push(...matches);
    });
    
    // Extract events using keyword matching
    const eventKeywords = ['filed', 'served', 'executed', 'signed', 'hearing', 'deadline', 'motion', 'order', 'judgment'];
    const events = eventKeywords.filter(keyword => 
      documentContent.toLowerCase().includes(keyword)
    );
    
    // Generate key findings
    const keyFindings = [
      `Document type: ${this.detectDocumentType(fileName, documentContent)}`,
      `Contains ${dates.length} date references`,
      `Mentions ${entities.length} entities`,
      `References ${events.length} legal events`
    ];
    
    // Assess confidence based on content quality
    const confidence = dates.length > 0 && entities.length > 0 ? 'high' : 
                     dates.length > 0 || entities.length > 0 ? 'medium' : 'low';
    
    return {
      dates,
      entities,
      events,
      keyFindings,
      confidence
    };
  }
  
  private detectDocumentType(fileName: string, content: string): string {
    const lowerContent = content.toLowerCase();
    const lowerFileName = fileName.toLowerCase();
    
    if (lowerContent.includes('motion') || lowerFileName.includes('motion')) return 'motion';
    if (lowerContent.includes('order') || lowerFileName.includes('order')) return 'court_order';
    if (lowerContent.includes('complaint') || lowerFileName.includes('complaint')) return 'complaint';
    if (lowerContent.includes('answer') || lowerFileName.includes('answer')) return 'answer';
    if (lowerContent.includes('discovery') || lowerFileName.includes('discovery')) return 'discovery';
    if (lowerContent.includes('deposition') || lowerFileName.includes('deposition')) return 'deposition';
    if (lowerFileName.includes('.eml') || lowerContent.includes('from:') || lowerContent.includes('to:')) return 'email';
    if (lowerContent.includes('contract') || lowerContent.includes('agreement')) return 'contract';
    return 'other';
  }
  
  // Process documents and create timeline entries
  // Supports both file buffers (new R2 upload) and pre-uploaded files (legacy)
  async processDocuments(
    caseId: string,
    documents: Array<{fileName: string, content: string, filePath?: string, fileBuffer?: Buffer}>,
    userId: string
  ): Promise<IngestionResult> {
    let documentsProcessed = 0;
    let entriesCreated = 0;
    const errors: string[] = [];
    const warnings: string[] = [];
    
    for (const doc of documents) {
      try {
        // Upload to R2 if file buffer provided (SOT for document storage)
        let r2Key = doc.filePath; // Use existing filePath if no buffer
        if (doc.fileBuffer && r2Storage.isConfigured()) {
          try {
            const uploadResult = await r2Storage.uploadDocument({
              caseId,
              fileName: doc.fileName,
              fileBuffer: doc.fileBuffer,
              metadata: {
                uploadedBy: userId,
                ingestionSource: 'pipeline',
              },
            });
            r2Key = uploadResult.key;
            console.log(`✅ Uploaded ${doc.fileName} to R2: ${r2Key}`);
          } catch (uploadError) {
            warnings.push(`Failed to upload ${doc.fileName} to R2: ${uploadError}`);
            // Continue processing even if upload fails
          }
        }

        const analysis = await this.analyzeDocument(doc.content, doc.fileName);
        documentsProcessed++;
        
        // Create timeline entries based on analysis
        for (const date of analysis.dates) {
          try {
            const entryData: InsertTimelineEntry = {
              caseId,
              entryType: 'event',
              eventSubtype: 'filed',
              date: date.toISOString().split('T')[0],
              description: `Document event from ${doc.fileName}`,
              detailedNotes: analysis.keyFindings.join('; '),
              confidenceLevel: analysis.confidence,
              eventStatus: 'occurred',
              createdBy: userId,
              modifiedBy: userId,
              tags: analysis.events,
              metadata: {
                sourceDocument: doc.fileName,
                analysisResults: analysis,
                ingestionSource: 'automated'
              }
            };
            
            const entry = await storage.createTimelineEntry(entryData);

            // Create source reference with R2 key
            const sourceData: InsertTimelineSource = {
              entryId: entry.id,
              documentType: 'other',
              fileName: doc.fileName,
              filePath: r2Key || doc.filePath || '',
              excerpt: analysis.keyFindings.slice(0, 2).join('; '),
              verificationStatus: 'pending',
              metadata: {
                analysisConfidence: analysis.confidence,
                autoGenerated: true,
                r2Key: r2Key,
              }
            };

            await storage.createTimelineSource(sourceData);
            entriesCreated++;

            // Auto-generate embedding (async, non-blocking)
            this.generateEmbeddingAsync(entry.id, doc.fileName);
            
          } catch (entryError) {
            warnings.push(`Failed to create entry for date ${date} in ${doc.fileName}: ${entryError}`);
          }
        }
        
        // If no dates found, create a general entry
        if (analysis.dates.length === 0) {
          const entryData: InsertTimelineEntry = {
            caseId,
            entryType: 'event',
            eventSubtype: 'filed',
            date: new Date().toISOString().split('T')[0],
            description: `Document uploaded: ${doc.fileName}`,
            detailedNotes: `No specific dates found. ${analysis.keyFindings.join('; ')}`,
            confidenceLevel: 'low',
            eventStatus: 'occurred',
            createdBy: userId,
            modifiedBy: userId,
            tags: analysis.events,
            metadata: {
              sourceDocument: doc.fileName,
              analysisResults: analysis,
              ingestionSource: 'automated'
            }
          };
          
          const entry = await storage.createTimelineEntry(entryData);

          const sourceData: InsertTimelineSource = {
            entryId: entry.id,
            documentType: 'other',
            fileName: doc.fileName,
            filePath: r2Key || doc.filePath || '',
            excerpt: 'Document uploaded without specific date references',
            verificationStatus: 'pending',
            metadata: {
              analysisConfidence: analysis.confidence,
              autoGenerated: true,
              r2Key: r2Key,
            }
          };

          await storage.createTimelineSource(sourceData);
          entriesCreated++;

          // Auto-generate embedding (async, non-blocking)
          this.generateEmbeddingAsync(entry.id, doc.fileName);
        }
        
      } catch (error) {
        errors.push(`Failed to process ${doc.fileName}: ${error}`);
      }
    }
    
    return {
      documentsProcessed,
      entriesCreated,
      errors,
      warnings
    };
  }
  
  // Create a new ingestion job
  async createIngestionJob(jobData: InsertDataIngestionJob): Promise<string> {
    const job = await storage.createDataIngestionJob(jobData);
    return job.id;
  }
  
  // Update ingestion job status
  async updateIngestionJobStatus(
    jobId: string, 
    status: 'pending' | 'processing' | 'completed' | 'failed',
    result?: IngestionResult
  ): Promise<void> {
    await storage.updateDataIngestionJob(jobId, {
      status,
      documentsProcessed: result?.documentsProcessed?.toString() || '0',
      entriesCreated: result?.entriesCreated?.toString() || '0',
      errorLog: result?.errors?.join('\n') || null,
      processingCompleted: status === 'completed' || status === 'failed' ? new Date() : undefined
    });
  }
  
  // Detect contradictions in timeline entries
  async detectContradictions(caseId: string): Promise<Array<{
    entry1: string;
    entry2: string;
    contradiction: string;
    confidence: number;
  }>> {
    const entries = await storage.getTimelineEntries(caseId, {});
    const contradictions: Array<{
      entry1: string;
      entry2: string;
      contradiction: string;
      confidence: number;
    }> = [];
    
    // Simple contradiction detection based on conflicting dates or statements
    for (let i = 0; i < entries.entries.length; i++) {
      for (let j = i + 1; j < entries.entries.length; j++) {
        const entry1 = entries.entries[i];
        const entry2 = entries.entries[j];
        
        // Check for date contradictions
        if (entry1.date === entry2.date && 
            entry1.description.toLowerCase().includes('filed') && 
            entry2.description.toLowerCase().includes('filed') &&
            entry1.description !== entry2.description) {
          contradictions.push({
            entry1: entry1.id,
            entry2: entry2.id,
            contradiction: `Same date filing contradiction: "${entry1.description}" vs "${entry2.description}"`,
            confidence: 0.8
          });
        }
        
        // Check for logical contradictions in task status
        if (entry1.taskStatus === 'completed' && entry2.taskStatus === 'pending' &&
            entry1.date > entry2.date && entry1.description.includes(entry2.description)) {
          contradictions.push({
            entry1: entry1.id,
            entry2: entry2.id,
            contradiction: `Task completed before it was pending`,
            confidence: 0.9
          });
        }
      }
    }
    
    return contradictions;
  }

  /**
   * Generate embedding for a timeline entry asynchronously (non-blocking)
   * Runs in background, failures are logged but don't block pipeline
   */
  private generateEmbeddingAsync(entryId: string, fileName: string): void {
    // Fire-and-forget pattern for background embedding generation
    (async () => {
      try {
        console.log(`🔄 Generating embedding for entry ${entryId} (${fileName})...`);
        await embedTimelineEntry(entryId);
        console.log(`✅ Embedding generated for entry ${entryId}`);
      } catch (error) {
        console.error(`❌ Failed to generate embedding for ${entryId}:`, error);
        // Silent failure - embedding can be regenerated later via batch script
      }
    })();
  }
}

export const ingestionService = new DataIngestionService();