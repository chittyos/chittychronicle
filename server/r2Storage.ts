/**
 * Cloudflare R2 Storage Service
 *
 * Source of Truth for all document storage in ChittyChronicle.
 * Handles document uploads, downloads, and metadata management.
 *
 * Environment Variables Required:
 * - R2_ACCOUNT_ID: Cloudflare account ID
 * - R2_ACCESS_KEY_ID: R2 access key
 * - R2_SECRET_ACCESS_KEY: R2 secret key
 * - R2_BUCKET_NAME: R2 bucket name (e.g., "chittychronicle-documents")
 * - R2_PUBLIC_URL: Optional public URL for the bucket
 */

import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand, ListObjectsV2Command } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import crypto from "crypto";

export interface R2UploadOptions {
  caseId: string;
  fileName: string;
  fileBuffer: Buffer;
  contentType?: string;
  metadata?: Record<string, string>;
}

export interface R2UploadResult {
  key: string;
  url: string;
  bucket: string;
  size: number;
  contentType: string;
  etag: string;
}

export interface R2DocumentMetadata {
  key: string;
  size: number;
  lastModified: Date;
  contentType: string;
  etag: string;
  metadata?: Record<string, string>;
}

class R2StorageService {
  private client: S3Client | null = null;
  private bucket: string;
  private accountId: string;
  private publicUrl?: string;

  constructor() {
    this.accountId = process.env.R2_ACCOUNT_ID || "";
    this.bucket = process.env.R2_BUCKET_NAME || "chittychronicle-documents";
    this.publicUrl = process.env.R2_PUBLIC_URL;

    if (this.isConfigured()) {
      this.client = new S3Client({
        region: "auto",
        endpoint: `https://${this.accountId}.r2.cloudflarestorage.com`,
        credentials: {
          accessKeyId: process.env.R2_ACCESS_KEY_ID!,
          secretAccessKey: process.env.R2_SECRET_ACCESS_KEY!,
        },
      });
      console.log(`✅ R2 Storage initialized: ${this.bucket}`);
    } else {
      console.warn("⚠️  R2 Storage not configured. Set R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME");
    }
  }

  /**
   * Check if R2 is properly configured
   */
  isConfigured(): boolean {
    return !!(
      process.env.R2_ACCOUNT_ID &&
      process.env.R2_ACCESS_KEY_ID &&
      process.env.R2_SECRET_ACCESS_KEY &&
      process.env.R2_BUCKET_NAME
    );
  }

  /**
   * Generate a safe, unique key for a document
   */
  private generateDocumentKey(caseId: string, fileName: string): string {
    // Sanitize filename
    const sanitized = fileName.replace(/[^a-zA-Z0-9.-]/g, '_');
    const timestamp = Date.now();
    const hash = crypto.randomBytes(8).toString('hex');

    return `cases/${caseId}/documents/${timestamp}-${hash}-${sanitized}`;
  }

  /**
   * Upload a document to R2
   */
  async uploadDocument(options: R2UploadOptions): Promise<R2UploadResult> {
    if (!this.client) {
      throw new Error("R2 Storage not configured. Please set environment variables.");
    }

    const key = this.generateDocumentKey(options.caseId, options.fileName);
    const contentType = options.contentType || this.detectContentType(options.fileName);

    const command = new PutObjectCommand({
      Bucket: this.bucket,
      Key: key,
      Body: options.fileBuffer,
      ContentType: contentType,
      Metadata: {
        ...options.metadata,
        caseId: options.caseId,
        originalFileName: options.fileName,
        uploadedAt: new Date().toISOString(),
      },
    });

    const response = await this.client.send(command);

    // Generate URL (public if configured, signed otherwise)
    const url = this.publicUrl
      ? `${this.publicUrl}/${key}`
      : await this.getSignedUrl(key, 3600 * 24 * 7); // 7-day signed URL

    return {
      key,
      url,
      bucket: this.bucket,
      size: options.fileBuffer.length,
      contentType,
      etag: response.ETag || "",
    };
  }

  /**
   * Download a document from R2
   */
  async downloadDocument(key: string): Promise<Buffer> {
    if (!this.client) {
      throw new Error("R2 Storage not configured.");
    }

    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });

    const response = await this.client.send(command);

    if (!response.Body) {
      throw new Error(`Document not found: ${key}`);
    }

    // Convert stream to buffer
    const chunks: Uint8Array[] = [];
    for await (const chunk of response.Body as any) {
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  }

  /**
   * Get document metadata
   */
  async getDocumentMetadata(key: string): Promise<R2DocumentMetadata> {
    if (!this.client) {
      throw new Error("R2 Storage not configured.");
    }

    const command = new HeadObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });

    const response = await this.client.send(command);

    return {
      key,
      size: response.ContentLength || 0,
      lastModified: response.LastModified || new Date(),
      contentType: response.ContentType || "application/octet-stream",
      etag: response.ETag || "",
      metadata: response.Metadata,
    };
  }

  /**
   * Delete a document from R2
   */
  async deleteDocument(key: string): Promise<void> {
    if (!this.client) {
      throw new Error("R2 Storage not configured.");
    }

    const command = new DeleteObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });

    await this.client.send(command);
  }

  /**
   * List documents for a case
   */
  async listCaseDocuments(caseId: string): Promise<R2DocumentMetadata[]> {
    if (!this.client) {
      throw new Error("R2 Storage not configured.");
    }

    const prefix = `cases/${caseId}/documents/`;
    const command = new ListObjectsV2Command({
      Bucket: this.bucket,
      Prefix: prefix,
    });

    const response = await this.client.send(command);
    const documents: R2DocumentMetadata[] = [];

    if (response.Contents) {
      for (const obj of response.Contents) {
        if (obj.Key) {
          documents.push({
            key: obj.Key,
            size: obj.Size || 0,
            lastModified: obj.LastModified || new Date(),
            contentType: "application/octet-stream", // R2 list doesn't return content type
            etag: obj.ETag || "",
          });
        }
      }
    }

    return documents;
  }

  /**
   * Generate a pre-signed URL for temporary access
   */
  async getSignedUrl(key: string, expiresIn: number = 3600): Promise<string> {
    if (!this.client) {
      throw new Error("R2 Storage not configured.");
    }

    const command = new GetObjectCommand({
      Bucket: this.bucket,
      Key: key,
    });

    return await getSignedUrl(this.client, command, { expiresIn });
  }

  /**
   * Detect content type from file extension
   */
  private detectContentType(fileName: string): string {
    const ext = fileName.split('.').pop()?.toLowerCase();
    const types: Record<string, string> = {
      pdf: "application/pdf",
      doc: "application/msword",
      docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      txt: "text/plain",
      jpg: "image/jpeg",
      jpeg: "image/jpeg",
      png: "image/png",
      gif: "image/gif",
      eml: "message/rfc822",
      msg: "application/vnd.ms-outlook",
      zip: "application/zip",
      csv: "text/csv",
      json: "application/json",
      xml: "application/xml",
    };
    return types[ext || ""] || "application/octet-stream";
  }

  /**
   * Check if a document exists
   */
  async documentExists(key: string): Promise<boolean> {
    try {
      await this.getDocumentMetadata(key);
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get storage statistics for a case
   */
  async getCaseStorageStats(caseId: string): Promise<{
    documentCount: number;
    totalSize: number;
    avgSize: number;
  }> {
    const documents = await this.listCaseDocuments(caseId);
    const totalSize = documents.reduce((sum, doc) => sum + doc.size, 0);

    return {
      documentCount: documents.length,
      totalSize,
      avgSize: documents.length > 0 ? totalSize / documents.length : 0,
    };
  }
}

export const r2Storage = new R2StorageService();
