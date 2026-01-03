import type { Express } from "express";
import fs from "fs";
import path from "path";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { chittyAuth, isAuthenticated, hasRole, hasPermission } from "./chittyAuth";
import { z } from "zod";
import {
  insertCaseSchema,
  insertTimelineEntrySchema,
  insertTimelineSourceSchema,
  insertDataIngestionJobSchema,
  insertMcpIntegrationSchema,
  insertPartySchema,
  insertPartyIdentifierSchema,
  insertConversationSchema,
  insertMessageSchema,
  insertMessagePartySchema,
  insertConversationMessageSchema,
  insertMessageAttachmentSchema
} from "@shared/schema";
import { ingestionService } from "./ingestionService";
import { mcpService } from "./mcpService";
import { chittyTrust } from "./chittyTrust";
import { emitContextEvent } from "./contextEmitter";
import { chittyBeacon } from "./chittyBeacon";
import { contradictionService } from "./contradictionService";
import { requireServiceTokenIfConfigured } from './middleware/authz';
import { communicationsService } from "./communicationsService";
import { chittyConnect } from "./chittyConnectClient";
import multer from "multer";
import { r2Storage } from "./r2Storage";

// Configure multer for file uploads (memory storage for R2 upload)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 100 * 1024 * 1024, // 100MB limit
  },
});

export async function registerRoutes(app: Express): Promise<Server> {
  // Health check endpoint (ChittyGov standard)
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      service: 'chittychronicle',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    });
  });

  // Discovery endpoints (.well-known) and OpenAPI
  app.get('/.well-known/chronicle-manifest.json', (req, res) => {
    try {
      const manifestPath = path.resolve(process.cwd(), 'server', 'registry-manifest.json');
      if (fs.existsSync(manifestPath)) {
        res.sendFile(manifestPath);
      } else {
        res.status(404).json({ message: 'Manifest not found' });
      }
    } catch (err) {
      res.status(500).json({ message: 'Failed to load manifest' });
    }
  });

  // Standard service discovery path
  app.get('/.well-known/service-manifest.json', (req, res) => {
    try {
      const manifestPath = path.resolve(process.cwd(), 'server', 'registry-manifest.json');
      if (fs.existsSync(manifestPath)) {
        res.sendFile(manifestPath);
      } else {
        res.status(404).json({ message: 'Manifest not found' });
      }
    } catch (err) {
      res.status(500).json({ message: 'Failed to load manifest' });
    }
  });

  app.get('/openapi.json', (req, res) => {
    try {
      const openapiPath = path.resolve(process.cwd(), 'server', 'openapi.json');
      if (fs.existsSync(openapiPath)) {
        res.sendFile(openapiPath);
      } else {
        res.status(404).json({ message: 'OpenAPI spec not found' });
      }
    } catch (err) {
      res.status(500).json({ message: 'Failed to load OpenAPI spec' });
    }
  });

  // Serve MCP manifest for discovery if requested by aggregator/clients
  app.get('/.well-known/mcp-manifest.json', (req, res) => {
    try {
      const mcpPath = path.resolve(process.cwd(), 'server', 'mcp.manifest.json');
      if (fs.existsSync(mcpPath)) {
        res.sendFile(mcpPath);
      } else {
        res.status(404).json({ message: 'MCP manifest not found' });
      }
    } catch (err) {
      res.status(500).json({ message: 'Failed to load MCP manifest' });
    }
  });

  // Registry inventory preview (no external calls; returns a plan)
  app.get('/api/admin/registry/preview', (req, res) => {
    try {
      const mcpBase = process.env.CHITTYMCP_BASE_URL || 'https://mcp.chitty.cc';
      const cfPath = '/cf';
      const plan = {
        description: 'Read-only inventory plan via MCP (no execution in preview).',
        mcp_base: mcpBase,
        steps: [
          {
            name: 'cloudflare:accounts',
            method: 'GET',
            path: `${cfPath}/accounts`,
          },
          {
            name: 'cloudflare:zones',
            method: 'GET',
            path: `${cfPath}/accounts/{account_id}/zones`,
          },
          {
            name: 'cloudflare:workers',
            method: 'GET',
            path: `${cfPath}/accounts/{account_id}/workers`,
          },
          {
            name: 'cloudflare:routes',
            method: 'GET',
            path: `${cfPath}/zones/{zone_id}/workers/routes`,
          },
        ],
        note: 'Use scripts/mcp/run_cf_inventory_with_op.sh to execute against MCP with OP-provided CF Access headers.',
      };
      res.json(plan);
    } catch (err) {
      res.status(500).json({ message: 'Failed to build preview' });
    }
  });

  // Execute read-only Cloudflare inventory via MCP (requires env creds)
  app.post('/api/admin/registry/run', async (req: any, res) => {
    try {
      const mcpBase = (process.env.MCP_CF_BASE || process.env.CHITTYMCP_BASE_URL && `${process.env.CHITTYMCP_BASE_URL.replace(/\/$/, '')}/cf`) || '';
      if (!mcpBase) {
        return res.status(412).json({ message: 'MCP_CF_BASE or CHITTYMCP_BASE_URL not set' });
      }

      const headers: Record<string, string> = {};
      if (process.env.CF_ACCESS_CLIENT_ID && process.env.CF_ACCESS_CLIENT_SECRET) {
        headers['CF-Access-Client-Id'] = process.env.CF_ACCESS_CLIENT_ID;
        headers['CF-Access-Client-Secret'] = process.env.CF_ACCESS_CLIENT_SECRET;
      } else if (process.env.AUTH_BEARER) {
        headers['Authorization'] = `Bearer ${process.env.AUTH_BEARER}`;
      } else {
        return res.status(412).json({ message: 'Missing CF Access headers or AUTH_BEARER' });
      }

      const mode = (req.query.mode as string) || 'lite'; // lite | standard | deep
      const accountsFilter = (req.query.accounts as string) || '';
      const reportsDir = path.resolve(process.cwd(), 'reports', 'cloudflare-mcp');
      fs.mkdirSync(reportsDir, { recursive: true });

      // health (best-effort)
      try {
        const h = await fetch(`${mcpBase}/health`, { headers });
        if (h.ok) {
          const healthJson = await h.json().catch(() => ({}));
          fs.writeFileSync(path.join(reportsDir, 'health.json'), JSON.stringify(healthJson, null, 2));
        }
      } catch {}

      // accounts
      const accResp = await fetch(`${mcpBase}/accounts`, { headers });
      if (!accResp.ok) {
        const text = await accResp.text();
        return res.status(accResp.status).json({ message: 'accounts failed', detail: text });
      }
      const accounts = await accResp.json();
      fs.writeFileSync(path.join(reportsDir, 'accounts.json'), JSON.stringify(accounts, null, 2));

      let accountIds: string[] = [];
      if (Array.isArray(accounts)) {
        accountIds = accounts.map((a: any) => a.id).filter(Boolean);
      } else if (accounts?.result) {
        accountIds = accounts.result.map((a: any) => a.id).filter(Boolean);
      }
      if (accountsFilter) {
        const set = new Set(accountsFilter.split(',').map(s => s.trim()));
        accountIds = accountIds.filter(id => set.has(id));
      }

      // Limit accounts in deep runs to reduce costs if not filtered
      const limit = req.query.limit ? parseInt(req.query.limit as string, 10) : 5;
      if (!accountsFilter && accountIds.length > limit) accountIds = accountIds.slice(0, limit);

      const results: any[] = [];
      for (const acc of accountIds) {
        // zones
        const zResp = await fetch(`${mcpBase}/accounts/${acc}/zones`, { headers });
        const zonesJson = zResp.ok ? await zResp.json() : { error: zResp.status };
        fs.writeFileSync(path.join(reportsDir, `zones-${acc}.json`), JSON.stringify(zonesJson, null, 2));

        if (mode !== 'lite') {
          // workers list
          const wResp = await fetch(`${mcpBase}/accounts/${acc}/workers`, { headers });
          const workersJson = wResp.ok ? await wResp.json() : { error: wResp.status };
          fs.writeFileSync(path.join(reportsDir, `workers-${acc}.json`), JSON.stringify(workersJson, null, 2));

          if (mode === 'deep') {
            // routes per zone
            let zoneIds: string[] = [];
            if (Array.isArray(zonesJson)) zoneIds = zonesJson.map((z: any) => z.id).filter(Boolean);
            else if (zonesJson?.result) zoneIds = zonesJson.result.map((z: any) => z.id).filter(Boolean);

            for (const zid of zoneIds.slice(0, limit)) {
              const rResp = await fetch(`${mcpBase}/zones/${zid}/workers/routes`, { headers });
              const routesJson = rResp.ok ? await rResp.json() : { error: rResp.status };
              fs.writeFileSync(path.join(reportsDir, `routes-${zid}.json`), JSON.stringify(routesJson, null, 2));
            }
            // observability
            const oResp = await fetch(`${mcpBase}/accounts/${acc}/workers/observability?days=7`, { headers });
            const obsJson = oResp.ok ? await oResp.json() : { error: oResp.status };
            fs.writeFileSync(path.join(reportsDir, `observability-${acc}.json`), JSON.stringify(obsJson, null, 2));
          }
        }

        results.push({ account: acc, zones: true, workers: mode !== 'lite', deep: mode === 'deep' });
      }

      res.json({ message: 'completed', results, reportsDir: 'reports/cloudflare-mcp' });
    } catch (err: any) {
      res.status(500).json({ message: 'inventory run failed', error: err?.message });
    }
  });

  // Return local registration plan and TODO (files under reports/)
  app.get('/api/admin/registry/plan', (req, res) => {
    try {
      const reportsDir = path.resolve(process.cwd(), 'reports');
      const planPath = path.join(reportsDir, 'MASTER_REGISTRATION_PLAN.md');
      const todoPath = path.join(reportsDir, 'REGISTRATION_TODO.md');
      const out: any = { plan: null, todo: null };
      if (fs.existsSync(planPath)) out.plan = fs.readFileSync(planPath, 'utf-8');
      if (fs.existsSync(todoPath)) out.todo = fs.readFileSync(todoPath, 'utf-8');
      res.json(out);
    } catch (e) {
      res.status(500).json({ message: 'Failed to read plan/TODO' });
    }
  });
  // ChittyID authentication - graceful degradation for development
  try {
    await chittyAuth.setupAuth(app);
    console.log("✅ ChittyAuth initialized successfully");
  } catch (error) {
    console.warn("⚠️ ChittyAuth unavailable, running in development mode");
    console.warn("ChittyID server endpoints needed for full authentication");
  }

  // Health check endpoint
  app.get('/api/health', (req, res) => {
    res.json({ 
      status: 'healthy', 
      auth: 'ChittyAuth',
      timestamp: new Date().toISOString() 
    });
  });

  // ==========================
  // AUTHORITY-OF-EVENTS (REST)
  // ==========================
  // Create event authority record (wraps timeline entry creation)
  app.post('/api/v1/events', requireServiceTokenIfConfigured, async (req: any, res) => {
    try {
      const entryData = insertTimelineEntrySchema.parse({
        ...req.body,
        createdBy: 'demo-user',
        modifiedBy: 'demo-user',
      });
      const entry = await storage.createTimelineEntry(entryData);
      emitContextEvent('timeline.entry.created', {
        subject_id: entry.chittyId || entry.id,
        related_ids: [entry.caseId],
        payload: {
          entryId: entry.id,
          caseId: entry.caseId,
          entryType: entry.entryType,
          confidenceLevel: entry.confidenceLevel,
        },
      });
      res.status(201).json({ success: true, entry });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ success: false, message: 'Invalid event data', errors: error.errors });
      }
      res.status(500).json({ success: false, message: 'Failed to create event' });
    }
  });

  // Get event authority view
  app.get('/api/v1/events/:id', requireServiceTokenIfConfigured, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { caseId } = req.query;
      const entry = await storage.getTimelineEntry(id, caseId as string | undefined);
      if (!entry) return res.status(404).json({ success: false, message: 'Event not found' });
      res.json({ success: true, entry });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Failed to fetch event' });
    }
  });

  // Verify event (trust scoring)
  app.post('/api/v1/events/:id/verify', requireServiceTokenIfConfigured, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { caseId } = req.query;
      const entry = await storage.getTimelineEntry(id, caseId as string | undefined);
      if (!entry) return res.status(404).json({ success: false, message: 'Event not found' });
      const trustScore = await chittyTrust.calculateTrustScore(entry);
      await emitContextEvent('timeline.entry.verified', {
        subject_id: entry.chittyId || entry.id,
        related_ids: [entry.caseId],
        payload: { entryId: entry.id, caseId: entry.caseId, trustScore },
      });
      res.json({ success: true, trustScore });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Failed to verify event' });
    }
  });

  // Mint event attestation (soft-mint local; hard-mint only in production code path)
  app.post('/api/v1/events/:id/mint', requireServiceTokenIfConfigured, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { caseId } = req.query;
      const entry = await storage.getTimelineEntry(id, caseId as string | undefined);
      if (!entry) return res.status(404).json({ success: false, message: 'Event not found' });
      const trustScore = await chittyTrust.calculateTrustScore(entry);
      const attestation = await chittyTrust.createAttestation(entry, trustScore);
      await emitContextEvent('timeline.entry.minted', {
        subject_id: entry.chittyId || entry.id,
        related_ids: [entry.caseId],
        payload: {
          entryId: entry.id,
          caseId: entry.caseId,
          attestation: {
            hash: attestation.attestationHash,
            txId: attestation.blockchainTxId,
            score: trustScore.score,
            confidence: trustScore.confidence,
          },
        },
      });
      res.json({ success: true, attestation });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Failed to mint event' });
    }
  });

  // Certify event (policy-based) — returns 501 unless configured
  app.post('/api/v1/events/:id/certify', requireServiceTokenIfConfigured, async (req: any, res) => {
    try {
      const certifyBase = process.env.CHITTYCERTIFY_BASE_URL || process.env.CHITTY_CERTIFY_URL;
      if (!certifyBase) {
        return res.status(501).json({ success: false, message: 'Certification service not configured (CHITTYCERTIFY_BASE_URL)' });
      }
      const { id } = req.params;
      const { caseId } = req.query;
      const entry = await storage.getTimelineEntry(id, caseId as string | undefined);
      if (!entry) return res.status(404).json({ success: false, message: 'Event not found' });
      // Stub acknowledge only (no external call here)
      res.json({ success: true, certification: { requested: true, service: certifyBase } });
    } catch (error) {
      res.status(500).json({ success: false, message: 'Failed to certify event' });
    }
  });

  // Authentication endpoints
  app.get('/api/auth/user', (req: any, res) => {
    // Check if user is authenticated via ChittyAuth
    if (req.user) {
      res.json(req.user);
    } else {
      // Demo mode - return null for unauthenticated state
      res.status(401).json({ message: 'Not authenticated' });
    }
  });

  app.get('/api/auth/login', (req, res) => {
    // Redirect to ChittyID login
    res.redirect('/auth/login');
  });

  app.get('/api/auth/logout', (req, res) => {
    // Handle logout
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: 'Logout failed' });
      }
      res.redirect('/');
    });
  });

  // Communications contradiction analysis endpoints
  app.get("/api/cases/:caseId/communications-contradictions", async (req, res) => {
    try {
      const { caseId } = req.params;
      const mode = req.query.mode || 'unified';
      
      // Stub implementation for now - return sample contradiction analysis
      const stubAnalysis = {
        contradictions: [
          {
            id: `contradiction-${caseId}-1`,
            caseId: caseId,
            messageIds: [`msg-${caseId}-1`, `msg-${caseId}-2`],
            timelineEntryIds: [`entry-${caseId}-1`],
            contradictionType: 'temporal',
            severity: 'high',
            title: 'Timeline Discrepancy in Communication Sequence',
            description: 'Email timestamp conflicts with meeting timeline entry by 2 hours',
            conflictingData: [
              {
                type: 'message',
                id: `msg-${caseId}-1`,
                source: 'email',
                content: 'Meeting scheduled for 2:00 PM',
                timestamp: new Date().toISOString(),
                platform: 'email',
                direction: 'inbound',
              },
              {
                type: 'timeline_entry',
                id: `entry-${caseId}-1`,
                source: 'timeline',
                content: 'Client meeting occurred at 4:00 PM',
                timestamp: new Date().toISOString(),
              }
            ],
            suggestedResolution: 'Verify actual meeting time through additional evidence sources',
            confidence: 0.85,
            detectedAt: new Date().toISOString(),
          }
        ],
        summary: {
          totalContradictions: 1,
          criticalCount: 0,
          highCount: 1,
          mediumCount: 0,
          lowCount: 0,
          crossPlatformCount: 1,
          timelineIntegrationCount: 1,
          analysisTimestamp: new Date().toISOString(),
        },
        recommendations: [
          'Review temporal sequence of communications',
          'Cross-reference meeting times with calendar entries',
          'Validate party identity across platforms'
        ],
        crossPlatformInsights: {
          platformCoverage: ['email', 'timeline'],
          identityResolutionIssues: 0,
          temporalInconsistencies: 1,
        }
      };
      
      res.json(stubAnalysis);
    } catch (error) {
      console.error("Error fetching communications contradictions:", error);
      res.status(500).json({ error: "Failed to fetch contradiction analysis" });
    }
  });

  app.post("/api/cases/:caseId/analyze-communications-contradictions", async (req, res) => {
    try {
      const { caseId } = req.params;
      const { mode, includeTimeline, includeCommunications } = req.body;
      
      // Stub implementation - simulate analysis processing
      const analysisResult = {
        contradictions: [
          {
            id: `contradiction-${caseId}-${Date.now()}`,
            caseId: caseId,
            contradictionType: 'cross_platform',
            severity: 'medium',
            title: 'Identity Resolution Conflict',
            description: 'Same person identified differently across WhatsApp and email platforms',
            conflictingData: [
              {
                type: 'message',
                id: `msg-${caseId}-whatsapp`,
                source: 'whatsapp',
                content: 'John Smith: Confirmed the contract details',
                timestamp: new Date().toISOString(),
                platform: 'whatsapp',
                direction: 'inbound',
              },
              {
                type: 'message',
                id: `msg-${caseId}-email`,
                source: 'email',
                content: 'J. Smith: Contract details need revision',
                timestamp: new Date().toISOString(),
                platform: 'email',
                direction: 'inbound',
              }
            ],
            confidence: 0.72,
            detectedAt: new Date().toISOString(),
          }
        ],
        summary: {
          totalContradictions: 1,
          criticalCount: 0,
          highCount: 0,
          mediumCount: 1,
          lowCount: 0,
          crossPlatformCount: 1,
          timelineIntegrationCount: 0,
          analysisTimestamp: new Date().toISOString(),
        },
        recommendations: [
          'Standardize party identification across platforms',
          'Implement identity linking for cross-platform analysis'
        ],
        crossPlatformInsights: {
          platformCoverage: ['whatsapp', 'email'],
          identityResolutionIssues: 1,
          temporalInconsistencies: 0,
        }
      };
      
      res.json(analysisResult);
    } catch (error) {
      console.error("Error analyzing communications contradictions:", error);
      res.status(500).json({ error: "Failed to analyze contradictions" });
    }
  });

  app.post("/api/communications-contradictions/:contradictionId/resolve", async (req, res) => {
    try {
      const { contradictionId } = req.params;
      const { resolution, resolvedBy } = req.body;
      
      // Stub implementation - mark contradiction as resolved
      const resolvedContradiction = {
        id: contradictionId,
        resolvedAt: new Date().toISOString(),
        resolvedBy: resolvedBy || 'current-user',
        resolution: resolution,
      };
      
      res.json(resolvedContradiction);
    } catch (error) {
      console.error("Error resolving contradiction:", error);
      res.status(500).json({ error: "Failed to resolve contradiction" });
    }
  });

  // Cases
  app.get('/api/cases', async (req: any, res) => {
    try {
      const cases = await storage.getCases('demo-user');
      res.json(cases);
    } catch (error) {
      console.error("Error fetching cases:", error);
      res.status(500).json({ message: "Failed to fetch cases" });
    }
  });

  app.post('/api/cases', async (req: any, res) => {
    try {
      const caseData = insertCaseSchema.parse({
        ...req.body,
        createdBy: 'demo-user',
      });
      
      const newCase = await storage.createCase(caseData);
      res.status(201).json(newCase);
    } catch (error) {
      console.error("Error creating case:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid case data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create case" });
    }
  });

  app.get('/api/cases/:id', async (req: any, res) => {
    try {
      const caseItem = await storage.getCase(req.params.id, 'demo-user');
      if (!caseItem) {
        return res.status(404).json({ message: "Case not found" });
      }
      res.json(caseItem);
    } catch (error) {
      console.error("Error fetching case:", error);
      res.status(500).json({ message: "Failed to fetch case" });
    }
  });

  // Timeline entries
  // Get all timeline entries across all cases
  app.get('/api/timeline/all', async (req: any, res) => {
    try {
      const entries = await storage.getAllTimelineEntries();
      res.json(entries);
    } catch (error) {
      console.error("Error fetching all timeline entries:", error);
      res.status(500).json({ message: "Failed to fetch timeline entries" });
    }
  });

  app.get('/api/timeline/entries', async (req: any, res) => {
    try {
      const { caseId, startDate, endDate, entryType, confidenceLevel, limit, offset } = req.query;

      const filters = {
        startDate: startDate as string,
        endDate: endDate as string,
        entryType: entryType as string,
        confidenceLevel: confidenceLevel as string,
        limit: limit ? parseInt(limit as string) : undefined,
        offset: offset ? parseInt(offset as string) : undefined,
      };

      const result = await storage.getTimelineEntries(caseId as string, filters);
      res.json({
        entries: result.entries,
        totalCount: result.totalCount,
        hasMore: result.hasMore
      });
    } catch (error) {
      console.error("Error fetching timeline entries:", error);
      res.status(500).json({ message: "Failed to fetch timeline entries" });
    }
  });

  app.post('/api/timeline/entries', async (req: any, res) => {
    try {
      const entryData = insertTimelineEntrySchema.parse({
        ...req.body,
        createdBy: 'demo-user',
        modifiedBy: 'demo-user',
        // Include message linkage fields if provided for audit trail
        messageId: req.body.messageId || null,
        messageSource: req.body.messageSource || null,
        messageDirection: req.body.messageDirection || null,
      });
      
      const entry = await storage.createTimelineEntry(entryData);
      // Emit context event (best-effort; local write + optional network)
      emitContextEvent('timeline.entry.created', {
        subject_id: entry.chittyId || entry.id,
        related_ids: [entry.caseId],
        payload: {
          entryId: entry.id,
          caseId: entry.caseId,
          entryType: entry.entryType,
          confidenceLevel: entry.confidenceLevel,
        },
      });
      res.status(201).json(entry);
    } catch (error) {
      console.error("Error creating timeline entry:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid entry data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create timeline entry" });
    }
  });

  // Alternative endpoint for case-specific timeline creation (compatibility)
  app.post('/api/timeline/:caseId', async (req: any, res) => {
    try {
      const { caseId } = req.params;
      
      const entryData = insertTimelineEntrySchema.parse({
        ...req.body,
        caseId,
        createdBy: 'demo-user',
        modifiedBy: 'demo-user',
        // Include message linkage fields if provided for audit trail
        messageId: req.body.messageId || null,
        messageSource: req.body.messageSource || null,
        messageDirection: req.body.messageDirection || null,
      });
      
      const entry = await storage.createTimelineEntry(entryData);
      // Emit context event (best-effort)
      emitContextEvent('timeline.entry.created', {
        subject_id: entry.chittyId || entry.id,
        related_ids: [caseId],
        payload: {
          entryId: entry.id,
          caseId: entry.caseId,
          entryType: entry.entryType,
          confidenceLevel: entry.confidenceLevel,
        },
      });
      res.status(201).json(entry);
    } catch (error) {
      console.error("Error creating timeline entry:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid entry data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create timeline entry" });
    }
  });

  app.get('/api/timeline/entries/:id', async (req: any, res) => {
    try {
      const { caseId } = req.query;
      const entry = await storage.getTimelineEntry(req.params.id, caseId as string);
      if (!entry) {
        return res.status(404).json({ message: "Timeline entry not found" });
      }
      res.json(entry);
    } catch (error) {
      console.error("Error fetching timeline entry:", error);
      res.status(500).json({ message: "Failed to fetch timeline entry" });
    }
  });

  app.put('/api/timeline/entries/:id', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const entryData = insertTimelineEntrySchema.partial().parse(req.body);
      
      const updatedEntry = await storage.updateTimelineEntry(req.params.id, entryData, userId);
      if (!updatedEntry) {
        return res.status(404).json({ message: "Timeline entry not found" });
      }
      res.json(updatedEntry);
    } catch (error) {
      console.error("Error updating timeline entry:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid entry data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to update timeline entry" });
    }
  });

  app.delete('/api/timeline/entries/:id', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const success = await storage.deleteTimelineEntry(req.params.id, userId);
      if (!success) {
        return res.status(404).json({ message: "Timeline entry not found" });
      }
      res.json({ message: "Timeline entry deleted successfully" });
    } catch (error) {
      console.error("Error deleting timeline entry:", error);
      res.status(500).json({ message: "Failed to delete timeline entry" });
    }
  });

  // Timeline sources
  app.get('/api/timeline/entries/:entryId/sources', async (req: any, res) => {
    try {
      const sources = await storage.getTimelineSources(req.params.entryId);
      res.json(sources);
    } catch (error) {
      console.error("Error fetching timeline sources:", error);
      res.status(500).json({ message: "Failed to fetch timeline sources" });
    }
  });

  app.post('/api/timeline/entries/:entryId/sources', async (req: any, res) => {
    try {
      const sourceData = insertTimelineSourceSchema.parse({
        ...req.body,
        entryId: req.params.entryId,
      });
      
      const source = await storage.createTimelineSource(sourceData);
      res.status(201).json(source);
    } catch (error) {
      console.error("Error creating timeline source:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid source data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create timeline source" });
    }
  });

  // Search
  app.get('/api/timeline/search', async (req: any, res) => {
    try {
      const { caseId, query } = req.query;
      
      if (!caseId || !query) {
        return res.status(400).json({ message: "caseId and query are required" });
      }
      
      const entries = await storage.searchTimelineEntries(caseId as string, query as string);
      res.json(entries);
    } catch (error) {
      console.error("Error searching timeline entries:", error);
      res.status(500).json({ message: "Failed to search timeline entries" });
    }
  });

  // Data ingestion routes
  app.post('/api/ingestion/jobs', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const jobData = insertDataIngestionJobSchema.parse({
        ...req.body,
        createdBy: userId,
      });
      
      const jobId = await ingestionService.createIngestionJob(jobData);
      res.status(201).json({ success: true, jobId });
    } catch (error) {
      console.error("Error creating ingestion job:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid job data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create ingestion job" });
    }
  });

  app.get('/api/ingestion/jobs/:caseId', async (req: any, res) => {
    try {
      const jobs = await storage.getDataIngestionJobs(req.params.caseId);
      res.json({ jobs });
    } catch (error) {
      console.error("Error fetching ingestion jobs:", error);
      res.status(500).json({ message: "Failed to fetch ingestion jobs" });
    }
  });

  // Legacy route: process documents from JSON payload
  app.post('/api/ingestion/process', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const { caseId, documents } = req.body;

      if (!caseId || !documents || !Array.isArray(documents)) {
        return res.status(400).json({ message: "caseId and documents array are required" });
      }

      // Create ingestion job
      const jobData = {
        caseId,
        source: 'manual_upload' as const,
        sourceIdentifier: 'Direct Upload',
        status: 'processing' as const,
        createdBy: userId,
        metadata: { documentCount: documents.length }
      };

      const jobId = await ingestionService.createIngestionJob(jobData);

      // Process documents
      const result = await ingestionService.processDocuments(caseId, documents, userId);

      // Update job status
      await ingestionService.updateIngestionJobStatus(jobId, 'completed', result);

      res.json({
        success: true,
        jobId,
        result,
        message: `Processed ${result.documentsProcessed} documents, created ${result.entriesCreated} timeline entries`
      });
    } catch (error) {
      console.error("Error processing documents:", error);
      res.status(500).json({ message: "Failed to process documents" });
    }
  });

  // New route: upload files to R2 and process with auto-embedding
  app.post('/api/ingestion/upload', upload.array('files', 20), async (req: any, res) => {
    try {
      const userId = 'demo-user'; // TODO: get from session
      const { caseId } = req.body;
      const files = req.files as Express.Multer.File[];

      if (!caseId) {
        return res.status(400).json({ message: "caseId is required" });
      }

      if (!files || files.length === 0) {
        return res.status(400).json({ message: "No files uploaded" });
      }

      console.log(`📤 Uploading ${files.length} files for case ${caseId}`);

      // Create ingestion job
      const jobData = {
        caseId,
        source: 'manual_upload' as const,
        sourceIdentifier: 'File Upload',
        status: 'processing' as const,
        createdBy: userId,
        metadata: {
          documentCount: files.length,
          totalSize: files.reduce((sum, f) => sum + f.size, 0),
        }
      };

      const jobId = await ingestionService.createIngestionJob(jobData);

      // Convert uploaded files to document format with buffers
      const documents = files.map(file => ({
        fileName: file.originalname,
        content: file.buffer.toString('utf-8'), // For text analysis
        fileBuffer: file.buffer, // For R2 upload
      }));

      // Process documents (uploads to R2, creates entries, generates embeddings)
      const result = await ingestionService.processDocuments(caseId, documents, userId);

      // Update job status
      await ingestionService.updateIngestionJobStatus(jobId, 'completed', result);

      res.json({
        success: true,
        jobId,
        result,
        message: `Uploaded and processed ${result.documentsProcessed} documents → R2 → Timeline → Embeddings (async)`,
        filesProcessed: files.map(f => f.originalname),
      });
    } catch (error) {
      console.error("Error uploading and processing documents:", error);
      res.status(500).json({
        message: "Failed to upload and process documents",
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // MCP Integration routes
  app.post('/api/mcp/integrations', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const integrationData = insertMcpIntegrationSchema.parse({
        ...req.body,
        createdBy: userId,
      });
      
      const integration = await mcpService.createIntegration(integrationData);
      res.status(201).json({ success: true, integration });
    } catch (error) {
      console.error("Error creating MCP integration:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid integration data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create MCP integration" });
    }
  });

  app.get('/api/mcp/integrations', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const integrations = await mcpService.getActiveIntegrations(userId);
      res.json({ integrations });
    } catch (error) {
      console.error("Error fetching MCP integrations:", error);
      res.status(500).json({ message: "Failed to fetch MCP integrations" });
    }
  });

  app.get('/api/mcp/config/:platform', async (req: any, res) => {
    try {
      const { platform } = req.params;
      const baseUrl = `${req.protocol}://${req.get('host')}`;
      
      const config = mcpService.generateMcpConfig(platform, baseUrl);
      res.json(config);
    } catch (error) {
      console.error("Error generating MCP config:", error);
      res.status(500).json({ message: "Failed to generate MCP config" });
    }
  });

  app.post('/api/mcp/:integrationId/:action', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const { integrationId, action } = req.params;
      
      const result = await mcpService.processMcpRequest(integrationId, action, req.body, userId);
      
      if (result.success) {
        res.json(result);
      } else {
        res.status(result.statusCode || 400).json(result);
      }
    } catch (error) {
      console.error("Error processing MCP request:", error);
      res.status(500).json({ message: "Failed to process MCP request" });
    }
  });

  app.post('/api/mcp/sync/:integrationId/:caseId', async (req: any, res) => {
    try {
      const { integrationId, caseId } = req.params;
      
      const result = await mcpService.syncToExternalPlatform(integrationId, caseId);
      
      if (result.success) {
        res.json(result);
      } else {
        res.status(result.statusCode || 400).json(result);
      }
    } catch (error) {
      console.error("Error syncing to external platform:", error);
      res.status(500).json({ message: "Failed to sync to external platform" });
    }
  });

  // Contradiction detection endpoint
  app.post('/api/timeline/detect-contradictions/:caseId', async (req: any, res) => {
    try {
      const contradictions = await ingestionService.detectContradictions(req.params.caseId);
      res.json({ contradictions });
    } catch (error) {
      console.error("Error detecting contradictions:", error);
      res.status(500).json({ message: "Failed to detect contradictions" });
    }
  });

  // ChittyTrust endpoints
  app.get('/api/trust/score/:entryId', async (req: any, res) => {
    try {
      const { caseId } = req.query;
      const entry = await storage.getTimelineEntry(req.params.entryId, caseId as string);
      if (!entry) {
        return res.status(404).json({ message: "Entry not found" });
      }
      
      const trustScore = await chittyTrust.calculateTrustScore(entry);
      const attestation = await chittyTrust.createAttestation(entry, trustScore);
      
      res.json({ trustScore, attestation });
    } catch (error) {
      console.error("Error calculating trust score:", error);
      res.status(500).json({ message: "Failed to calculate trust score" });
    }
  });

  app.get('/api/trust/network/:caseId', async (req: any, res) => {
    try {
      const trustNetwork = await chittyTrust.getCaseTrustNetwork(req.params.caseId);
      res.json(trustNetwork);
    } catch (error) {
      console.error("Error getting trust network:", error);
      res.status(500).json({ message: "Failed to get trust network" });
    }
  });

  app.post('/api/trust/verify/:entryId', async (req: any, res) => {
    try {
      const { caseId } = req.query;
      const entry = await storage.getTimelineEntry(req.params.entryId, caseId as string);
      if (!entry) {
        return res.status(404).json({ message: "Entry not found" });
      }
      
      const verification = await chittyTrust.requestExternalVerification(entry);
      res.json({ success: true, verification });
    } catch (error) {
      console.error("Error requesting verification:", error);
      res.status(500).json({ message: "Failed to request verification" });
    }
  });

  // ChittyBeacon endpoints  
  app.post('/api/beacon/subscribe', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const subscription = {
        userId,
        ...req.body
      };
      
      const subscriptionId = await chittyBeacon.subscribe(subscription);
      res.json({ success: true, subscriptionId });
    } catch (error) {
      console.error("Error creating subscription:", error);
      res.status(500).json({ message: "Failed to create subscription" });
    }
  });

  app.get('/api/beacon/alerts/:caseId', async (req: any, res) => {
    try {
      const stats = await chittyBeacon.getAlertStats(req.params.caseId);
      res.json(stats);
    } catch (error) {
      console.error("Error getting alert stats:", error);
      res.status(500).json({ message: "Failed to get alert stats" });
    }
  });

  app.post('/api/beacon/monitor/:caseId', async (req: any, res) => {
    try {
      const deadlineAlerts = await chittyBeacon.monitorDeadlines(req.params.caseId);
      const contradictionAlerts = await chittyBeacon.detectContradictions(req.params.caseId);
      
      res.json({ 
        success: true, 
        alerts: [...deadlineAlerts, ...contradictionAlerts],
        summary: {
          deadlines: deadlineAlerts.length,
          contradictions: contradictionAlerts.length,
          total: deadlineAlerts.length + contradictionAlerts.length
        }
      });
    } catch (error) {
      console.error("Error monitoring case:", error);
      res.status(500).json({ message: "Failed to monitor case" });
    }
  });

  app.get('/api/beacon/digest', async (req: any, res) => {
    try {
      const userId = 'demo-user';
      const { period = 'daily' } = req.query;
      
      const digest = await chittyBeacon.generateDigest(
        userId, 
        period as 'daily' | 'weekly' | 'monthly'
      );
      
      res.json(digest);
    } catch (error) {
      console.error("Error generating digest:", error);
      res.status(500).json({ message: "Failed to generate digest" });
    }
  });

  // AI-Powered Contradiction Detection
  app.post('/api/cases/:caseId/analyze-contradictions', async (req: any, res) => {
    try {
      const caseId = req.params.caseId;
      const analysis = await contradictionService.analyzeContradictions(caseId);
      res.json(analysis);
    } catch (error) {
      console.error("Error in contradiction analysis:", error);
      res.status(500).json({ message: "Failed to analyze contradictions" });
    }
  });

  app.get('/api/cases/:caseId/contradictions', async (req: any, res) => {
    try {
      const caseId = req.params.caseId;
      const contradictions = await contradictionService.getContradictionReports(caseId);
      res.json(contradictions);
    } catch (error) {
      console.error("Error fetching contradictions:", error);
      res.status(500).json({ message: "Failed to fetch contradictions" });
    }
  });

  app.post('/api/contradictions/:contradictionId/resolve', async (req: any, res) => {
    try {
      const contradictionId = req.params.contradictionId;
      const { resolvedBy, resolution } = req.body;
      
      await contradictionService.resolveContradiction(contradictionId, resolvedBy, resolution);
      res.json({ message: "Contradiction resolved successfully" });
    } catch (error) {
      console.error("Error resolving contradiction:", error);
      res.status(500).json({ message: "Failed to resolve contradiction" });
    }
  });

  app.post('/api/timeline-entries/analyze-contradictions', async (req: any, res) => {
    try {
      const { entryIds, caseId } = req.body;
      const contradictions = await contradictionService.analyzeSpecificEntries(entryIds, caseId);
      res.json(contradictions);
    } catch (error) {
      console.error("Error analyzing specific entries:", error);
      res.status(500).json({ message: "Failed to analyze timeline entries" });
    }
  });

  // ========================
  // COMMUNICATIONS ENDPOINTS
  // ========================

  // Party Management
  app.post('/api/parties', async (req: any, res) => {
    try {
      const partyData = insertPartySchema.parse(req.body);
      const party = await storage.createParty(partyData);
      res.status(201).json(party);
    } catch (error) {
      console.error("Error creating party:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid party data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to create party" });
    }
  });

  app.get('/api/parties/:id', async (req: any, res) => {
    try {
      const party = await storage.getParty(req.params.id);
      if (!party) {
        return res.status(404).json({ message: "Party not found" });
      }
      res.json(party);
    } catch (error) {
      console.error("Error fetching party:", error);
      res.status(500).json({ message: "Failed to fetch party" });
    }
  });

  app.get('/api/cases/:caseId/parties', async (req: any, res) => {
    try {
      const parties = await storage.findPartiesByCase(req.params.caseId);
      res.json(parties);
    } catch (error) {
      console.error("Error fetching parties for case:", error);
      res.status(500).json({ message: "Failed to fetch parties" });
    }
  });

  app.post('/api/parties/find-by-identifier', async (req: any, res) => {
    try {
      const { idType, identifier } = req.body;
      const party = await storage.findPartyByIdentifier(idType, identifier);
      if (!party) {
        return res.status(404).json({ message: "Party not found" });
      }
      res.json(party);
    } catch (error) {
      console.error("Error finding party by identifier:", error);
      res.status(500).json({ message: "Failed to find party" });
    }
  });

  app.post('/api/parties/upsert-with-identifier', async (req: any, res) => {
    try {
      const { partyData, identifier } = req.body;
      const validatedPartyData = insertPartySchema.parse(partyData);
      const validatedIdentifier = insertPartyIdentifierSchema.parse(identifier);
      
      const party = await storage.upsertPartyWithIdentifier(validatedPartyData, validatedIdentifier);
      res.json(party);
    } catch (error) {
      console.error("Error upserting party with identifier:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to upsert party" });
    }
  });

  app.put('/api/parties/:id/chitty-id', async (req: any, res) => {
    try {
      const { chittyId } = req.body;
      const party = await storage.linkPartyToChittyId(req.params.id, chittyId);
      if (!party) {
        return res.status(404).json({ message: "Party not found" });
      }
      res.json(party);
    } catch (error) {
      console.error("Error linking party to ChittyID:", error);
      res.status(500).json({ message: "Failed to link party to ChittyID" });
    }
  });

  // Party Identifier Management
  app.post('/api/party-identifiers', async (req: any, res) => {
    try {
      const identifierData = insertPartyIdentifierSchema.parse(req.body);
      const identifier = await storage.addIdentifier(identifierData);
      res.status(201).json(identifier);
    } catch (error) {
      console.error("Error adding identifier:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid identifier data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to add identifier" });
    }
  });

  app.get('/api/parties/:partyId/identifiers', async (req: any, res) => {
    try {
      const identifiers = await storage.listIdentifiers(req.params.partyId);
      res.json(identifiers);
    } catch (error) {
      console.error("Error fetching identifiers:", error);
      res.status(500).json({ message: "Failed to fetch identifiers" });
    }
  });

  // Message Ingestion and Management
  app.post('/api/messages/ingest', async (req: any, res) => {
    try {
      const { source, externalId, messageData } = req.body;
      const validatedMessageData = insertMessageSchema.parse(messageData);
      
      const message = await storage.upsertBySourceExternalId(source, externalId, validatedMessageData);
      res.json(message);
    } catch (error) {
      console.error("Error ingesting message:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid message data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to ingest message" });
    }
  });

  app.get('/api/messages/:id', async (req: any, res) => {
    try {
      const message = await storage.getMessage(req.params.id);
      if (!message) {
        return res.status(404).json({ message: "Message not found" });
      }
      res.json(message);
    } catch (error) {
      console.error("Error fetching message:", error);
      res.status(500).json({ message: "Failed to fetch message" });
    }
  });

  app.get('/api/cases/:caseId/messages', async (req: any, res) => {
    try {
      const { from, to, partyId, direction, limit, offset } = req.query;
      
      const filters = {
        from: from as string,
        to: to as string,
        partyId: partyId as string,
        direction: direction as 'inbound' | 'outbound' | 'system',
        limit: limit ? parseInt(limit as string) : undefined,
        offset: offset ? parseInt(offset as string) : undefined,
      };

      const messages = await storage.listMessagesByCase(req.params.caseId, filters);
      res.json(messages);
    } catch (error) {
      console.error("Error fetching messages for case:", error);
      res.status(500).json({ message: "Failed to fetch messages" });
    }
  });

  app.get('/api/cases/:caseId/messages/search', async (req: any, res) => {
    try {
      const { q } = req.query;
      if (!q) {
        return res.status(400).json({ message: "Search query is required" });
      }
      
      const messages = await storage.searchMessages(req.params.caseId, q as string);
      res.json(messages);
    } catch (error) {
      console.error("Error searching messages:", error);
      res.status(500).json({ message: "Failed to search messages" });
    }
  });

  // Conversation Management
  app.post('/api/conversations/upsert-by-thread', async (req: any, res) => {
    try {
      const { source, externalThreadId, conversationData } = req.body;
      const validatedConversationData = insertConversationSchema.parse(conversationData);
      
      const conversation = await storage.upsertConversationBySourceThread(
        source, 
        externalThreadId, 
        validatedConversationData
      );
      res.json(conversation);
    } catch (error) {
      console.error("Error upserting conversation:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid conversation data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to upsert conversation" });
    }
  });

  app.get('/api/cases/:caseId/conversations', async (req: any, res) => {
    try {
      const { limit, cursor } = req.query;
      const options = {
        limit: limit ? parseInt(limit as string) : undefined,
        cursor: cursor as string,
      };
      
      const conversations = await storage.listConversationsByCase(req.params.caseId, options);
      res.json(conversations);
    } catch (error) {
      console.error("Error fetching conversations:", error);
      res.status(500).json({ message: "Failed to fetch conversations" });
    }
  });

  app.get('/api/conversations/:conversationId/messages', async (req: any, res) => {
    try {
      const messages = await storage.listConversationMessages(req.params.conversationId);
      res.json(messages);
    } catch (error) {
      console.error("Error fetching conversation messages:", error);
      res.status(500).json({ message: "Failed to fetch conversation messages" });
    }
  });

  app.post('/api/conversations/:conversationId/link-message', async (req: any, res) => {
    try {
      const { messageId } = req.body;
      const link = await storage.linkConversationMessage(req.params.conversationId, messageId);
      res.json(link);
    } catch (error) {
      console.error("Error linking message to conversation:", error);
      res.status(500).json({ message: "Failed to link message to conversation" });
    }
  });

  // Message Parties (Roles)
  app.post('/api/messages/:messageId/parties', async (req: any, res) => {
    try {
      const { roles } = req.body;
      const validatedRoles = roles.map((role: any) => insertMessagePartySchema.parse(role));
      
      const messageParties = await storage.addMessageRoles(req.params.messageId, validatedRoles);
      res.json(messageParties);
    } catch (error) {
      console.error("Error adding message parties:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid role data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to add message parties" });
    }
  });

  app.get('/api/messages/:messageId/parties', async (req: any, res) => {
    try {
      const parties = await storage.listMessageParties(req.params.messageId);
      res.json(parties);
    } catch (error) {
      console.error("Error fetching message parties:", error);
      res.status(500).json({ message: "Failed to fetch message parties" });
    }
  });

  // Message Attachments
  app.post('/api/message-attachments', async (req: any, res) => {
    try {
      const attachmentData = insertMessageAttachmentSchema.parse(req.body);
      const attachment = await storage.addAttachment(attachmentData);
      res.status(201).json(attachment);
    } catch (error) {
      console.error("Error adding attachment:", error);
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid attachment data", errors: error.errors });
      }
      res.status(500).json({ message: "Failed to add attachment" });
    }
  });

  app.get('/api/messages/:messageId/attachments', async (req: any, res) => {
    try {
      const attachments = await storage.listAttachmentsByMessage(req.params.messageId);
      res.json(attachments);
    } catch (error) {
      console.error("Error fetching attachments:", error);
      res.status(500).json({ message: "Failed to fetch attachments" });
    }
  });

  app.get('/api/attachments/by-hash/:sha256', async (req: any, res) => {
    try {
      const attachment = await storage.findAttachmentBySha256(req.params.sha256);
      if (!attachment) {
        return res.status(404).json({ message: "Attachment not found" });
      }
      res.json(attachment);
    } catch (error) {
      console.error("Error finding attachment by hash:", error);
      res.status(500).json({ message: "Failed to find attachment" });
    }
  });

  // ChittyConnect Integration - Sync messages from platforms
  app.post('/api/cases/:caseId/communications/sync', async (req: any, res) => {
    try {
      const { caseId } = req.params;
      const { platforms, startDate, endDate } = req.body;

      const result = await communicationsService.syncMessagesFromChittyConnect({
        caseId,
        platforms,
        startDate,
        endDate,
      });

      res.json({
        success: true,
        synced: result.synced,
        messages: result.messages,
      });
    } catch (error) {
      console.error("Error syncing messages from ChittyConnect:", error);
      res.status(500).json({ message: "Failed to sync messages" });
    }
  });

  // Cross-Source Communications Analytics (now powered by ChittyConnect)
  app.get('/api/cases/:caseId/communications-summary', async (req: any, res) => {
    try {
      const caseId = req.params.caseId;
      const summary = await communicationsService.getCommunicationsSummary(caseId);
      res.json(summary);
    } catch (error) {
      console.error("Error fetching communications summary:", error);
      res.status(500).json({ message: "Failed to fetch communications summary" });
    }
  });

  // Evidence Orchestrator Routes
  const { EvidenceOrchestrator } = await import('./evidenceOrchestrator');
  const evidenceOrchestrator = new EvidenceOrchestrator();

  // Create evidence envelope
  app.post('/api/evidence/envelopes', async (req: any, res) => {
    try {
      const userId = req.user?.id || 'anonymous';
      const envelope = await storage.createEvidenceEnvelope({
        ...req.body,
        createdBy: userId,
        modifiedBy: userId,
      });
      res.json(envelope);
    } catch (error) {
      console.error("Error creating evidence envelope:", error);
      res.status(500).json({ message: "Failed to create evidence envelope" });
    }
  });

  // List evidence envelopes for a case
  app.get('/api/evidence/envelopes', async (req: any, res) => {
    try {
      const caseId = req.query.caseId;
      if (!caseId) {
        return res.status(400).json({ message: "caseId is required" });
      }
      const envelopes = await storage.getEvidenceEnvelopes(caseId);
      res.json(envelopes);
    } catch (error) {
      console.error("Error fetching evidence envelopes:", error);
      res.status(500).json({ message: "Failed to fetch evidence envelopes" });
    }
  });

  // Get evidence envelope by ID
  app.get('/api/evidence/envelopes/:id', async (req: any, res) => {
    try {
      const envelope = await storage.getEvidenceEnvelope(req.params.id);
      if (!envelope) {
        return res.status(404).json({ message: "Evidence envelope not found" });
      }
      res.json(envelope);
    } catch (error) {
      console.error("Error fetching evidence envelope:", error);
      res.status(500).json({ message: "Failed to fetch evidence envelope" });
    }
  });

  // Dispatch evidence to ecosystem targets
  app.post('/api/evidence/envelopes/:id/dispatch', async (req: any, res) => {
    try {
      const userId = req.user?.id || 'anonymous';
      await evidenceOrchestrator.dispatchEvidence(req.params.id, userId);
      res.json({ success: true, message: "Evidence dispatch initiated" });
    } catch (error) {
      console.error("Error dispatching evidence:", error);
      res.status(500).json({ message: "Failed to dispatch evidence" });
    }
  });

  // Get evidence distributions for an envelope
  app.get('/api/evidence/envelopes/:id/distributions', async (req: any, res) => {
    try {
      const distributions = await storage.getEvidenceDistributions(req.params.id);
      res.json(distributions);
    } catch (error) {
      console.error("Error fetching evidence distributions:", error);
      res.status(500).json({ message: "Failed to fetch evidence distributions" });
    }
  });

  // Dashboard API: Get all evidence distributions with filtering
  app.get('/api/evidence/distributions', async (req: any, res) => {
    try {
      const { caseId, status, target, limit, offset } = req.query;
      const distributions = await storage.getAllEvidenceDistributions(caseId, {
        status,
        target,
        limit: limit ? parseInt(limit) : undefined,
        offset: offset ? parseInt(offset) : undefined,
      });
      res.json(distributions);
    } catch (error) {
      console.error("Error fetching all distributions:", error);
      res.status(500).json({ message: "Failed to fetch distributions" });
    }
  });

  // Dashboard API: Get outbound messages with filtering
  app.get('/api/evidence/outbound-messages', async (req: any, res) => {
    try {
      const { distributionId, status, target, limit } = req.query;
      const messages = await storage.getOutboundMessages(distributionId, {
        status,
        target,
        limit: limit ? parseInt(limit) : undefined,
      });
      res.json(messages);
    } catch (error) {
      console.error("Error fetching outbound messages:", error);
      res.status(500).json({ message: "Failed to fetch outbound messages" });
    }
  });

  // Get effective permissions for an envelope
  app.get('/api/evidence/envelopes/:id/permissions', async (req: any, res) => {
    try {
      const userId = req.user?.id || 'anonymous';
      const permissions = await evidenceOrchestrator.resolveEffectivePermissions(
        req.params.id,
        userId
      );
      res.json(permissions);
    } catch (error) {
      console.error("Error resolving permissions:", error);
      res.status(500).json({ message: "Failed to resolve permissions" });
    }
  });

  // Add participant to evidence envelope
  app.post('/api/evidence/envelopes/:id/participants', async (req: any, res) => {
    try {
      const userId = req.user?.id || 'anonymous';
      const participant = await storage.addEvidenceParticipant({
        envelopeId: req.params.id,
        ...req.body,
        addedBy: userId,
      });
      res.json(participant);
    } catch (error) {
      console.error("Error adding participant:", error);
      res.status(500).json({ message: "Failed to add participant" });
    }
  });

  // Process pending distributions (admin/background task)
  app.post('/api/evidence/process-pending', async (req: any, res) => {
    try {
      await evidenceOrchestrator.processPendingDistributions();
      res.json({ success: true, message: "Pending distributions processed" });
    } catch (error) {
      console.error("Error processing pending distributions:", error);
      res.status(500).json({ message: "Failed to process pending distributions" });
    }
  });

  // Generate timeline from messages using ChittyConnect AI
  app.post('/api/cases/:caseId/communications/generate-timeline', async (req: any, res) => {
    try {
      const { caseId } = req.params;
      const { conversationId } = req.body;

      const result = await communicationsService.generateTimelineFromMessages({
        caseId,
        conversationId,
      });

      res.json({
        success: true,
        generated: result.generated,
        entries: result.entries,
      });
    } catch (error) {
      console.error("Error generating timeline from messages:", error);
      res.status(500).json({ message: "Failed to generate timeline" });
    }
  });

  // ChittyConnect Ecosystem Health
  app.get('/api/chittyconnect/ecosystem/health', async (req: any, res) => {
    try {
      const health = await chittyConnect.getEcosystemAwareness();
      res.json(health);
    } catch (error) {
      console.error("Error fetching ecosystem health:", error);
      res.status(500).json({ message: "Failed to fetch ecosystem health" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
