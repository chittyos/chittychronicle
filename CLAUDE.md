# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 🚀 SOTA Upgrade Initiative (November 2025)

**Status**: Planning phase - Pending approval
**Documentation**: See `/docs/` for detailed upgrade plans

ChittyChronicle is undergoing a major upgrade to state-of-the-art (SOTA) legal document intelligence capabilities. This will transform the system from basic document management to intelligent legal reasoning with semantic search, automated classification, relationship discovery, and predictive analytics.

**Key Documentation**:
- **[Executive Summary](docs/EXECUTIVE_SUMMARY_SOTA_UPGRADE.md)** - High-level overview, ROI analysis, decision framework
- **[Implementation Plan](docs/SOTA_UPGRADE_IMPLEMENTATION_PLAN.md)** - Detailed Phase 1 technical specification
- **[Roadmap](docs/ROADMAP_SOTA_UPGRADE.md)** - 5-phase rollout plan (Nov 2025 - Mar 2027)

**Phase 1 Highlights** (8 weeks, Jan 2026 target):
- Vector embeddings with pgvector (Legal-BERT)
- Hybrid search (60% semantic + 40% keyword)
- RAG-powered document Q&A
- 50-70% improvement in search relevance
- Investment: $22,500-45,500 dev + $250-500/month ongoing

When working on SOTA upgrade features, always reference the detailed implementation plans in `/docs/`.

## Project Overview

ChittyChronicle is a legal timeline management system for evidentiary tracking and litigation support. Built with TypeScript/React frontend, Express backend, PostgreSQL database via Drizzle ORM, and ChittyID authentication.

**Part of ChittyOS Ecosystem**: Integrates with ChittyID (identity), ChittyPM (project management), ChittyBeacon (alerting), ChittyConnect (context sharing), and ChittyChain (verification).

## Development Commands

```bash
# Start development server (port 5000)
npm run dev

# Build for production
npm run build

# Start production server
npm run start

# TypeScript type checking
npm run check

# Push database schema changes
npm run db:push

# ChittyOS Registry commands
npm run registry:register          # Register service with ChittyRegistry
npm run registry:local:scan        # Scan local project metadata
npm run registry:generate-core     # Generate core service manifests
npm run registry:validate          # Validate manifest files

# MCP integration commands
npm run mcp:cf:lite                # Cloudflare inventory (lite scan)
npm run mcp:cf:standard            # Cloudflare inventory (standard)
npm run mcp:cf:deep                # Cloudflare inventory (deep scan)
```

## Architecture

### Tech Stack
- **Frontend**: React 18, TypeScript, TanStack Query, React Hook Form, shadcn/ui
- **Backend**: Express with TypeScript (tsx for dev, esbuild for prod)
- **Database**: PostgreSQL with Drizzle ORM
- **Auth**: ChittyID OIDC authentication with PostgreSQL session storage
- **AI**: Anthropic Claude (claude-sonnet-4-20250514) for contradiction detection
- **Styling**: Tailwind CSS with shadcn/ui components
- **Build**: Vite for client, esbuild for server

### Critical Services Layer

ChittyChronicle includes several unique service integrations:

**ChittyAuth Service** (`server/chittyAuth.ts`):
- OIDC authentication via ChittyID (`https://auth.chitty.com/oidc`)
- Role-based access control (RBAC) and permission checking
- ChittyChain verification for attestations
- Middleware: `isAuthenticated`, `hasRole(role)`, `hasPermission(permission)`

**Contradiction Detection Service** (`server/contradictionService.ts`):
- AI-powered timeline analysis using Claude Sonnet 4
- Detects temporal, factual, witness, location, entity, and logical conflicts
- Severity classification: critical/high/medium/low
- Generates structured contradiction reports with suggested resolutions

**ChittyBeacon Integration** (`server/chittyBeacon.ts`):
- Real-time alerting via WebSocket
- Alert types: deadline, contradiction, update, verification, milestone
- Multi-channel delivery: web, email, SMS, push
- Digest scheduling: daily, weekly, monthly

**Context Emitter** (`server/contextEmitter.ts`):
- Publishes events to ChittyConnect (`CHITTYCONNECT_BASE_URL`)
- Local JSONL logging to `reports/context-events.jsonl`
- Event types: case_created, timeline_entry_added, contradiction_detected, etc.
- Non-fatal best-effort design pattern

**MCP Service** (`server/mcpService.ts`):
- Model Context Protocol integration for Claude and ChatGPT
- Exposes timeline management, document ingestion, case analysis
- MCP manifest served at `/.well-known/mcp-manifest.json`
- Tool definitions for AI assistant integration

### Project Structure
- `/client` - React frontend
  - `/src/components/ui` - shadcn/ui component library
  - `/src/hooks` - Custom hooks (auth, toast, mobile detection)
  - `/src/pages` - Page components (home, timeline, landing, communications)
  - `/src/lib` - Utilities and query client setup
- `/server` - Express backend
  - `index.ts` - Server entry with request logging middleware
  - `routes.ts` - API route definitions with ChittyOS discovery endpoints
  - `storage.ts` - Database operations interface
  - `chittyAuth.ts` - ChittyID OIDC authentication
  - `contradictionService.ts` - AI contradiction detection
  - `chittyBeacon.ts` - Real-time alerting service
  - `contextEmitter.ts` - ChittyConnect event publisher
  - `mcpService.ts` - MCP integration
  - `ingestionService.ts` - Document ingestion pipeline
  - `caseService.ts` - Case management logic
  - `timelineService.ts` - Timeline operations
  - `db.ts` - Drizzle database connection
  - `vite.ts` - Vite dev server integration
  - `/middleware` - Authorization middleware (service token auth)
- `/shared` - Shared TypeScript code
  - `schema.ts` - Drizzle schema, Zod validation, TypeScript types
- `/scripts` - Automation and tooling
  - `/registry` - ChittyRegistry integration scripts
  - `/mcp` - MCP integration scripts (Cloudflare inventory)
- `/docs` - Integration documentation
- `/functions` - Cloudflare Workers functions

### API Routes

**ChittyOS Discovery**:
- `/.well-known/chronicle-manifest.json` - Service manifest
- `/.well-known/service-manifest.json` - Standard service discovery
- `/.well-known/mcp-manifest.json` - MCP manifest
- `/openapi.json` - OpenAPI specification

**Core API** (all require authentication):
- `/api/auth/user` - Get current ChittyID user
- `/api/cases` - CRUD operations for cases
- `/api/timeline/entries` - Timeline entry CRUD with filtering
- `/api/timeline/entries/:id/sources` - Document source management
- `/api/timeline/search` - Full-text search across entries
- `/api/timeline/analysis/contradictions` - AI contradiction detection
- `/api/timeline/analysis/deadlines` - Upcoming deadline tracking

**Document Ingestion Pipeline** (Phase 1 SOTA):
- `/api/ingestion/upload` - Upload files (multipart) → R2 → Timeline → Auto-embed (async)
- `/api/ingestion/process` - Process pre-uploaded documents (legacy JSON API)
- `/api/ingestion/jobs` - Create ingestion jobs
- `/api/ingestion/jobs/:caseId` - Get ingestion job status

**Communications** (new feature):
- `/api/communications/conversations` - Conversation threads
- `/api/communications/messages` - Message CRUD
- `/api/communications/timeline/generate` - Generate timeline from messages
- `/api/communications/sources` - Cross-source message aggregation (iMessage, WhatsApp, email, DocuSign, OpenPhone)

**MCP Integration**:
- `/api/mcp/timeline` - Timeline management for AI assistants
- `/api/mcp/cases` - Case management
- `/api/mcp/ingest` - Document ingestion
- `/api/mcp/analyze` - Case analysis

**Admin**:
- `/api/admin/registry/preview` - ChittyRegistry inventory preview

### Database Schema

**Core Tables**:
- `users` - ChittyID user accounts
- `sessions` - Express session storage
- `cases` - Legal case records with ChittyPM integration (`chitty_pm_project_id`)
- `timeline_entries` - Events/tasks with temporal data and ChittyID linkage
- `timeline_sources` - Document attachments with verification status
- `timeline_contradictions` - AI-detected conflicts
- `data_ingestion_jobs` - Document processing queue
- `mcp_integrations` - MCP extension settings
- `chitty_id_users` - ChittyID user mapping

**Communications Tables** (new):
- `parties` - People/entities involved in cases
- `party_identifiers` - Email, phone, WhatsApp JID, etc.
- `conversations` - Message threads
- `messages` - Individual messages with ChittyID
- `conversation_messages` - Message-to-conversation linking
- `message_parties` - Message participants (sender/recipient/cc/bcc)
- `message_attachments` - Message attachments

**Key Schema Features**:
- Entry types: `'task'` and `'event'` with specific subtypes
- Confidence levels: `high/medium/low/unverified`
- Task status: `pending/in_progress/completed/blocked`
- Event status: `occurred/upcoming/missed`
- Soft deletion via `deleted_at` timestamp
- Relationship tracking via `related_entries` and `dependencies` arrays
- ChittyID integration: `chitty_id` field on timeline entries and messages
- Message sources: `imessage`, `whatsapp`, `email`, `docusign`, `openphone`

### Environment Variables

**Database**:
- `DATABASE_URL` - PostgreSQL connection string (required)
- `PORT` - Server port (defaults to 5000)
- `NODE_ENV` - development/production

**ChittyID Authentication**:
- `CHITTYID_ISSUER_URL` - OIDC issuer (defaults to https://auth.chitty.com/oidc)
- `CHITTYID_CLIENT_ID` - OAuth client ID (defaults to "chittytimeline")
- `CHITTYID_CLIENT_SECRET` - OAuth client secret (required for production)
- `CHITTYID_REDIRECT_URI` - OAuth redirect URI (defaults to http://localhost:5000/auth/callback)
- `SESSION_SECRET` - Express session secret (auto-generated if not set)

**AI Services**:
- `ANTHROPIC_API_KEY` - Anthropic API key for contradiction detection (required for AI features)

**ChittyOS Integrations**:
- `CHITTYCONNECT_BASE_URL` - ChittyConnect API base URL
- `CHITTYCHRONICLE_SERVICE_TOKEN` - Service token for ChittyConnect authentication
- `CHITTY_BEACON_API_URL` - ChittyBeacon API URL (defaults to https://api.chittybeacon.com/v1)
- `CHITTYMCP_BASE_URL` - ChittyMCP base URL (defaults to https://mcp.chitty.cc)

**Cloudflare R2 (Primary Document Storage - SOT)**:
- `R2_ACCOUNT_ID` - Cloudflare account ID (required for R2)
- `R2_ACCESS_KEY_ID` - R2 access key ID (required for R2)
- `R2_SECRET_ACCESS_KEY` - R2 secret access key (required for R2)
- `R2_BUCKET_NAME` - R2 bucket name (defaults to "chittychronicle-documents")
- `R2_PUBLIC_URL` - Optional public URL for bucket (e.g., custom domain)

**Google Cloud (Legacy)**:
- `GOOGLE_CLOUD_PROJECT` - Google Cloud project ID for file uploads
- `GOOGLE_CLOUD_STORAGE_BUCKET` - GCS bucket name for document storage

## Key Implementation Patterns

### Authentication Flow
1. User redirects to ChittyID OIDC (`/auth/login`)
2. ChittyID authenticates and returns to `/auth/callback`
3. Session stored in PostgreSQL via `connect-pg-simple`
4. ChittyID tokens include roles, permissions, and ChittyChain attestations
5. Middleware enforces authentication: `isAuthenticated`, `hasRole`, `hasPermission`

### Contradiction Detection Workflow
1. Timeline entries fetched for a case
2. Entries formatted for Claude Sonnet 4 analysis
3. AI detects temporal, factual, witness, location, entity, and logical conflicts
4. Structured contradiction reports generated with severity and suggested resolutions
5. Results stored in `timeline_contradictions` table
6. Context event emitted to ChittyConnect

### Document Ingestion Pipeline (Phase 1 SOTA)

**Complete Pipeline Flow**:
1. **Upload** → Files uploaded via `/api/ingestion/upload` (multipart/form-data)
2. **R2 Storage** → Documents stored in Cloudflare R2 (Source of Truth)
3. **Analysis** → Document content analyzed for dates, entities, events
4. **Timeline Creation** → Timeline entries created with R2 key references
5. **Embedding Generation** → Vector embeddings auto-generated (async, non-blocking)
6. **Search Ready** → Entries immediately searchable via hybrid search

**Key Features**:
- Automatic R2 upload with unique key generation
- Fire-and-forget embedding generation (doesn't block uploads)
- Graceful fallback if R2 not configured (uses legacy filePath)
- Silent embedding failures (can regenerate via batch script)
- Supports up to 20 files per upload, 100MB per file

**API Usage**:
```bash
# Upload files with automatic pipeline processing
curl -X POST http://localhost:5000/api/ingestion/upload \
  -F "caseId=<uuid>" \
  -F "files=@document1.pdf" \
  -F "files=@document2.pdf"

# Response includes R2 keys, timeline entry IDs, embedding status
{
  "success": true,
  "jobId": "<uuid>",
  "result": {
    "documentsProcessed": 2,
    "entriesCreated": 5,
    "errors": [],
    "warnings": []
  },
  "message": "Uploaded and processed 2 documents → R2 → Timeline → Embeddings (async)",
  "filesProcessed": ["document1.pdf", "document2.pdf"]
}
```

### Context Event Publishing
All significant operations emit context events:
- Events logged to `reports/context-events.jsonl` (local observability)
- If `CHITTYCONNECT_BASE_URL` set, events published via HTTP POST
- Non-fatal, best-effort design (failures are silent)
- Event structure: `event_type`, `subject_id`, `related_ids`, `timestamp`, `source`, `payload`

### Message Timeline Generation
1. Messages aggregated from multiple sources (iMessage, WhatsApp, email, DocuSign, OpenPhone)
2. Cross-source deduplication via party identifiers
3. AI analysis extracts legal events from message content
4. Timeline entries auto-generated with message linkage (`message_id`, `message_source`)
5. Confidence levels assigned based on message metadata

### Service Discovery
ChittyChronicle implements ChittyOS service discovery patterns:
- Registry manifest at `/.well-known/chronicle-manifest.json`
- OpenAPI spec at `/openapi.json`
- MCP manifest at `/.well-known/mcp-manifest.json`
- Manifests generated via `scripts/registry/` tools

### Important Model Selection
The contradiction detection service uses Claude Sonnet 4 (`claude-sonnet-4-20250514`). When modifying AI code, preserve this model selection unless explicitly requested to change.

## Integration Status

### ✅ Fully Implemented

**Contradiction Detection Service**:
- AI-powered analysis using Claude Sonnet 4
- Database persistence with full CRUD operations
- Real-time and batch analysis capabilities
- Graceful fallback to demo analysis if API unavailable

**Context Emitter**:
- Local JSONL logging to `reports/context-events.jsonl`
- Best-effort HTTP publishing to ChittyConnect
- Non-fatal design (failures are silent)

**MCP Service**:
- Model Context Protocol integration
- Tool definitions for AI assistants
- Manifest served at `/.well-known/mcp-manifest.json`

**Session Management**:
- PostgreSQL session storage
- Secure cookie handling
- OIDC token refresh

### ⚠️ Partial Implementation

**ChittyID Authentication**:
- **Status**: Hybrid implementation with fallback to Replit Auth
- **What Works**: OIDC authentication, session management, RBAC
- **What's Missing**: Production integration with id.chitty.cc requires `CHITTYID_SERVICE_TOKEN`
- **Development**: Falls back to Replit Auth when ChittyAuth unavailable
- **Important**: ChittyID minting now properly requires external service (no local generation)

**ChittyPM Integration**:
- **Status**: Real HTTP/WebSocket client implemented
- **What Works**: Project/task sync, bidirectional updates, WebSocket real-time
- **What's Missing**: Requires external ChittyPM service at `CHITTYPM_API_URL`
- **Development**: Mock endpoints exist but not wired in production code

**ChittyBeacon Alerting**:
- **Status**: Core infrastructure complete
- **What Works**: Alert generation, WebSocket delivery, alert queue processing
- **What's Missing**: Email/SMS/Push delivery (currently console.log only)
- **Development**: Only web channel (WebSocket) actually delivers alerts

**ChittyTrust Service**:
- **Status**: Trust scoring complete, blockchain pending
- **What Works**: Trust score calculation, factor analysis, integrity verification
- **What's Missing**: Blockchain attestation (currently returns mock transaction IDs)
- **Development**: Full trust analysis without blockchain persistence

### 🚧 Planned / Not Yet Implemented

**ChittyChain Blockchain Integration**:
- Blockchain attestation submission
- Transaction receipt storage
- Immutable audit trail verification
- **Roadmap**: Q2 2025

**Multi-Channel Notifications**:
- Email delivery integration
- SMS delivery via Twilio/SNS
- Push notifications (FCM/APNs)
- **Roadmap**: Q1 2025

**Full ChittyPM Production Integration**:
- Service auto-discovery
- Health check integration
- **Roadmap**: When ChittyPM reaches production

### Configuration Status

**Required for Full Functionality**:
- `DATABASE_URL` - PostgreSQL connection (required)
- `ANTHROPIC_API_KEY` - For AI contradiction detection
- `CHITTYID_SERVICE_TOKEN` - For ChittyID minting

**Optional Integrations**:
- `CHITTYPM_API_URL` - ChittyPM integration (falls back to manual workflow)
- `CHITTYCONNECT_BASE_URL` - Context sharing (falls back to local logging)
- `CHITTY_BEACON_API_URL` - Advanced alerting (falls back to basic WebSocket)
- `CHITTYID_CLIENT_SECRET` - Full ChittyID auth (falls back to Replit Auth)

## Development Notes

- Single port (5000) serves both API and client assets
- Vite HMR in development, static serving in production
- Request logging middleware truncates responses at 80 chars
- Path aliases: `@/` → client/src, `@shared/` → shared, `@assets/` → attached_assets
- All ChittyOS integrations are optional (fail gracefully if not configured)
- MCP tools enable AI assistants (Claude, ChatGPT) to manage timelines directly
- Communications feature enables cross-platform message aggregation and timeline generation

## Important Implementation Notes

**ChittyID Authority**:
- All ChittyIDs MUST come from `id.chitty.cc`
- Local ChittyID generation has been removed (as of 2025-10-18)
- `mintChittyId()` method now requires `CHITTYID_SERVICE_TOKEN` and calls external service

**Contradiction Analysis**:
- Results are now persisted to `timeline_contradictions` table
- Cache invalidation on new timeline entries
- AI analysis runs on-demand or can be scheduled

**Authentication Flow**:
- Primary: ChittyAuth (OIDC via id.chitty.cc)
- Fallback: Replit Auth (for development)
- Configure via `AUTH_PROVIDER` environment variable (coming soon)