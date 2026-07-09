# ARIBIA Chronicle - Cloudflare Remote Deployment Guide

## Overview

This guide covers deploying ARIBIA Chronicle to **Cloudflare's Edge Network** for global, low-latency access. The deployment uses:

- **Cloudflare Workers** - Serverless compute at the edge
- **Cloudflare D1** - Distributed SQLite database
- **Cloudflare R2** - Object storage for evidence files
- **Cloudflare KV** - Key-value storage for agent state
- **Cloudflare Cron Triggers** - Scheduled autonomous agent execution
- **Cloudflare Durable Objects** - Stateful coordination

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    CLOUDFLARE EDGE NETWORK                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│   │   Workers    │───▶│   D1 Database │    │  R2 Storage  │   │
│   │  (Compute)   │    │  (SQL Data)  │    │ (Evidence)   │   │
│   └──────────────┘    └──────────────┘    └──────────────┘   │
│          │                                                      │
│          ▼                                                      │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
│   │  Durable     │    │   KV Store   │    │  Cron        │   │
│   │  Objects     │    │ (Agent State)│    │  Triggers    │   │
│   └──────────────┘    └──────────────┘    └──────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

### 1. Cloudflare Account

- Sign up at https://dash.cloudflare.com
- Upgrade to Workers Paid plan ($5/month) for:
  - Unlimited requests
  - Longer CPU time
  - Durable Objects
  - D1 database

### 2. Domain Setup

- Add domain to Cloudflare (e.g., `chitty.cc`)
- Set up DNS records:
  ```
  aribia-chronicle.chitty.cc → Cloudflare Worker
  ```

### 3. Install Wrangler CLI

```bash
npm install -g wrangler

# Login to Cloudflare
wrangler login
```

### 4. Environment Variables

Required secrets:
- `ANTHROPIC_API_KEY` - Claude Sonnet 4 API key
- `SESSION_SECRET` - Random secret for sessions
- `CHITTYID_SERVICE_TOKEN` - ChittyID authentication (optional)
- `CHITTYCHAIN_API_KEY` - ChittyChain attestation (optional)

## Quick Start - Automated Deployment

### Option 1: Full Automated Setup

```bash
# 1. Create all Cloudflare resources
bash deploy/cloudflare-setup.sh production

# 2. Set required secrets
wrangler secret put ANTHROPIC_API_KEY --env=production
wrangler secret put SESSION_SECRET --env=production

# 3. Deploy to Cloudflare
bash deploy/cloudflare-deploy.sh production
```

### Option 2: Manual Setup

See detailed steps below.

## Step-by-Step Manual Deployment

### Step 1: Create D1 Database

```bash
# Create production database
wrangler d1 create aribia-chronicle-production

# Output will show database ID - copy it
# Example: database_id = "abc123..."
```

Update `wrangler.aribia.toml`:
```toml
[[env.production.d1_databases]]
binding = "DB"
database_name = "aribia-chronicle-production"
database_id = "YOUR_DATABASE_ID_HERE"
```

### Step 2: Apply Database Schema

```bash
# Generate schema SQL
npm run db:push

# Apply to D1
wrangler d1 execute aribia-chronicle-production \
  --file=drizzle/schema.sql \
  --env=production
```

### Step 3: Create R2 Buckets

```bash
# Evidence storage
wrangler r2 bucket create aribia-evidence-prod

# Document storage
wrangler r2 bucket create aribia-documents-prod
```

### Step 4: Create KV Namespaces

```bash
# Agent state storage
wrangler kv:namespace create aribia-chronicle-agent-state-production

# Cache storage
wrangler kv:namespace create aribia-chronicle-cache-production
```

Update `wrangler.aribia.toml` with the KV namespace IDs from output.

### Step 5: Set Secrets

```bash
# Required
wrangler secret put ANTHROPIC_API_KEY --env=production
wrangler secret put SESSION_SECRET --env=production

# Optional (for full ChittyOS integration)
wrangler secret put CHITTYID_SERVICE_TOKEN --env=production
wrangler secret put CHITTYCHAIN_API_KEY --env=production
wrangler secret put CHITTYBEACON_API_KEY --env=production
```

### Step 6: Build Application

```bash
npm run build
```

### Step 7: Deploy to Cloudflare

```bash
# Deploy to production
wrangler deploy --config=wrangler.aribia.toml --env=production

# Or use deployment script
bash deploy/cloudflare-deploy.sh production
```

### Step 8: Verify Deployment

```bash
# Check health endpoint
curl https://aribia-chronicle.chitty.cc/health

# View logs
wrangler tail --env=production --format=pretty

# Check metrics
wrangler metrics --env=production
```

## Configuration

### Domain Routing

Edit `wrangler.aribia.toml`:

```toml
[env.production]
route = { pattern = "aribia-chronicle.chitty.cc/*", zone_name = "chitty.cc" }
```

### Autonomous Agent Scheduling

Cron triggers are configured in `wrangler.aribia.toml`:

```toml
# Evidence Agent - Every 5 minutes
[[env.production.triggers.crons]]
cron = "*/5 * * * *"
handler = "custom/agents/evidence-agent.ts"

# Analysis Agent - Every 15 minutes
[[env.production.triggers.crons]]
cron = "*/15 * * * *"
handler = "custom/agents/analysis-agent.ts"

# Litigation Agent - Every hour
[[env.production.triggers.crons]]
cron = "0 * * * *"
handler = "custom/agents/litigation-agent.ts"
```

### Resource Limits

```toml
[limits]
cpu_ms = 50000  # Extended CPU time for AI processing
```

## Monitoring and Observability

### Real-time Logs

```bash
# Stream all logs
wrangler tail --env=production --format=pretty

# Filter by agent
wrangler tail --env=production | grep "EvidenceAgent"
```

### Metrics

```bash
# View metrics
wrangler metrics --env=production

# Or access Cloudflare Dashboard
https://dash.cloudflare.com → Workers → aribia-chronicle → Metrics
```

### Analytics

Access via Cloudflare Dashboard:
- Request volume
- CPU time usage
- Error rates
- Geographic distribution

## Autonomous Agents on Edge

### How Agents Work on Cloudflare

1. **Cron Triggers** invoke agent handlers on schedule
2. **Durable Objects** maintain agent state across invocations
3. **KV Storage** persists agent data globally
4. **D1 Database** stores evidence and analysis
5. **R2 Storage** holds evidence files

### Agent Execution Flow

```
Cron Trigger (*/5 * * * *)
    ↓
Worker Invocation
    ↓
Durable Object (Agent State)
    ↓
Process Evidence
    ↓
Write to D1 + R2 + KV
    ↓
Ship Event to ChittyChain
    ↓
Complete
```

### Monitoring Agent Execution

```bash
# View agent logs in real-time
wrangler tail --env=production | grep "Agent"

# Check agent state in KV
wrangler kv:key get "evidence-agent:state" \
  --binding=AGENT_STATE \
  --env=production
```

## Cost Optimization

### Cloudflare Pricing (as of 2024)

**Workers Paid Plan**: $5/month
- Unlimited requests
- 50ms CPU time per request
- Durable Objects included

**Additional Costs**:
- D1: $0.75/million reads, $4.50/million writes
- R2: $0.015/GB stored, $0.36/million Class A ops
- KV: $0.50/million reads, $5.00/million writes

**Estimated Monthly Cost for ARIBIA**:
- Base: $5 (Workers Paid)
- D1: ~$2-5 (typical usage)
- R2: ~$1-3 (evidence storage)
- KV: ~$1-2 (agent state)
- **Total: ~$10-15/month**

### Cost Optimization Tips

1. **Cache aggressively** - Use KV for read-heavy data
2. **Batch agent operations** - Process multiple items per invocation
3. **Optimize cron frequency** - Adjust based on case activity
4. **Use R2 lifecycle rules** - Archive old evidence

## Performance

### Expected Performance

- **Request Latency**: <100ms (global edge)
- **Agent Processing**: 1-5s per batch
- **Database Queries**: <50ms (D1 SQLite)
- **File Storage**: <200ms (R2 multi-region)

### Performance Tuning

1. **Enable Smart Placement**:
   ```toml
   [placement]
   mode = "smart"
   ```

2. **Optimize Durable Objects**:
   - Use per-agent Durable Objects
   - Minimize state transitions

3. **Cache Strategy**:
   - Cache AI analysis results in KV
   - Use Cloudflare Cache API for static assets

## Troubleshooting

### Deployment Fails

```bash
# Check wrangler config
wrangler deploy --dry-run --config=wrangler.aribia.toml

# Validate syntax
npx toml-cli validate wrangler.aribia.toml
```

### Agents Not Running

```bash
# Check cron trigger status
wrangler tail --env=production | grep "cron"

# Manually trigger agent
wrangler dev --test-scheduled --env=production
```

### Database Errors

```bash
# Check D1 connection
wrangler d1 execute aribia-chronicle-production \
  --command="SELECT 1"

# View database schema
wrangler d1 execute aribia-chronicle-production \
  --command="SELECT * FROM sqlite_master"
```

### High Costs

```bash
# Check usage metrics
wrangler metrics --env=production

# Review cron frequency
# Adjust in wrangler.aribia.toml
```

## Rollback

### Quick Rollback

```bash
# Deploy previous version
wrangler rollback --env=production

# Or deploy specific version
wrangler versions deploy VERSION_ID --env=production
```

### Version Management

```bash
# List deployed versions
wrangler versions list --env=production

# View version details
wrangler versions view VERSION_ID --env=production
```

## Scaling

### Horizontal Scaling

Cloudflare Workers automatically scale horizontally:
- No configuration needed
- Handles millions of requests
- Global edge distribution

### Vertical Scaling

For heavier AI processing:

```toml
[limits]
cpu_ms = 50000  # Max CPU time per request
```

### Multi-Region Deployment

Automatic with Cloudflare:
- 300+ edge locations
- Automatic failover
- Geographic routing

## Security

### Secrets Management

```bash
# Rotate secrets
wrangler secret put ANTHROPIC_API_KEY --env=production

# Delete secret
wrangler secret delete OLD_SECRET --env=production

# List secrets (names only, values hidden)
wrangler secret list --env=production
```

### Access Control

- Use Cloudflare Access for dashboard protection
- Implement ChittyID for user authentication
- Enable Cloudflare WAF for DDoS protection

### Audit Trail

All operations logged to:
- Cloudflare Analytics
- Workers Logs
- ChittyChain blockchain (if enabled)

## Backup and Recovery

### Database Backup

```bash
# Export D1 database
wrangler d1 export aribia-chronicle-production > backup.sql

# Restore from backup
wrangler d1 execute aribia-chronicle-production --file=backup.sql
```

### R2 Backup

```bash
# Download all evidence
wrangler r2 object get aribia-evidence-prod/OBJECT_NAME --file=backup/

# Upload from backup
wrangler r2 object put aribia-evidence-prod/OBJECT_NAME --file=backup/
```

## Best Practices

1. **Use Staging Environment** - Test all changes in staging first
2. **Monitor Agent Execution** - Check logs daily for errors
3. **Set Up Alerts** - Use Cloudflare notifications for critical events
4. **Version Control** - Tag deployments in Git
5. **Document Changes** - Update deployment notes for each release
6. **Test Rollback** - Practice rollback procedures
7. **Review Costs** - Check Cloudflare billing monthly

## Support

### Cloudflare Support

- **Dashboard**: https://dash.cloudflare.com
- **Docs**: https://developers.cloudflare.com
- **Discord**: https://discord.gg/cloudflaredev
- **Status**: https://www.cloudflarestatus.com

### ARIBIA Support

- **Technical**: See main documentation
- **Legal**: Contact legal team

---

**Version**: 1.0.0
**Last Updated**: 2025-10-30
**Deployment Type**: Cloudflare Edge
