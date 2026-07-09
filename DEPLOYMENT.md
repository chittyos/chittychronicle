# ChittyChronicle Deployment Guide

**Date**: 2025-10-21
**Status**: Production-Ready

## Overview

ChittyChronicle uses GitHub Actions for automated deployment to Cloudflare infrastructure:
- **Frontend**: Cloudflare Pages at `https://app.chitty.cc/chronicle/`
- **Backend API**: Cloudflare Workers at `https://chronicle.chitty.cc/`

## Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    GitHub Repository                         │
│                  (push to main branch)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              GitHub Actions Workflow                         │
│                                                              │
│  1. Build Stage                                             │
│     - npm ci (install dependencies)                         │
│     - npm run build (vite + esbuild)                        │
│     - Upload build artifacts                                │
│                                                              │
│  2. Deploy Backend (Cloudflare Workers)                     │
│     - wrangler deploy                                       │
│     - Route: chronicle.chitty.cc/*                          │
│                                                              │
│  3. Deploy Frontend (Cloudflare Pages)                      │
│     - pages deploy                                          │
│     - Directory: dist/public                                │
│     - Route: app.chitty.cc/chronicle                        │
│     - Purge CDN cache                                       │
└─────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  Cloudflare Edge Network                     │
│                                                              │
│  Frontend: https://app.chitty.cc/chronicle/                 │
│  Backend:  https://chronicle.chitty.cc/                     │
└─────────────────────────────────────────────────────────────┘
```

## GitHub Secrets Configuration

### Required Secrets

Configure these in your GitHub repository settings under **Settings → Secrets and variables → Actions**:

#### 1. `CLOUDFLARE_API_TOKEN`
**Description**: Cloudflare API token with Workers and Pages permissions

**How to create**:
1. Go to Cloudflare Dashboard → My Profile → API Tokens
2. Click "Create Token"
3. Use "Edit Cloudflare Workers" template
4. Add additional permissions:
   - Account / Cloudflare Pages / Edit
   - Zone / Zone / Read
   - Zone / Cache Purge / Purge
5. Select specific account and zones
6. Create token and copy the value
7. Add to GitHub Secrets as `CLOUDFLARE_API_TOKEN`

**Required Permissions**:
```
Account:
  - Cloudflare Pages: Edit
  - Workers Scripts: Edit

Zone (chitty.cc):
  - Zone Settings: Read
  - Cache Purge: Purge
```

#### 2. `CLOUDFLARE_ACCOUNT_ID`
**Description**: Your Cloudflare account ID

**How to find**:
1. Go to Cloudflare Dashboard
2. Select any website
3. Scroll to the right sidebar
4. Copy "Account ID" value
5. Add to GitHub Secrets as `CLOUDFLARE_ACCOUNT_ID`

#### 3. `CLOUDFLARE_ZONE_ID`
**Description**: Zone ID for chitty.cc domain

**How to find**:
1. Go to Cloudflare Dashboard
2. Select "chitty.cc" domain
3. Scroll to the right sidebar under "API"
4. Copy "Zone ID" value
5. Add to GitHub Secrets as `CLOUDFLARE_ZONE_ID`

### Verification

After adding secrets, verify they are set:
```bash
# In GitHub repository
Settings → Secrets and variables → Actions → Repository secrets

You should see:
✓ CLOUDFLARE_API_TOKEN
✓ CLOUDFLARE_ACCOUNT_ID
✓ CLOUDFLARE_ZONE_ID
```

## Cloudflare Environment Variables

These must be configured in the **Cloudflare Workers dashboard** for the `chittychronicle` worker:

### How to Configure

1. Go to Cloudflare Dashboard → Workers & Pages
2. Select `chittychronicle` worker
3. Go to Settings → Variables
4. Add the following environment variables

### Required Variables

#### 1. `DATABASE_URL` (required)
**Description**: PostgreSQL connection string

**Format**:
```
postgresql://user:password@host:5432/chittychronicle?sslmode=require
```

**Recommendation**: Use Neon or Supabase for serverless PostgreSQL

#### 2. `CHITTYCONNECT_BASE_URL` (required)
**Description**: ChittyConnect API base URL

**Value**:
```
https://chittyconnect-staging.ccorp.workers.dev
```

**Production**:
```
https://chittyconnect.chitty.cc
```

#### 3. `CHITTYCHRONICLE_SERVICE_TOKEN` (required)
**Description**: Service token for ChittyConnect authentication

**How to obtain**:
1. Contact ChittyAuth administrator
2. Request service token for `chittychronicle` service
3. Token format: `svc_xxxxxxxxxxxxxxxxxxxxxxxx`

#### 4. `ANTHROPIC_API_KEY` (required for AI features)
**Description**: Anthropic API key for Claude Sonnet 4

**How to obtain**:
1. Go to https://console.anthropic.com/
2. Create API key
3. Copy key (starts with `sk-ant-`)

#### 5. `SESSION_SECRET` (required)
**Description**: Secret for Express session signing

**How to generate**:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the output and use as `SESSION_SECRET`

### Optional Variables

#### `CHITTYID_CLIENT_SECRET`
**Description**: OAuth client secret for ChittyID authentication

**Default Behavior**: Falls back to Replit Auth if not set

**Production**: Required for full ChittyID integration

#### `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_STORAGE_BUCKET`
**Description**: Google Cloud Storage for document uploads

**Default Behavior**: Document uploads disabled if not configured

### Verification

After configuring environment variables:

1. Test health endpoint:
   ```bash
   curl https://chronicle.chitty.cc/health
   ```

   Expected response:
   ```json
   {
     "status": "healthy",
     "service": "chittychronicle",
     "version": "1.0.0",
     "timestamp": "2025-10-21T..."
   }
   ```

2. Test ChittyConnect integration:
   ```bash
   curl https://chronicle.chitty.cc/api/chittyconnect/ecosystem/health
   ```

   Should return ecosystem awareness data (if ChittyConnect is configured)

## Deployment Workflows

### Automatic Deployment (Production)

**Trigger**: Push to `main` branch

**Workflow**: `.github/workflows/deploy.yml`

**Jobs**:
1. **Build** - Compile frontend and backend
2. **Deploy Backend** - Deploy to Cloudflare Workers
3. **Deploy Frontend** - Deploy to Cloudflare Pages
4. **Notify** - Report deployment status

**Example**:
```bash
git add .
git commit -m "feat: add new feature"
git push origin main
```

Deployment automatically starts and completes in ~3-5 minutes.

### Preview Deployment (Pull Requests)

**Trigger**: Open pull request to `main` branch

**Workflow**: `.github/workflows/ci.yml`

**Jobs**:
1. **Test** - Run type checking, database migration, tests
2. **Build** - Build application
3. **Deploy Preview** - Deploy to `chittychronicle-preview.pages.dev`
4. **Security Scan** - Run Trivy and npm audit

**Preview URL**: Posted as comment on pull request

### Manual Deployment

**Trigger**: GitHub Actions → Run workflow

**How to use**:
1. Go to GitHub repository
2. Click "Actions" tab
3. Select "Deploy ChittyChronicle" workflow
4. Click "Run workflow"
5. Select environment (production/staging)
6. Click "Run workflow"

## Build Artifacts

After successful build, the following artifacts are created:

### Frontend (`dist/public/`)
```
dist/public/
├── index.html              # Entry point
├── assets/
│   ├── index-[hash].js    # Main bundle (~558 kB)
│   ├── index-[hash].css   # Styles
│   └── ...
└── favicon.ico
```

**Deployment**: Uploaded to Cloudflare Pages

**URL**: `https://app.chitty.cc/chronicle/`

### Backend (`dist/index.js`)
```
dist/
└── index.js               # Bundled server (~180 kB)
```

**Deployment**: Uploaded to Cloudflare Workers

**URL**: `https://chronicle.chitty.cc/`

### Retention
Build artifacts are retained for 7 days in GitHub Actions.

## Monitoring and Troubleshooting

### Check Deployment Status

**GitHub Actions**:
1. Go to repository → Actions tab
2. View recent workflow runs
3. Click on a run to see detailed logs

**Cloudflare Dashboard**:
1. Workers & Pages → `chittychronicle`
2. View deployments and logs
3. Check analytics and error rates

### Common Issues

#### 1. Build Fails with "vite: command not found"

**Cause**: Dependencies not installed

**Fix**:
```yaml
# In workflow file
- name: Install dependencies
  run: npm ci  # ← Ensure this step exists
```

#### 2. Deployment Fails with "Invalid API token"

**Cause**: `CLOUDFLARE_API_TOKEN` is missing or invalid

**Fix**:
1. Verify secret is set in GitHub repository settings
2. Check token has correct permissions
3. Regenerate token if necessary

#### 3. Frontend 404 Errors

**Cause**: Base path misconfiguration

**Fix**: Verify `vite.config.ts` has correct base path:
```typescript
export default defineConfig({
  base: process.env.NODE_ENV === "production" ? "/chronicle/" : "/",
});
```

#### 4. Backend API Errors

**Cause**: Environment variables not set in Cloudflare Workers

**Fix**:
1. Go to Cloudflare Dashboard → Workers & Pages
2. Select `chittychronicle` worker
3. Settings → Variables
4. Add missing environment variables

#### 5. Database Connection Errors

**Cause**: `DATABASE_URL` not configured or incorrect

**Fix**:
1. Verify `DATABASE_URL` is set in Cloudflare Workers environment variables
2. Test connection string locally:
   ```bash
   psql "$DATABASE_URL"
   ```
3. Ensure database accepts connections from Cloudflare IPs

### Health Checks

**Backend Health**:
```bash
curl https://chronicle.chitty.cc/health
```

**Expected Response**:
```json
{
  "status": "healthy",
  "service": "chittychronicle",
  "version": "1.0.0",
  "timestamp": "2025-10-21T10:00:00.000Z"
}
```

**Frontend Health**:
```bash
curl -I https://app.chitty.cc/chronicle/
```

**Expected Response**:
```
HTTP/2 200
content-type: text/html
```

**Ecosystem Health**:
```bash
curl https://chronicle.chitty.cc/api/chittyconnect/ecosystem/health
```

**Expected Response**:
```json
{
  "success": true,
  "timestamp": 1729544896912,
  "ecosystem": {
    "totalServices": 12,
    "healthy": 10,
    "degraded": 1,
    "down": 1
  }
}
```

## Rollback Procedure

If a deployment introduces critical bugs:

### Option 1: Revert via Git
```bash
# Identify the last good commit
git log --oneline

# Revert to that commit
git revert <bad-commit-hash>

# Push to trigger new deployment
git push origin main
```

### Option 2: Rollback via Cloudflare Dashboard

**For Workers**:
1. Go to Cloudflare Dashboard → Workers & Pages
2. Select `chittychronicle` worker
3. View deployments
4. Click "Rollback" on previous deployment

**For Pages**:
1. Go to Cloudflare Dashboard → Workers & Pages
2. Select `chittychronicle` Pages project
3. View deployments
4. Click "Rollback" on previous deployment

### Option 3: Manual Workflow Dispatch
1. Go to GitHub Actions
2. Find the last successful deployment workflow run
3. Click "Re-run jobs"

## Security Best Practices

1. **Never commit secrets** to the repository
2. **Rotate API tokens** every 90 days
3. **Use least-privilege** permissions for API tokens
4. **Enable security scanning** (Trivy, npm audit) in CI
5. **Monitor deployment logs** for suspicious activity
6. **Use environment-specific** tokens (dev vs production)

## Next Steps

After initial deployment:

1. **Test all endpoints** - Verify API functionality
2. **Check integrations** - Ensure ChittyConnect, ChittyID, ChittyBeacon work
3. **Monitor logs** - Watch for errors in Cloudflare dashboard
4. **Set up alerts** - Configure monitoring for downtime
5. **Document runbook** - Create incident response procedures

## Support

- **ChittyConnect Integration**: See [CHITTYCONNECT_INTEGRATION.md](CHITTYCONNECT_INTEGRATION.md)
- **Architecture**: See [CLAUDE.md](CLAUDE.md)
- **GitHub Actions**: https://github.com/anthropics/chittychronicle/actions
- **Cloudflare Dashboard**: https://dash.cloudflare.com/

---

**Deployment Status**: ✅ Ready for production
**Last Updated**: 2025-10-21
