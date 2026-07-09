# ARIBIA Chronicle - Cloudflare Deployment Quickstart

## 🚀 Deploy to Cloudflare in 5 Minutes

This guide gets ARIBIA Chronicle running on Cloudflare's global edge network.

---

## Prerequisites

- Cloudflare account (free tier works, Paid recommended)
- Domain added to Cloudflare
- Anthropic API key

---

## Option 1: Automated Deployment (Recommended)

### Step 1: Install Wrangler

```bash
npm install -g wrangler
wrangler login
```

### Step 2: Create Resources

```bash
npm run cf:setup
```

This creates:
- ✅ D1 Database (SQL storage)
- ✅ R2 Buckets (Evidence & document storage)
- ✅ KV Namespaces (Agent state & cache)
- ✅ Applies database schema

### Step 3: Set Secrets

```bash
# Required
wrangler secret put ANTHROPIC_API_KEY --env=production
wrangler secret put SESSION_SECRET --env=production

# Generate random session secret
openssl rand -base64 32 | wrangler secret put SESSION_SECRET --env=production
```

### Step 4: Update Configuration

Edit `wrangler.aribia.toml` with the resource IDs from Step 2:

```bash
# Get D1 database ID
wrangler d1 list

# Get KV namespace IDs
wrangler kv:namespace list
```

Update the `database_id` and KV `id` fields in `wrangler.aribia.toml`.

### Step 5: Deploy

```bash
npm run cf:deploy
```

### Step 6: Verify

```bash
curl https://aribia-chronicle.chitty.cc/health
```

**Done!** 🎉

---

## Option 2: Manual Deployment

### 1. Create D1 Database

```bash
wrangler d1 create aribia-chronicle-production
```

Copy the `database_id` to `wrangler.aribia.toml`.

### 2. Apply Schema

```bash
npm run db:push
wrangler d1 execute aribia-chronicle-production --file=drizzle/schema.sql
```

### 3. Create R2 Buckets

```bash
wrangler r2 bucket create aribia-evidence-prod
wrangler r2 bucket create aribia-documents-prod
```

### 4. Create KV Namespaces

```bash
wrangler kv:namespace create aribia-chronicle-agent-state-production
wrangler kv:namespace create aribia-chronicle-cache-production
```

Copy the namespace IDs to `wrangler.aribia.toml`.

### 5. Set Secrets

```bash
wrangler secret put ANTHROPIC_API_KEY --env=production
wrangler secret put SESSION_SECRET --env=production
```

### 6. Deploy

```bash
npm run build
wrangler deploy --config=wrangler.aribia.toml --env=production
```

---

## Configuration

### Update Domain

Edit `wrangler.aribia.toml`:

```toml
[env.production]
route = { pattern = "your-domain.com/*", zone_name = "your-domain.com" }
```

### Update Account ID

```bash
# Get your account ID
wrangler whoami

# Update wrangler.aribia.toml
account_id = "your-account-id"
```

---

## Monitoring

### View Live Logs

```bash
npm run cf:logs
```

### Check Metrics

```bash
npm run cf:metrics
```

### Cloudflare Dashboard

https://dash.cloudflare.com → Workers → aribia-chronicle

---

## Autonomous Agents

Agents run automatically via Cron Triggers:

- **Evidence Agent**: Every 5 minutes
- **Analysis Agent**: Every 15 minutes
- **Litigation Agent**: Every hour
- **Timeline Synthesis**: Every 10 minutes
- **Strategy Advisor**: Every 30 minutes

Monitor execution:
```bash
wrangler tail --env=production | grep "Agent"
```

---

## Costs

### Cloudflare Workers Paid Plan
- **$5/month** base fee
- Unlimited requests
- 50ms CPU time per request

### Estimated Total Monthly Cost
- **$10-15/month** including D1, R2, and KV usage

---

## Environments

### Production
```bash
npm run cf:deploy
# URL: https://aribia-chronicle.chitty.cc
```

### Staging
```bash
npm run cf:deploy:staging
# URL: https://staging.aribia-chronicle.chitty.cc
```

---

## Troubleshooting

### Deployment Fails

```bash
# Check configuration
wrangler deploy --dry-run --config=wrangler.aribia.toml

# View detailed errors
wrangler deploy --config=wrangler.aribia.toml --env=production --verbose
```

### Agents Not Running

```bash
# Check cron triggers
wrangler tail --env=production | grep "cron"

# Manually test cron
wrangler dev --test-scheduled
```

### Database Issues

```bash
# Test connection
wrangler d1 execute aribia-chronicle-production --command="SELECT 1"

# Check tables
wrangler d1 execute aribia-chronicle-production --command="SELECT name FROM sqlite_master WHERE type='table'"
```

---

## Rollback

```bash
# Rollback to previous version
wrangler rollback --env=production

# List versions
wrangler versions list --env=production
```

---

## Next Steps

1. **Configure DNS** - Point your domain to Cloudflare
2. **Set up alerts** - Configure Cloudflare notifications
3. **Enable WAF** - Add Web Application Firewall rules
4. **Review logs** - Monitor agent execution daily
5. **Optimize costs** - Adjust cron frequencies as needed

---

## Support

- **Full Documentation**: [docs/cloudflare-deployment.md](docs/cloudflare-deployment.md)
- **Cloudflare Docs**: https://developers.cloudflare.com
- **Wrangler CLI**: https://developers.cloudflare.com/workers/wrangler/

---

## Security Checklist

- [ ] Secrets set in Cloudflare (not in code)
- [ ] SESSION_SECRET is random and secure
- [ ] API keys are rotated regularly
- [ ] Cloudflare Access configured (optional)
- [ ] WAF rules enabled (optional)
- [ ] Rate limiting configured (optional)

---

**Ready to go live? Run:**

```bash
npm run cf:setup
wrangler secret put ANTHROPIC_API_KEY --env=production
wrangler secret put SESSION_SECRET --env=production
npm run cf:deploy
```

**Your legal AI platform will be live at the edge in minutes!** ⚡️🌍
