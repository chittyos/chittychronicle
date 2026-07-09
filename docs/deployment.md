# ARIBIA Chronicle - Deployment Guide

## Overview

This guide covers the complete deployment process for ARIBIA Chronicle using the ChittyCFD v1.0 standard. The deployment is fully automated through shell scripts and configuration files.

## Prerequisites

### System Requirements

- **OS**: Linux, macOS, or Windows (WSL2)
- **Node.js**: v18.0.0 or higher
- **npm**: v9.0.0 or higher
- **PostgreSQL**: v14 or higher (Neon recommended)
- **Git**: v2.30 or higher

### Required API Keys

- **Anthropic API Key**: For Claude Sonnet 4 analysis
- **ChittyID Service Token**: For authentication
- **ChittyChain API Key**: For blockchain attestation (optional)
- **ChittyBeacon API Key**: For alerting (optional)

### Optional Tools

- **chittysecrets CLI**: For automated secret management
- **Docker**: For containerized deployment
- **Cloudflare CLI**: For edge deployment

## Deployment Environments

### 1. Development

**Purpose**: Local development and testing

```bash
bash deploy/setup.sh development
```

**Configuration**:
- Uses local database
- Mock external services
- Debug logging enabled
- Hot reload enabled
- Test data seeding

### 2. Staging

**Purpose**: Pre-production validation

```bash
bash deploy/setup.sh staging
```

**Configuration**:
- Staging database
- Real external services
- Integration tests required
- Smoke tests required
- Limited agent processing

### 3. Production

**Purpose**: Live case management

```bash
bash deploy/setup.sh production
```

**Configuration**:
- Production database
- All services enabled
- Security scan required
- Legal compliance check
- Full agent automation
- Monitoring and alerting

## Deployment Process

### Step-by-Step Deployment

#### 1. Clone Repository

```bash
git clone https://github.com/chittyapps/chittychronicle.git aribia-chronicle
cd aribia-chronicle
```

#### 2. Configure Secrets

**Option A: Using chittysecrets CLI**

```bash
# Login to chittysecrets
eval $(op signin)

# Secrets will be auto-resolved during setup
bash deploy/setup.sh production
```

**Option B: Manual Environment Variables**

```bash
# Create .env file
cat > .env <<EOF
DATABASE_URL=postgresql://...
ANTHROPIC_API_KEY=sk-ant-...
CHITTYID_SERVICE_TOKEN=...
CHITTYCHAIN_API_KEY=...
SESSION_SECRET=$(openssl rand -base64 32)
EOF
```

#### 3. Review Configuration

Edit `config/aribia-litigation.yaml` to customize:

```yaml
business:
  case:
    name: "Arias v Bianchi"
    number: "2024D007847"

evidence:
  source_paths:
    - path: "/path/to/evidence"
      auto_import: true

agents:
  evidence_processor:
    processing_interval: "5m"
```

#### 4. Run Master Setup

```bash
bash deploy/setup.sh production
```

This script will:
1. ✅ Validate CFD v1.0 compliance
2. ✅ Install dependencies
3. ✅ Resolve secrets
4. ✅ Apply configuration
5. ✅ Deploy custom modules
6. ✅ Setup database
7. ✅ Initialize agents
8. ✅ Run tests
9. ✅ Perform health check

#### 5. Start Application

```bash
# Development mode (with hot reload)
npm run dev

# Production mode
npm run start
```

#### 6. Verify Deployment

```bash
# Check health
curl http://localhost:5000/health

# Check agent status
curl http://localhost:5000/api/agents/status

# Open dashboard
open http://localhost:5000
```

## Configuration Management

### Configuration Files

```
config/
├── aribia-litigation.yaml    # Main case configuration
├── secrets.yaml             # Secret references
├── development.yaml         # Dev overrides
├── staging.yaml            # Staging overrides
└── production.yaml         # Production overrides
```

### Configuration Hierarchy

1. **Base**: `config/aribia-litigation.yaml`
2. **Environment**: `config/{environment}.yaml`
3. **Secrets**: `config/secrets.yaml`
4. **Environment Variables**: `.env`

Later configurations override earlier ones.

### Updating Configuration

```bash
# Edit configuration
vim config/aribia-litigation.yaml

# Apply changes
bash deploy/apply-config.sh production

# Restart agents
bash deploy/restart-agents.sh
```

## Agent Management

### Initialize Agents

```bash
bash deploy/init-agents.sh
```

### Start Individual Agent

```bash
# Evidence Agent
npm run agent:evidence:start

# Analysis Agent
npm run agent:analysis:start

# Litigation Agent
npm run agent:litigation:start
```

### Stop Agents

```bash
# Stop all agents
bash deploy/stop-agents.sh

# Stop individual agent
npm run agent:evidence:stop
```

### Restart Agents

```bash
# Restart all agents
bash deploy/restart-agents.sh

# Restart individual agent
npm run agent:evidence:restart
```

### Monitor Agents

```bash
# View all agent logs
tail -f logs/*.log

# View specific agent
tail -f logs/evidence-agent.log

# Agent status
curl http://localhost:5000/api/agents/status
```

## Database Management

### Initial Setup

```bash
# Push schema to database
npm run db:push
```

### Migrations

```bash
# Generate migration
npm run db:generate

# Apply migration
npm run db:migrate

# Rollback migration
npm run db:rollback
```

### Backup

```bash
# Backup database
pg_dump $DATABASE_URL > backup.sql

# Restore database
psql $DATABASE_URL < backup.sql
```

## Validation and Testing

### CFD Validation

```bash
bash deploy/validate-cfd.sh
```

### Unit Tests

```bash
npm test
```

### Integration Tests

```bash
npm run test:integration
```

### Smoke Tests

```bash
npm run test:smoke
```

### Agent Tests

```bash
npm test -- agents/
```

## Monitoring

### Health Checks

```bash
# Overall health
curl http://localhost:5000/health

# Agent health
curl http://localhost:5000/api/agents/evidence/health
curl http://localhost:5000/api/agents/analysis/health
curl http://localhost:5000/api/agents/litigation/health
```

### Metrics

```bash
# View metrics
curl http://localhost:5000/api/metrics

# Prometheus metrics
curl http://localhost:5000/metrics
```

### Logging

```bash
# Application logs
tail -f logs/app.log

# Agent logs
tail -f logs/evidence-agent.log
tail -f logs/analysis-agent.log
tail -f logs/litigation-agent.log

# Error logs
tail -f logs/error.log
```

## Scaling

### Horizontal Scaling

```bash
# Increase agent workers
export MAX_WORKERS=20
bash deploy/restart-agents.sh
```

### Vertical Scaling

```bash
# Increase Node.js memory
export NODE_OPTIONS="--max-old-space-size=4096"
npm run start
```

### Database Scaling

```bash
# Increase connection pool
DATABASE_POOL_SIZE=50 npm run start
```

## Security

### SSL/TLS Configuration

```bash
# Enable HTTPS
export SSL_CERT_PATH=/path/to/cert.pem
export SSL_KEY_PATH=/path/to/key.pem
npm run start
```

### Firewall Rules

```bash
# Allow only necessary ports
sudo ufw allow 5000/tcp   # Application
sudo ufw allow 22/tcp     # SSH
sudo ufw enable
```

### Secret Rotation

```bash
# Rotate secrets
op item edit "ANTHROPIC_API_KEY" --vault Private

# Re-deploy
bash deploy/apply-config.sh production
bash deploy/restart-agents.sh
```

## Troubleshooting

### Deployment Fails

```bash
# Check logs
cat logs/deployment.log

# Validate configuration
bash deploy/validate-cfd.sh

# Check dependencies
npm doctor
```

### Agent Fails to Start

```bash
# Check agent logs
tail -f logs/evidence-agent.log

# Verify configuration
npm run config:validate

# Restart with debug
DEBUG=* npm run agent:evidence:start
```

### Database Connection Issues

```bash
# Test connection
psql $DATABASE_URL -c "SELECT 1"

# Check connection pool
curl http://localhost:5000/api/db/pool
```

### High Memory Usage

```bash
# Check process memory
ps aux | grep node

# Restart with increased memory
NODE_OPTIONS="--max-old-space-size=8192" npm run start
```

## Rollback

### Automatic Rollback

```bash
bash deploy/rollback.sh
```

### Manual Rollback

```bash
# Stop services
bash deploy/stop-agents.sh
npm run stop

# Checkout previous version
git checkout HEAD~1

# Re-deploy
bash deploy/setup.sh production
```

## Maintenance

### Update Dependencies

```bash
# Update npm packages
npm update

# Check for security issues
npm audit

# Fix vulnerabilities
npm audit fix
```

### Clean Up

```bash
# Clear logs
rm -rf logs/*.log

# Clear cache
npm run cache:clear

# Clear agent state
rm -rf .agents/*
```

### Backup

```bash
# Backup configuration
tar -czf config-backup.tar.gz config/

# Backup database
pg_dump $DATABASE_URL > db-backup.sql

# Backup evidence
tar -czf evidence-backup.tar.gz /path/to/evidence/
```

## Best Practices

1. **Always test in staging** before production deployment
2. **Backup database** before major changes
3. **Monitor agent logs** regularly
4. **Rotate secrets** every 90 days
5. **Review AI-generated documents** before filing
6. **Keep configuration in version control**
7. **Document all customizations**
8. **Run security scans** regularly

## Support

### Documentation

- [Agentic Architecture](agentic-architecture.md)
- [Configuration Guide](configuration.md)
- [Legal Workflows](legal-workflows.md)

### Issues

- **Platform Issues**: https://github.com/chittyapps/chittychronicle/issues
- **Case-Specific**: Contact legal team

### Emergency Contacts

- **Technical Support**: tech@aribia.com
- **Legal Support**: legal@aribia.com

---

**Version**: 1.0.0
**Last Updated**: 2025-10-29
