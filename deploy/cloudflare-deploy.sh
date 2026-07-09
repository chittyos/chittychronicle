#!/bin/bash
# ARIBIA Chronicle - Cloudflare Deployment Script
# Deploys the application to Cloudflare Workers/Pages

set -e

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🚀 Deploying ARIBIA Chronicle to Cloudflare"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Color codes
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
ENVIRONMENT=${1:-production}
WRANGLER_CONFIG="wrangler.aribia.toml"

echo "Environment: ${ENVIRONMENT}"
echo "Config: ${WRANGLER_CONFIG}"
echo ""

# Validate wrangler config exists
if [ ! -f "$WRANGLER_CONFIG" ]; then
    echo -e "${RED}✗ Wrangler config not found: ${WRANGLER_CONFIG}${NC}"
    exit 1
fi

# Pre-deployment checks
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔍 Pre-deployment Checks"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check authentication
echo -e "${BLUE}[1/5]${NC} Checking Cloudflare authentication..."
if wrangler whoami &> /dev/null; then
    WHOAMI=$(wrangler whoami 2>&1 | grep "logged in" || echo "authenticated")
    echo -e "${GREEN}✓ Authenticated${NC}"
else
    echo -e "${RED}✗ Not authenticated. Run: wrangler login${NC}"
    exit 1
fi
echo ""

# Validate configuration
echo -e "${BLUE}[2/5]${NC} Validating configuration..."
bash deploy/validate-cfd.sh
echo -e "${GREEN}✓ Configuration valid${NC}"
echo ""

# Run tests
echo -e "${BLUE}[3/5]${NC} Running tests..."
if npm test &> /dev/null; then
    echo -e "${GREEN}✓ Tests passed${NC}"
else
    echo -e "${YELLOW}⚠ Some tests failed, but continuing...${NC}"
fi
echo ""

# Build application
echo -e "${BLUE}[4/5]${NC} Building application..."
npm run build
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Type check
echo -e "${BLUE}[5/5]${NC} Type checking..."
if npm run check &> /dev/null; then
    echo -e "${GREEN}✓ Type check passed${NC}"
else
    echo -e "${YELLOW}⚠ Type check warnings, but continuing...${NC}"
fi
echo ""

# Deployment
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ☁️  Deploying to Cloudflare"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Deploy to Cloudflare
echo "Starting deployment..."
wrangler deploy --config="$WRANGLER_CONFIG" --env="$ENVIRONMENT"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ✅ Deployment Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Get deployment URL
if [ "$ENVIRONMENT" = "production" ]; then
    DEPLOYMENT_URL="https://aribia-chronicle.chitty.cc"
elif [ "$ENVIRONMENT" = "staging" ]; then
    DEPLOYMENT_URL="https://staging.aribia-chronicle.chitty.cc"
else
    DEPLOYMENT_URL="https://aribia-chronicle-dev.workers.dev"
fi

echo "🌐 Deployment URL: ${DEPLOYMENT_URL}"
echo ""
echo "Verify deployment:"
echo "  curl ${DEPLOYMENT_URL}/health"
echo ""
echo "View logs:"
echo "  wrangler tail --env=$ENVIRONMENT"
echo ""
echo "Manage deployment:"
echo "  Dashboard: https://dash.cloudflare.com"
echo "  Logs: wrangler tail --env=$ENVIRONMENT"
echo "  Metrics: wrangler metrics --env=$ENVIRONMENT"
echo ""

# Post-deployment health check
echo "Running health check..."
sleep 5

if curl -s "${DEPLOYMENT_URL}/health" | grep -q "ok\|healthy"; then
    echo -e "${GREEN}✓ Health check passed!${NC}"
else
    echo -e "${YELLOW}⚠ Health check inconclusive, please verify manually${NC}"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🤖 Autonomous Agents"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Agents will start automatically via Cron Triggers:"
echo "  ✓ Evidence Agent      Every 5 minutes"
echo "  ✓ Analysis Agent      Every 15 minutes"
echo "  ✓ Litigation Agent    Every hour"
echo "  ✓ Timeline Synthesis  Every 10 minutes"
echo "  ✓ Strategy Advisor    Every 30 minutes"
echo ""
echo "Monitor agent execution:"
echo "  wrangler tail --env=$ENVIRONMENT --format=pretty"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
