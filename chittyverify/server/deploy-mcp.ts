#!/usr/bin/env node

/**
 * ChittyChain MCP Server Deployment Script
 * Deploys Model Context Protocol servers to Cloudflare Workers
 */

interface MCPServer {
  name: string;
  description: string;
  sourceFile: string;
  workerName: string;
  status: 'available' | 'needs-secrets' | 'ready';
}

const MCP_SERVERS: MCPServer[] = [
  {
    name: 'Email Bill Ingestion',
    description: 'Processes bills and receipts from email attachments',
    sourceFile: 'attached_assets/email_bill_ingestion_mcp_1753558749915.ts',
    workerName: 'chittychain-email-bills',
    status: 'available'
  },
  {
    name: 'CAO Bill Integration',
    description: 'Integrates with Cook County Assessor Office billing systems',
    sourceFile: 'attached_assets/cao_bill_mcp_integration_1753558749917.ts',
    workerName: 'chittychain-cao-bills',
    status: 'available'
  },
  {
    name: 'Plaid Bill Integration',
    description: 'Connects with financial institutions via Plaid for transaction evidence',
    sourceFile: 'attached_assets/plaid_bill_integration_1753558749916.js',
    workerName: 'chittychain-plaid-bills',
    status: 'needs-secrets'
  },
  {
    name: 'Fortress MCP Server',
    description: 'Secure AI execution environment with evidence validation',
    sourceFile: 'attached_assets/fortress_mcp_server_1753558749917.ts',
    workerName: 'chittychain-fortress',
    status: 'available'
  },
  {
    name: 'Integrated MCP Coordinator',
    description: 'Orchestrates multiple MCP servers and data flow',
    sourceFile: 'attached_assets/integrated_mcp_coordinator_1753558749917.ts',
    workerName: 'chittychain-coordinator',
    status: 'ready'
  }
];

async function checkCloudflareStatus() {
  console.log('🔗 ChittyChain MCP Server Deployment Status\n');

  if (!process.env.CLOUDFLARE_API_TOKEN) {
    console.log('❌ Cloudflare API Token not configured');
    console.log('   Setup: Add CLOUDFLARE_API_TOKEN to environment variables');
    console.log('   1. Go to Cloudflare Dashboard → My Profile → API Tokens');
    console.log('   2. Create Custom Token with Zone:Read, Worker:Edit permissions');
    console.log('   3. Copy token and add as CLOUDFLARE_API_TOKEN secret\n');
    return false;
  }

  console.log('✅ Cloudflare API Token configured\n');
  return true;
}

async function displayMCPServers() {
  console.log('📋 Available MCP Servers for Deployment:\n');

  MCP_SERVERS.forEach((server, index) => {
    const statusIcon = server.status === 'ready' ? '🟢' : 
                      server.status === 'needs-secrets' ? '🟡' : '🔵';
    
    console.log(`${index + 1}. ${statusIcon} ${server.name}`);
    console.log(`   Description: ${server.description}`);
    console.log(`   Worker Name: ${server.workerName}`);
    console.log(`   Status: ${server.status}`);
    console.log(`   Source: ${server.sourceFile}\n`);
  });
}

async function generateDeploymentCommands() {
  console.log('🚀 Deployment Commands (run after configuring Cloudflare API token):\n');

  MCP_SERVERS.forEach((server, index) => {
    console.log(`# Deploy ${server.name}`);
    console.log(`npx wrangler deploy ${server.sourceFile} --name ${server.workerName}`);
    console.log(`# Test deployment`);
    console.log(`curl https://${server.workerName}.your-subdomain.workers.dev/health\n`);
  });

  console.log('🔧 Additional Setup:\n');
  console.log('1. Configure custom domain for MCP servers');
  console.log('2. Set up environment variables for each worker');
  console.log('3. Configure CORS settings for ChittyChain integration');
  console.log('4. Set up monitoring and logging\n');
}

async function main() {
  const cloudflareReady = await checkCloudflareStatus();
  await displayMCPServers();
  
  if (cloudflareReady) {
    await generateDeploymentCommands();
    console.log('✅ Ready to deploy MCP servers to Cloudflare Workers');
    console.log('🔗 MCP servers will extend ChittyChain with external data integrations');
  } else {
    console.log('🔧 Configure Cloudflare API token to enable MCP server deployment');
  }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}

export { MCP_SERVERS, checkCloudflareStatus };