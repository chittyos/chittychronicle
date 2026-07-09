/**
 * ChittyChain Secrets Manager
 * Secure API key and sensitive data management using chittysecrets
 */

import { Client } from '@chittysecrets/sdk';

interface SecretConfig {
  vaultId: string;
  itemTitle: string;
  fieldName: string;
}

class SecretsManager {
  private client: Client;
  private initialized = false;

  constructor() {
    // Initialize chittysecrets client
    this.client = new Client({
      auth: process.env.OP_SERVICE_ACCOUNT_TOKEN || '',
      integrationName: 'ChittyChain Evidence Ledger',
      integrationVersion: '1.0.0'
    });
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    
    try {
      // Test connection
      await this.client.vaults.listAll();
      this.initialized = true;
      console.log('✅ chittysecrets Secrets Manager initialized');
    } catch (error) {
      console.warn('⚠️  chittysecrets not available, falling back to environment variables');
      this.initialized = false;
    }
  }

  async getSecret(config: SecretConfig): Promise<string | null> {
    await this.initialize();
    
    if (!this.initialized) {
      // Fallback to environment variables
      return this.getEnvFallback(config.fieldName);
    }

    try {
      const item = await this.client.items.get(config.vaultId, config.itemTitle);
      const field = item.fields?.find(f => f.title === config.fieldName);
      return field?.value || null;
    } catch (error) {
      console.error(`Failed to get secret ${config.fieldName}:`, error);
      return this.getEnvFallback(config.fieldName);
    }
  }

  private getEnvFallback(fieldName: string): string | null {
    const envMapping: Record<string, string> = {
      'NOTION_API_KEY': 'NOTION_API_KEY',
      'NOTION_MASTER_EVIDENCE_DB_ID': 'NOTION_MASTER_EVIDENCE_DB_ID',
      'NOTION_ATOMIC_FACTS_DB_ID': 'NOTION_ATOMIC_FACTS_DB_ID',
      'NOTION_CASES_DB_ID': 'NOTION_CASES_DB_ID',
      'NOTION_USERS_DB_ID': 'NOTION_USERS_DB_ID',
      'NOTION_CHAIN_OF_CUSTODY_DB_ID': 'NOTION_CHAIN_OF_CUSTODY_DB_ID',
      'NOTION_CONTRADICTIONS_DB_ID': 'NOTION_CONTRADICTIONS_DB_ID',
      'NOTION_AUDIT_TRAIL_DB_ID': 'NOTION_AUDIT_TRAIL_DB_ID',
      'OPENAI_API_KEY': 'OPENAI_API_KEY',
      'ANTHROPIC_API_KEY': 'ANTHROPIC_API_KEY',
      'BLOCKCHAIN_PRIVATE_KEY': 'ORACLE_PRIVATE_KEY',
      'IPFS_API_KEY': 'IPFS_API_KEY'
    };

    const envVar = envMapping[fieldName];
    return envVar ? process.env[envVar] || null : null;
  }

  // Predefined secret configurations
  static readonly SECRETS = {
    NOTION_API_KEY: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion API',
      fieldName: 'NOTION_API_KEY'
    },
    NOTION_MASTER_EVIDENCE_DB_ID: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion Databases',
      fieldName: 'NOTION_MASTER_EVIDENCE_DB_ID'
    },
    NOTION_ATOMIC_FACTS_DB_ID: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion Databases',
      fieldName: 'NOTION_ATOMIC_FACTS_DB_ID'
    },
    NOTION_CASES_DB_ID: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion Databases',
      fieldName: 'NOTION_CASES_DB_ID'
    },
    NOTION_USERS_DB_ID: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion Databases',
      fieldName: 'NOTION_USERS_DB_ID'
    },
    NOTION_CHAIN_OF_CUSTODY_DB_ID: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion Databases',
      fieldName: 'NOTION_CHAIN_OF_CUSTODY_DB_ID'
    },
    NOTION_CONTRADICTIONS_DB_ID: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion Databases',
      fieldName: 'NOTION_CONTRADICTIONS_DB_ID'
    },
    NOTION_AUDIT_TRAIL_DB_ID: {
      vaultId: 'ChittyChain',
      itemTitle: 'Notion Databases',
      fieldName: 'NOTION_AUDIT_TRAIL_DB_ID'
    },
    OPENAI_API_KEY: {
      vaultId: 'ChittyChain',
      itemTitle: 'AI Services',
      fieldName: 'OPENAI_API_KEY'
    },
    ANTHROPIC_API_KEY: {
      vaultId: 'ChittyChain',
      itemTitle: 'AI Services',
      fieldName: 'ANTHROPIC_API_KEY'
    },
    BLOCKCHAIN_PRIVATE_KEY: {
      vaultId: 'ChittyChain',
      itemTitle: 'Blockchain',
      fieldName: 'BLOCKCHAIN_PRIVATE_KEY'
    },
    IPFS_API_KEY: {
      vaultId: 'ChittyChain',
      itemTitle: 'IPFS',
      fieldName: 'IPFS_API_KEY'
    }
  } as const;
}

// Singleton instance
const secretsManager = new SecretsManager();

export { secretsManager, SecretsManager };
export type { SecretConfig };