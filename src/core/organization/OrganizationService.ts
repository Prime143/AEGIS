import { OrganizationContext } from '../types';

export const DEFAULT_ORGANIZATION_CONTEXT: OrganizationContext = {
  organizationName: 'Nexus Defense Systems',
  dataClassifications: [
    {
      id: 'cls-public',
      name: 'PUBLIC',
      level: 'PUBLIC',
      description: 'Information approved for unrestricted public release with zero corporate liability.'
    },
    {
      id: 'cls-internal',
      name: 'INTERNAL',
      level: 'INTERNAL',
      description: 'General internal company communications, documentation, and operational data.'
    },
    {
      id: 'cls-confidential',
      name: 'CONFIDENTIAL',
      level: 'CONFIDENTIAL',
      description: 'Proprietary intellectual property, client data, and internal architectural designs requiring masking.'
    },
    {
      id: 'cls-restricted',
      name: 'RESTRICTED',
      level: 'RESTRICTED',
      description: 'Critical authentication secrets, private keys, financial ledgers, and trade secrets strictly prohibited from external transmission.'
    }
  ],
  glossary: [
    {
      id: 'gls-1',
      term: 'Project Chimera',
      category: 'CONFIDENTIAL_TECHNICAL',
      classification: 'CONFIDENTIAL',
      placeholder: '[REDACTED_PROJECT_CODENAME]'
    },
    {
      id: 'gls-2',
      term: 'Orion-Core',
      category: 'CONFIDENTIAL_TECHNICAL',
      classification: 'CONFIDENTIAL',
      placeholder: '[REDACTED_PROJECT_CODENAME]'
    },
    {
      id: 'gls-3',
      term: 'AegisMasterKey',
      category: 'CREDENTIAL',
      classification: 'RESTRICTED',
      placeholder: '[REDACTED_RESTRICTED_KEY]'
    },
    {
      id: 'gls-4',
      term: 'Executive Board Compensation Q4',
      category: 'CONFIDENTIAL_FINANCIAL',
      classification: 'RESTRICTED',
      placeholder: '[REDACTED_FINANCIAL_RECORD]'
    }
  ],
  sensitiveEntities: [
    {
      id: 'ent-1',
      name: 'Internal Dev Cluster FQDN',
      pattern: 'dev-cluster\\.internal\\.nexus-corp\\.com',
      type: 'regex',
      action: 'BLOCK',
      placeholder: '[REDACTED_INTERNAL_HOST]',
      explanation: 'Prevents leakage of internal development cluster infrastructure endpoints.'
    },
    {
      id: 'ent-2',
      name: 'Project Orion Codename',
      pattern: 'Orion-Core',
      type: 'keyword',
      action: 'MASK',
      placeholder: '[REDACTED_PROJECT_CODENAME]',
      explanation: 'Protects references to confidential Project Orion R&D.'
    },
    {
      id: 'ent-3',
      name: 'Financial Ledger Spreadsheet References',
      pattern: 'Q[1-4]-financial-report\\.xlsx',
      type: 'regex',
      action: 'BLOCK',
      placeholder: '[REDACTED_FINANCIAL_ASSET]',
      explanation: 'Blocks queries referencing corporate financial ledger spreadsheets.'
    }
  ],
  allowedProviders: ['provider-safe-mock', 'provider-gemini'],
  retentionDays: 90
};

export const NOVA_SYSTEMS_CONTEXT: OrganizationContext = {
  organizationName: 'NOVA Systems',
  dataClassifications: [
    {
      id: 'nova-cls-public',
      name: 'PUBLIC',
      level: 'PUBLIC',
      description: 'Information approved for unrestricted public release with zero corporate liability.'
    },
    {
      id: 'nova-cls-internal',
      name: 'INTERNAL',
      level: 'INTERNAL',
      description: 'General internal company communications, documentation, and operational data.'
    },
    {
      id: 'nova-cls-confidential',
      name: 'CONFIDENTIAL',
      level: 'CONFIDENTIAL',
      description: 'Proprietary intellectual property, client telemetry, and internal architectural designs requiring masking.'
    },
    {
      id: 'nova-cls-restricted',
      name: 'RESTRICTED',
      level: 'RESTRICTED',
      description: 'Critical authentication secrets, private keys, financial ledgers, and trade secrets strictly prohibited from external transmission.'
    }
  ],
  glossary: [
    {
      id: 'nova-gls-1',
      term: 'Project Aurora',
      category: 'CONFIDENTIAL_TECHNICAL',
      classification: 'CONFIDENTIAL',
      placeholder: '[REDACTED_PROJECT_CODENAME]'
    },
    {
      id: 'nova-gls-2',
      term: 'Valkyrie-X',
      category: 'CONFIDENTIAL_TECHNICAL',
      classification: 'RESTRICTED',
      placeholder: '[REDACTED_SWARM_CODENAME]'
    },
    {
      id: 'nova-gls-3',
      term: 'Zephyr-OS',
      category: 'CONFIDENTIAL_TECHNICAL',
      classification: 'CONFIDENTIAL',
      placeholder: '[REDACTED_RTOS_NAME]'
    },
    {
      id: 'nova-gls-4',
      term: 'Project Apex',
      category: 'CONFIDENTIAL_FINANCIAL',
      classification: 'RESTRICTED',
      placeholder: '[REDACTED_MA_CODENAME]'
    }
  ],
  sensitiveEntities: [
    {
      id: 'nova-ent-1',
      name: 'NOVA Core Telemetry FQDN',
      pattern: 'core-telemetry\\.internal\\.novasystems\\.net',
      type: 'regex',
      action: 'BLOCK',
      placeholder: '[REDACTED_NOVA_INTERNAL_HOST]',
      explanation: 'Prevents leakage of NOVA Systems internal telemetry endpoints.'
    },
    {
      id: 'nova-ent-2',
      name: 'NOVA Vault Infrastructure',
      pattern: 'vault-01\\.mgmt\\.novasystems\\.net',
      type: 'regex',
      action: 'BLOCK',
      placeholder: '[REDACTED_NOVA_VAULT_HOST]',
      explanation: 'Prevents leakage of NOVA Systems management vault infrastructure.'
    },
    {
      id: 'nova-ent-3',
      name: 'NOVA Engineering Jira Issue Keys',
      pattern: 'NOVA-(?:ENG|SEC|AERO|SWARM)-\\d{4,}',
      type: 'regex',
      action: 'MASK',
      placeholder: '[REDACTED_NOVA_TICKET]',
      explanation: 'Masks proprietary issue tracker references.'
    }
  ],
  allowedProviders: ['provider-safe-mock', 'provider-gemini'],
  retentionDays: 90
};


export class OrganizationService {
  private context: OrganizationContext;

  constructor(initialContext?: OrganizationContext) {
    this.context = initialContext ? { ...initialContext } : { ...DEFAULT_ORGANIZATION_CONTEXT };
  }

  getContext(): OrganizationContext {
    return { ...this.context };
  }

  updateContext(updates: Partial<OrganizationContext>): OrganizationContext {
    this.context = {
      ...this.context,
      ...updates
    };
    return this.getContext();
  }

  addGlossaryTerm(term: OrganizationContext['glossary'][0]): void {
    this.context.glossary.push(term);
  }

  deleteGlossaryTerm(id: string): boolean {
    const idx = this.context.glossary.findIndex(g => g.id === id);
    if (idx === -1) return false;
    this.context.glossary.splice(idx, 1);
    return true;
  }

  addSensitiveEntity(entity: OrganizationContext['sensitiveEntities'][0]): void {
    this.context.sensitiveEntities.push(entity);
  }

  deleteSensitiveEntity(id: string): boolean {
    const idx = this.context.sensitiveEntities.findIndex(e => e.id === id);
    if (idx === -1) return false;
    this.context.sensitiveEntities.splice(idx, 1);
    return true;
  }
}
