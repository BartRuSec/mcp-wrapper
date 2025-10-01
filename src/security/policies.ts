import { homedir, tmpdir } from 'os';

export type SecurityLevel = 'strict' | 'moderate' | 'permissive';

export interface SecurityPolicy {
  level: SecurityLevel;
  allowedPaths: string[];
  maxExecutionTimeout: number;
  maxInputLength: number;
  auditLogging: boolean;
  failOnWarnings: boolean;
  defaultEscapeMode: 'quote' | 'remove';
}

const getModerateAllowedPaths = (): string[] => {
  return ['./', tmpdir(), homedir()];
};

export const SECURITY_POLICIES: Record<SecurityLevel, SecurityPolicy> = {
  strict: {
    level: 'strict',
    allowedPaths: ['./'],
    maxExecutionTimeout: 10,
    maxInputLength: 1000,
    auditLogging: true,
    failOnWarnings: true,
    defaultEscapeMode: 'remove'
  },

  moderate: {
    level: 'moderate',
    allowedPaths: getModerateAllowedPaths(),
    maxExecutionTimeout: 30,
    maxInputLength: 5000,
    auditLogging: true,
    failOnWarnings: false,
    defaultEscapeMode: 'quote'
  },

  permissive: {
    level: 'permissive',
    allowedPaths: [],
    maxExecutionTimeout: 60,
    maxInputLength: 10000,
    auditLogging: false,
    failOnWarnings: false,
    defaultEscapeMode: 'quote'
  }
};

export class SecurityPolicyManager {
  private policy: SecurityPolicy;

  /**
   * Creates a new SecurityPolicyManager with the specified security level.
   *
   * @param level Security level to apply. Defaults to 'moderate' which provides
   *              a good balance of security and usability for most use cases.
   * @param customPolicy Optional custom policy overrides
   */
  constructor(level: SecurityLevel = 'moderate', customPolicy?: Partial<SecurityPolicy>) {
    this.policy = { ...SECURITY_POLICIES[level] };

    if (customPolicy) {
      this.policy = { ...this.policy, ...customPolicy };
    }
  }

  getPolicy(): SecurityPolicy {
    return { ...this.policy };
  }

  getMaxExecutionTimeout(): number {
    return this.policy.maxExecutionTimeout * 1000; // Convert to milliseconds
  }

  shouldFailOnWarnings(): boolean {
    return this.policy.failOnWarnings;
  }

  isAuditLoggingEnabled(): boolean {
    return this.policy.auditLogging;
  }

  getDefaultEscapeMode(): 'quote' | 'remove' {
    return this.policy.defaultEscapeMode;
  }


  /**
   * Creates a SecurityPolicyManager from a configuration object.
   *
   * @param config Security configuration object. If null/undefined or missing
   *               level property, defaults to 'moderate' security level.
   * @returns SecurityPolicyManager instance with specified or default settings
   */
  static fromConfig(config: any): SecurityPolicyManager {
    const level = config?.level || 'moderate'; // Default to moderate security
    const customPolicy: Partial<SecurityPolicy> = {};

    if (config?.allowedPaths) {
      customPolicy.allowedPaths = config.allowedPaths;
    }
    if (config?.maxExecutionTimeout) {
      customPolicy.maxExecutionTimeout = config.maxExecutionTimeout;
    }
    if (config?.maxInputLength) {
      customPolicy.maxInputLength = config.maxInputLength;
    }
    if (config?.auditLogging !== undefined) {
      customPolicy.auditLogging = config.auditLogging;
    }
    if (config?.failOnWarnings !== undefined) {
      customPolicy.failOnWarnings = config.failOnWarnings;
    }

    return new SecurityPolicyManager(level, customPolicy);
  }
}