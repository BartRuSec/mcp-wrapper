import { SecurityType } from './sanitizer.js';

export type SecurityLevel = 'strict' | 'moderate' | 'permissive';

export interface SecurityPolicy {
  /** Overall security level */
  level: SecurityLevel;

  /** Default security type when none specified */
  defaultSecurityType: SecurityType;

  /** Whether to allow 'unsafe' security type */
  allowUnsafe: boolean;

  /** Commands allowed in 'command' security type */
  allowedCommands: string[];

  /** Patterns that are always blocked */
  blockedPatterns: string[];

  /** Allowed base paths for 'filepath' security type */
  allowedPaths: string[];

  /** Maximum command execution timeout (seconds) */
  maxExecutionTimeout: number;

  /** Maximum input length */
  maxInputLength: number;

  /** Whether to log security events */
  auditLogging: boolean;

  /** Whether to fail on security warnings */
  failOnWarnings: boolean;
}

export const SECURITY_POLICIES: Record<SecurityLevel, SecurityPolicy> = {
  strict: {
    level: 'strict',
    defaultSecurityType: 'safe',
    allowUnsafe: false,
    allowedCommands: [
      'echo', 'cat', 'ls', 'pwd', 'whoami', 'date', 'bc',
      'grep', 'awk', 'sed', 'sort', 'uniq', 'wc', 'head', 'tail'
    ],
    blockedPatterns: [
      '\\|', '&&', '||', ';', '`', '$(', '${',
      'rm ', 'del ', 'format', 'mkfs', 'dd ',
      'chmod', 'chown', 'sudo', 'su ', 'passwd'
    ],
    allowedPaths: ['./'],
    maxExecutionTimeout: 10,
    maxInputLength: 1000,
    auditLogging: true,
    failOnWarnings: true
  },

  moderate: {
    level: 'moderate',
    defaultSecurityType: 'safe',
    allowUnsafe: false,
    allowedCommands: [
      'echo', 'cat', 'ls', 'pwd', 'whoami', 'date', 'bc',
      'grep', 'awk', 'sed', 'sort', 'uniq', 'wc', 'head', 'tail',
      'find', 'which', 'file', 'stat', 'df', 'du', 'ps',
      'git', 'curl', 'wget', 'ping', 'nslookup'
    ],
    blockedPatterns: [
      'rm -rf', 'del /s', 'format', 'mkfs', 'dd if=',
      'sudo rm', 'su -', 'passwd'
    ],
    allowedPaths: ['./', '/tmp/', '/home/', '/Users/'],
    maxExecutionTimeout: 30,
    maxInputLength: 5000,
    auditLogging: true,
    failOnWarnings: false
  },

  permissive: {
    level: 'permissive',
    defaultSecurityType: 'safe',
    allowUnsafe: true,
    allowedCommands: [], // Empty means all commands allowed
    blockedPatterns: [
      'rm -rf /', 'del /s /q C:\\', 'format C:',
      'mkfs', 'dd if=/dev/zero'
    ],
    allowedPaths: [], // Empty means all paths allowed
    maxExecutionTimeout: 60,
    maxInputLength: 10000,
    auditLogging: false,
    failOnWarnings: false
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

  updatePolicy(updates: Partial<SecurityPolicy>): void {
    this.policy = { ...this.policy, ...updates };
  }

  isCommandAllowed(command: string): boolean {
    // If no commands specified, all are allowed
    if (this.policy.allowedCommands.length === 0) {
      return !this.isPatternBlocked(command);
    }

    return this.policy.allowedCommands.includes(command) && !this.isPatternBlocked(command);
  }

  isPatternBlocked(input: string): boolean {
    return this.policy.blockedPatterns.some(pattern => {
      try {
        const regex = new RegExp(pattern, 'i');
        return regex.test(input);
      } catch {
        // If pattern is not a valid regex, use simple string matching
        return input.toLowerCase().includes(pattern.toLowerCase());
      }
    });
  }

  isPathAllowed(path: string): boolean {
    // If no paths specified, all are allowed
    if (this.policy.allowedPaths.length === 0) {
      return true;
    }

    return this.policy.allowedPaths.some(allowedPath => {
      return path.startsWith(allowedPath);
    });
  }

  validateInputLength(input: string): boolean {
    return input.length <= this.policy.maxInputLength;
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

  isUnsafeAllowed(): boolean {
    return this.policy.allowUnsafe;
  }

  getDefaultSecurityType(): SecurityType {
    return this.policy.defaultSecurityType;
  }

  validateSecurityType(securityType: SecurityType): boolean {
    if (securityType === 'unsafe' && !this.policy.allowUnsafe) {
      return false;
    }
    return true;
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

    if (config?.defaultSecurityType) {
      customPolicy.defaultSecurityType = config.defaultSecurityType;
    }
    if (config?.allowUnsafe !== undefined) {
      customPolicy.allowUnsafe = config.allowUnsafe;
    }
    if (config?.allowedCommands) {
      customPolicy.allowedCommands = config.allowedCommands;
    }
    if (config?.blockedPatterns) {
      customPolicy.blockedPatterns = config.blockedPatterns;
    }
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