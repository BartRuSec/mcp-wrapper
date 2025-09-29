import { platform } from 'os';
import { basename, resolve, normalize } from 'path';

export type SecurityType = 'safe' | 'filepath' | 'command' | 'text' | 'unsafe';

export interface SanitizationResult {
  value: string;
  safe: boolean;
  warnings: string[];
}

export class SecuritySanitizer {
  private readonly currentPlatform: string;
  private readonly allowedCommands: Set<string>;
  private readonly allowUnsafe: boolean;

  constructor(allowedCommands: string[] = [], allowUnsafe = false) {
    this.currentPlatform = platform();
    this.allowedCommands = new Set(allowedCommands);
    this.allowUnsafe = allowUnsafe;
  }

  sanitize(value: any, securityType: SecurityType = 'safe'): SanitizationResult {
    if (value === null || value === undefined) {
      return { value: '', safe: true, warnings: [] };
    }

    const stringValue = String(value);

    switch (securityType) {
      case 'unsafe':
        return this.sanitizeUnsafe(stringValue);
      case 'filepath':
        return this.sanitizeFilePath(stringValue);
      case 'command':
        return this.sanitizeCommand(stringValue);
      case 'text':
        return this.sanitizeText(stringValue);
      case 'safe':
      default:
        return this.sanitizeSafe(stringValue);
    }
  }

  private sanitizeUnsafe(value: string): SanitizationResult {
    if (!this.allowUnsafe) {
      return {
        value: this.sanitizeSafe(value).value,
        safe: false,
        warnings: ['Unsafe sanitization not allowed, falling back to safe mode']
      };
    }

    return {
      value,
      safe: false,
      warnings: ['Using unsafe mode - no sanitization applied']
    };
  }

  private sanitizeFilePath(value: string): SanitizationResult {
    const warnings: string[] = [];

    // Remove dangerous characters
    let sanitized = value.replace(/[;&|`$(){}[\]]/g, '');

    // Normalize path to prevent traversal
    try {
      sanitized = normalize(sanitized);
    } catch (error) {
      warnings.push('Invalid path format detected');
      sanitized = basename(sanitized);
    }

    // Check for path traversal attempts
    if (sanitized.includes('..')) {
      warnings.push('Path traversal attempt detected and blocked');
      sanitized = basename(sanitized);
    }

    // Block absolute paths for security
    if (sanitized.startsWith('/') || /^[A-Za-z]:/.test(sanitized)) {
      warnings.push('Absolute path detected, using basename only');
      sanitized = basename(sanitized);
    }

    // Quote for shell safety
    sanitized = this.shellQuote(sanitized);

    return {
      value: sanitized,
      safe: warnings.length === 0,
      warnings
    };
  }

  private sanitizeCommand(value: string): SanitizationResult {
    const warnings: string[] = [];
    const commandParts = value.trim().split(/\s+/);
    const command = commandParts[0];

    if (!command) {
      return {
        value: '',
        safe: false,
        warnings: ['Empty command not allowed']
      };
    }

    // Check if command is in whitelist
    if (this.allowedCommands.size > 0 && !this.allowedCommands.has(command)) {
      return {
        value: '',
        safe: false,
        warnings: [`Command '${command}' not in allowed list`]
      };
    }

    // Block dangerous commands
    const dangerousCommands = [
      'rm', 'del', 'rmdir', 'format', 'mkfs',
      'dd', 'fdisk', 'chmod', 'chown', 'sudo',
      'su', 'passwd', 'eval', 'exec', 'source'
    ];

    if (dangerousCommands.includes(command.toLowerCase())) {
      warnings.push(`Potentially dangerous command '${command}' detected`);
      return {
        value: '',
        safe: false,
        warnings
      };
    }

    // Sanitize arguments
    const sanitizedArgs = commandParts.slice(1).map(arg => {
      return this.shellQuote(arg.replace(/[;&|`$(){}[\]]/g, ''));
    });

    const sanitized = [command, ...sanitizedArgs].join(' ');

    return {
      value: sanitized,
      safe: warnings.length === 0,
      warnings
    };
  }

  private sanitizeText(value: string): SanitizationResult {
    const warnings: string[] = [];

    // Remove/escape dangerous shell characters
    let sanitized = value
      .replace(/[;&|`]/g, '') // Remove dangerous operators
      .replace(/\$\(/g, '') // Remove command substitution
      .replace(/\${/g, '') // Remove parameter expansion
      .replace(/`/g, ''); // Remove backticks

    // Quote for shell safety
    sanitized = this.shellQuote(sanitized);

    const wasSanitized = sanitized !== this.shellQuote(value);
    if (wasSanitized) {
      warnings.push('Dangerous characters removed from text input');
    }

    return {
      value: sanitized,
      safe: !wasSanitized,
      warnings
    };
  }


  private sanitizeSafe(value: string): SanitizationResult {
    const warnings: string[] = [];

    // Remove most dangerous characters
    let sanitized = value
      .replace(/[;&|`$(){}[\]]/g, '') // Remove shell operators
      .replace(/\n/g, ' ') // Replace newlines with spaces
      .replace(/\r/g, ''); // Remove carriage returns

    // Quote for shell safety
    sanitized = this.shellQuote(sanitized);

    const wasSanitized = sanitized !== this.shellQuote(value);
    if (wasSanitized) {
      warnings.push('Input sanitized for shell safety');
    }

    return {
      value: sanitized,
      safe: !wasSanitized,
      warnings
    };
  }

  private shellQuote(value: string): string {
    if (!value) return "''";

    if (this.currentPlatform === 'win32') {
      // Windows cmd/PowerShell quoting
      if (value.includes(' ') || value.includes('"') || value.includes("'")) {
        return `"${value.replace(/"/g, '""')}"`;
      }
      return value;
    } else {
      // Unix shell quoting
      if (!/^[a-zA-Z0-9_.-]+$/.test(value)) {
        return `'${value.replace(/'/g, "'\"'\"'")}'`;
      }
      return value;
    }
  }
}