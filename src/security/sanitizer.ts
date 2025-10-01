import { platform } from 'os';
import { basename, normalize } from 'path';

export type SecurityType = 'filepath';

export interface SanitizationResult {
  value: string;
  safe: boolean;
  warnings: string[];
}

const shellQuote = (value: string): string => {
  if (!value) return "''";

  const currentPlatform = platform();

  if (currentPlatform === 'win32') {
    return `"${value.replace(/"/g, '""')}"`;
  } else {
    const escaped = value.replace(/'/g, "'\\''");
    return `'${escaped}'`;
  }
};

/**
 * Sanitize file paths for path traversal attacks.
 */
export const sanitizeFilePath = (value: any, allowedPaths: string[] = []): SanitizationResult => {
  if (value === null || value === undefined) {
    return { value: '', safe: true, warnings: [] };
  }

  const warnings: string[] = [];
  let sanitized = String(value).replace(/[;&|`$(){}[\]]/g, '');

  try {
    sanitized = normalize(sanitized);
  } catch (error) {
    warnings.push('Invalid path format detected');
    sanitized = basename(sanitized);
  }

  if (sanitized.includes('..')) {
    warnings.push('Path traversal attempt detected and blocked');
    sanitized = basename(sanitized);
  }

  if (allowedPaths.length > 0) {
    const isAllowed = allowedPaths.some(allowedPath => {
      const normalizedAllowed = normalize(allowedPath);
      const normalizedSanitized = normalize(sanitized);
      return normalizedSanitized.startsWith(normalizedAllowed) ||
             normalizedSanitized === normalizedAllowed;
    });

    if (!isAllowed) {
      warnings.push(`Path not in allowed directories: ${allowedPaths.join(', ')}`);
      sanitized = basename(sanitized);
    }
  }

  sanitized = shellQuote(sanitized);

  return {
    value: sanitized,
    safe: warnings.length === 0,
    warnings
  };
};

/**
 * Quote all characters to make them literal (QUOTE mode).
 */
export const shellEscapeQuote = (value: any): string => {
  if (value === null || value === undefined) {
    return "''";
  }

  return shellQuote(String(value));
};

/**
 * Remove dangerous characters then quote (REMOVE mode).
 */
export const shellEscapeRemove = (value: any): string => {
  if (value === null || value === undefined) {
    return "''";
  }

  const sanitized = String(value)
    .replace(/[;&|`$(){}[\]]/g, '')
    .replace(/\n/g, ' ')
    .replace(/\r/g, '');

  return shellQuote(sanitized);
};

/**
 * Get escape function based on mode.
 */
export const getEscapeFunction = (escapeMode: 'quote' | 'remove' = 'quote'): (value: any) => string => {
  return escapeMode === 'remove' ? shellEscapeRemove : shellEscapeQuote;
};

/**
 * Pre-process context to sanitize filepath properties.
 */
export const preprocessContext = (
  context: Record<string, any>,
  inputSchema: any,
  allowedPaths: string[] = []
): {
  sanitizedContext: Record<string, any>;
  warnings: string[];
} => {
  const sanitizedContext: Record<string, any> = { ...context };
  const warnings: string[] = [];

  if (inputSchema?.properties) {
    for (const [key, propertySchema] of Object.entries(inputSchema.properties as Record<string, any>)) {
      if (context[key] === undefined) continue;

      if (propertySchema.security === 'filepath') {
        const result = sanitizeFilePath(context[key], allowedPaths);
        sanitizedContext[key] = result.value;

        if (result.warnings.length > 0) {
          warnings.push(`${key}: ${result.warnings.join(', ')}`);
        }
        if (!result.safe) {
          warnings.push(`${key}: File path was sanitized for safety`);
        }
      }
    }
  }

  return { sanitizedContext, warnings };
};
