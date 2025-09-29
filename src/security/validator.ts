import { SecurityType, SecuritySanitizer, SanitizationResult } from './sanitizer.js';
import { TemplateContext } from '../types/config.js';

export interface ValidationRule {
  securityType?: SecurityType;
}

export interface ValidationResult {
  valid: boolean;
  sanitizedValue: string;
  errors: string[];
  warnings: string[];
}

export interface PropertyValidation {
  [propertyName: string]: ValidationRule;
}

export class InputValidator {
  private sanitizer: SecuritySanitizer;

  constructor(sanitizer: SecuritySanitizer) {
    this.sanitizer = sanitizer;
  }

  validateInput(
    input: TemplateContext,
    validation: PropertyValidation
  ): { [key: string]: ValidationResult } {
    const results: { [key: string]: ValidationResult } = {};

    // Validate each property (MCP already validated required properties and schema constraints)
    for (const [propName, value] of Object.entries(input)) {
      const rule = validation[propName];
      if (!rule) {
        // No validation rule, apply default safe sanitization
        const sanitizationResult = this.sanitizer.sanitize(value, 'safe');
        results[propName] = {
          valid: sanitizationResult.safe,
          sanitizedValue: sanitizationResult.value,
          errors: [],
          warnings: sanitizationResult.warnings
        };
        continue;
      }

      results[propName] = this.validateProperty(value, rule);
    }

    return results;
  }

  private validateProperty(value: any, rule: ValidationRule): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    // Convert to string for security sanitization
    const stringValue = value === null || value === undefined ? '' : String(value);

    // Security sanitization (only security validation, MCP handles schema validation)
    const securityType = rule.securityType || 'safe';
    const sanitizationResult: SanitizationResult = this.sanitizer.sanitize(stringValue, securityType);

    // Combine warnings
    warnings.push(...sanitizationResult.warnings);

    // If sanitization failed with no sanitized value, it's an error
    // But if we have warnings only (sanitized value exists), treat as warning
    if (!sanitizationResult.safe && securityType !== 'unsafe') {
      if (sanitizationResult.value === '' && sanitizationResult.warnings.length === 0) {
        // Complete failure with no output
        errors.push('Input failed security validation');
      } else if (sanitizationResult.warnings.length === 0) {
        // Failed but no warnings means a real security issue
        errors.push('Input failed security validation');
      }
      // If we have warnings, let the policy manager decide if warnings are errors
    }

    return {
      valid: errors.length === 0,
      sanitizedValue: sanitizationResult.value,
      errors,
      warnings
    };
  }

  extractValidationRules(inputSchema: any): { validation: PropertyValidation; required: string[] } {
    const validation: PropertyValidation = {};

    if (inputSchema.properties) {
      for (const [propName, propSchema] of Object.entries(inputSchema.properties)) {
        const schema = propSchema as any;
        const rule: ValidationRule = {};

        // Extract only security type (MCP handles all other validation)
        if (schema.security) {
          rule.securityType = schema.security as SecurityType;
        } else {
          // Default security type based on property type
          rule.securityType = this.getDefaultSecurityType(schema.type, propName);
        }

        validation[propName] = rule;
      }
    }

    return { validation, required: [] }; // MCP handles required validation
  }

  private getDefaultSecurityType(_type: string, propertyName: string): SecurityType {
    // Auto-detect security type based on property name and type
    const lowerName = propertyName.toLowerCase();

    if (lowerName.includes('path') || lowerName.includes('file') || lowerName.includes('dir')) {
      return 'filepath';
    }

    if (lowerName.includes('command') || lowerName.includes('cmd')) {
      return 'command';
    }

    // For numbers, we don't need special security handling - regular validation is enough
    // Default to safe for all cases including numbers
    return 'safe';
  }
}