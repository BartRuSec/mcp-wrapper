import { describe, it, expect, beforeEach } from 'vitest';
import { InputValidator, ValidationRule } from './validator.js';
import { SecuritySanitizer } from './sanitizer.js';

describe('InputValidator', () => {
  let validator: InputValidator;
  let sanitizer: SecuritySanitizer;

  beforeEach(() => {
    sanitizer = new SecuritySanitizer(['ls', 'echo'], false);
    validator = new InputValidator(sanitizer);
  });

  describe('validateInput', () => {
    // Note: Required property validation is now handled by MCP SDK
    it('should apply security sanitization to provided properties', () => {
      const validation = {
        name: { securityType: 'safe' as const }
      };
      const input = { name: 'test value' };
      const results = validator.validateInput(input, validation);

      expect(results.name.valid).toBe(true);
      expect(results.name.sanitizedValue).toContain('test value');
    });

    // Note: String length validation is now handled by MCP SDK via JSON schema
    it('should handle security sanitization regardless of string length', () => {
      const validation = {
        name: { securityType: 'safe' as const }
      };

      // Short string
      let results = validator.validateInput({ name: 'ab' }, validation);
      expect(results.name.valid).toBe(true);
      expect(results.name.sanitizedValue).toContain('ab');

      // Long string
      results = validator.validateInput({ name: 'a'.repeat(100) }, validation);
      expect(results.name.valid).toBe(true);
      expect(results.name.sanitizedValue).toContain('a');
    });

    // Note: Pattern validation is now handled by MCP SDK via JSON schema
    it('should handle security sanitization regardless of pattern matching', () => {
      const validation = {
        email: { securityType: 'safe' as const }
      };

      // Any string (pattern validation handled by MCP)
      let results = validator.validateInput({ email: 'invalid-email' }, validation);
      expect(results.email.valid).toBe(true);
      expect(results.email.sanitizedValue).toContain('invalid-email');

      // Valid email
      results = validator.validateInput({ email: 'test@example.com' }, validation);
      expect(results.email.valid).toBe(true);
      expect(results.email.sanitizedValue).toContain('test@example.com');
    });

    // Note: Enum/allowed values validation is now handled by MCP SDK via JSON schema
    it('should handle security sanitization regardless of enum values', () => {
      const validation = {
        status: { securityType: 'safe' as const }
      };

      // Any value (enum validation handled by MCP)
      let results = validator.validateInput({ status: 'unknown' }, validation);
      expect(results.status.valid).toBe(true);
      expect(results.status.sanitizedValue).toContain('unknown');

      // Valid enum value
      results = validator.validateInput({ status: 'active' }, validation);
      expect(results.status.valid).toBe(true);
      expect(results.status.sanitizedValue).toContain('active');
    });

    it('should apply security sanitization', () => {
      const validation = {
        path: { securityType: 'filepath' as const }
      };

      const results = validator.validateInput({ path: '../../../etc/passwd' }, validation);
      expect(results.path.valid).toBe(true); // With new validation logic, warnings don't make it invalid
      expect(results.path.warnings.length).toBeGreaterThan(0);
      expect(results.path.sanitizedValue).not.toContain('..');
    });

    it('should handle properties without validation rules', () => {
      const validation = {};
      const results = validator.validateInput({ name: 'test; rm -rf /' }, validation);

      // Should apply default safe sanitization
      expect(results.name.sanitizedValue).not.toContain(';');
      expect(results.name.warnings).toContain('Input sanitized for shell safety');
    });
  });

  describe('extractValidationRules', () => {
    // Note: JSON schema validation (minLength, maxLength, pattern, required) is handled by MCP SDK
    it('should extract only security types from schema', () => {
      const schema = {
        type: 'object',
        properties: {
          name: {
            type: 'string',
            minLength: 2,
            maxLength: 50,
            pattern: '^[a-zA-Z]+$'
          },
          age: {
            type: 'number',
            minimum: 0,
            maximum: 120
          }
        },
        required: ['name']
      };

      const { validation } = validator.extractValidationRules(schema);

      // Only security types should be extracted, not JSON schema constraints
      expect(validation.name.securityType).toBe('safe');
      expect(validation.age.securityType).toBe('safe');
      // ValidationRule interface should only contain securityType
      expect(Object.keys(validation.name)).toEqual(['securityType']);
      expect(Object.keys(validation.age)).toEqual(['securityType']);
    });

    it('should auto-detect security types from property names', () => {
      const schema = {
        type: 'object',
        properties: {
          file_path: { type: 'string' },
          directory: { type: 'string' },
          command: { type: 'string' },
          cmd: { type: 'string' },
          count: { type: 'number' },
          message: { type: 'string' }
        }
      };

      const { validation } = validator.extractValidationRules(schema);

      expect(validation.file_path.securityType).toBe('filepath');
      expect(validation.directory.securityType).toBe('filepath');
      expect(validation.command.securityType).toBe('command');
      expect(validation.cmd.securityType).toBe('command');
      expect(validation.count.securityType).toBe('safe');
      expect(validation.message.securityType).toBe('safe');
    });

    it('should respect explicit security annotations', () => {
      const schema = {
        type: 'object',
        properties: {
          path: {
            type: 'string',
            security: 'unsafe'
          },
          text: {
            type: 'string',
            security: 'text'
          }
        }
      };

      const { validation } = validator.extractValidationRules(schema);

      expect(validation.path.securityType).toBe('unsafe');
      expect(validation.text.securityType).toBe('text');
    });

    // Note: Enum validation is now handled by MCP SDK via JSON schema
    it('should extract security types but not enum values', () => {
      const schema = {
        type: 'object',
        properties: {
          level: {
            type: 'string',
            enum: ['debug', 'info', 'warn', 'error']
          }
        }
      };

      const { validation } = validator.extractValidationRules(schema);

      // Should extract security type but not enum values
      expect(validation.level.securityType).toBe('safe');
      // ValidationRule interface should only contain securityType
      expect(Object.keys(validation.level)).toEqual(['securityType']);
    });
  });

  describe('Edge cases', () => {
    it('should handle missing input properties gracefully', () => {
      const validation = {
        optional: { securityType: 'safe' as const }
      };

      const results = validator.validateInput({}, validation);
      // Since the property is missing from input, it won't be in results
      expect(Object.keys(results)).toHaveLength(0);
    });

    // Note: Complex validation is now handled by MCP SDK via JSON schema
    it('should handle security validation for any input', () => {
      const validation = {
        config: { securityType: 'safe' as const }
      };

      // MCP handles required validation, we just do security
      const results = validator.validateInput({ config: '' }, validation);
      expect(results.config.valid).toBe(true);
      expect(results.config.sanitizedValue).toBe("''"); // Empty string gets quoted
    });
  });
});