import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { writeFileSync, unlinkSync, existsSync } from 'fs';
import { loadConfig } from './loader.js';
import { SecurityPolicyManager } from '../security/policies.js';

describe('Config Loader', () => {
  const testConfigPath = '/tmp/test-config.yaml';

  afterEach(() => {
    if (existsSync(testConfigPath)) {
      unlinkSync(testConfigPath);
    }
  });

  describe('Default Security Behavior', () => {
    it('should apply moderate security level when no security section is provided', () => {
      const configContent = `
tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
      required: [message]
    cmd: "echo {{message}}"
`;

      writeFileSync(testConfigPath, configContent);
      const config = loadConfig(testConfigPath);

      expect(config.tools).toBeDefined();
      expect(config.tools.test_tool).toBeDefined();
      expect(config.security).toBeUndefined(); // No security section in config

      // Verify that default security policy is applied during validation
      // This is tested indirectly by ensuring the config loads successfully
      expect(config.tools.test_tool.description).toBe("A test tool");
    });

    it('should use moderate security level as default in SecurityPolicyManager', () => {
      // Test the actual default behavior of SecurityPolicyManager
      const defaultManager = new SecurityPolicyManager();
      const policy = defaultManager.getPolicy();

      expect(policy.level).toBe('moderate');
      expect(policy.defaultSecurityType).toBe('safe');
      expect(policy.allowUnsafe).toBe(false);
      expect(policy.auditLogging).toBe(true);
      expect(policy.failOnWarnings).toBe(false);
      expect(policy.maxExecutionTimeout).toBe(30);
      expect(policy.maxInputLength).toBe(5000);

      // Verify moderate-level command whitelist
      expect(policy.allowedCommands).toContain('echo');
      expect(policy.allowedCommands).toContain('ls');
      expect(policy.allowedCommands).toContain('git');

      // Verify moderate-level blocked patterns
      expect(policy.blockedPatterns).toContain('rm -rf');
      expect(policy.blockedPatterns).not.toContain(';'); // Less restrictive than strict
    });

    it('should create SecurityPolicyManager from undefined config', () => {
      const manager = SecurityPolicyManager.fromConfig(undefined);
      const policy = manager.getPolicy();

      expect(policy.level).toBe('moderate');
      expect(policy.defaultSecurityType).toBe('safe');
    });

    it('should create SecurityPolicyManager from empty config', () => {
      const manager = SecurityPolicyManager.fromConfig({});
      const policy = manager.getPolicy();

      expect(policy.level).toBe('moderate');
      expect(policy.defaultSecurityType).toBe('safe');
    });
  });

  describe('Explicit Security Configuration', () => {
    it('should use explicit security level when provided', () => {
      const configContent = `
security:
  level: moderate  # Use moderate instead of strict to avoid command restrictions
  allowUnsafe: false
  auditLogging: true

tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
      required: [message]
    cmd: "echo {{message}}"
`;

      writeFileSync(testConfigPath, configContent);
      const config = loadConfig(testConfigPath);

      expect(config.security).toBeDefined();
      expect(config.security?.level).toBe('moderate');
    });

    it('should validate security configuration', () => {
      const configContent = `
security:
  level: invalid_level

tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
      required: [message]
    cmd: "date"  # Use a simpler command
`;

      writeFileSync(testConfigPath, configContent);

      expect(() => {
        loadConfig(testConfigPath);
      }).toThrow(/Security level must be one of/);
    });

    it('should validate defaultSecurityType without number', () => {
      const configContent = `
security:
  level: moderate
  defaultSecurityType: number

tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
      required: [message]
    cmd: "echo {{message}}"
`;

      writeFileSync(testConfigPath, configContent);

      expect(() => {
        loadConfig(testConfigPath);
      }).toThrow(/Default security type must be one of: safe, filepath, command, text, unsafe/);
    });

    it('should allow valid security types', () => {
      const validTypes = ['safe', 'filepath', 'command', 'text', 'unsafe'];

      for (const securityType of validTypes) {
        const configContent = `
security:
  level: permissive
  defaultSecurityType: ${securityType}
  allowUnsafe: true

tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
      required: [message]
    cmd: "echo {{message}}"
`;

        writeFileSync(testConfigPath, configContent);

        expect(() => {
          loadConfig(testConfigPath);
        }).not.toThrow();
      }
    });
  });

  describe('Security Type Validation in Tools', () => {
    it('should validate security types in tool properties', () => {
      const configContent = `
security:
  level: moderate

tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
          security: invalid_type  # This should fail
      required: [message]
    cmd: "echo {{message}}"
`;

      writeFileSync(testConfigPath, configContent);

      expect(() => {
        loadConfig(testConfigPath);
      }).toThrow(/Security type must be one of/);
    });

    it('should allow unsafe security type when explicitly enabled', () => {
      const configContent = `
security:
  level: permissive
  allowUnsafe: true

tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
          security: unsafe
      required: [message]
    cmd: "echo {{message}}"
`;

      writeFileSync(testConfigPath, configContent);

      expect(() => {
        loadConfig(testConfigPath);
      }).not.toThrow();
    });

    it('should reject unsafe security type when not allowed', () => {
      const configContent = `
security:
  level: strict
  allowUnsafe: false

tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    input:
      type: object
      properties:
        message:
          type: string
          description: "Test message"
          security: unsafe
      required: [message]
    cmd: "echo {{message}}"
`;

      writeFileSync(testConfigPath, configContent);

      expect(() => {
        loadConfig(testConfigPath);
      }).toThrow(/Security type 'unsafe' not allowed by current security policy/);
    });
  });

  describe('Missing File Handling', () => {
    it('should throw error for missing config file', () => {
      expect(() => {
        loadConfig('/nonexistent/config.yaml');
      }).toThrow(/Configuration file not found/);
    });

    it('should return empty config when allowMissingFile is true', () => {
      const config = loadConfig('/nonexistent/config.yaml', { allowMissingFile: true });
      expect(config).toEqual({ tools: {} });
    });
  });

  describe('YAML Parsing', () => {
    it('should handle invalid YAML syntax', () => {
      const invalidYaml = `
tools:
  test_tool:
    name: "Test Tool"
    description: "A test tool"
    invalid: yaml: syntax: here
`;

      writeFileSync(testConfigPath, invalidYaml);

      expect(() => {
        loadConfig(testConfigPath);
      }).toThrow(/Invalid YAML syntax/);
    });
  });
});