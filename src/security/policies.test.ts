import { describe, it, expect, beforeEach } from 'vitest';
import { SecurityPolicyManager, SECURITY_POLICIES } from './policies.js';

describe('SecurityPolicyManager', () => {
  describe('Policy levels', () => {
    it('should have correct default settings for strict policy', () => {
      const policy = SECURITY_POLICIES.strict;
      expect(policy.allowUnsafe).toBe(false);
      expect(policy.auditLogging).toBe(true);
      expect(policy.failOnWarnings).toBe(true);
      expect(policy.maxExecutionTimeout).toBe(10);
      expect(policy.allowedCommands).toContain('echo');
      expect(policy.allowedCommands).not.toContain('rm');
    });

    it('should have correct default settings for moderate policy', () => {
      const policy = SECURITY_POLICIES.moderate;
      expect(policy.allowUnsafe).toBe(false);
      expect(policy.auditLogging).toBe(true);
      expect(policy.failOnWarnings).toBe(false);
      expect(policy.maxExecutionTimeout).toBe(30);
      expect(policy.allowedCommands).toContain('git');
    });

    it('should have correct default settings for permissive policy', () => {
      const policy = SECURITY_POLICIES.permissive;
      expect(policy.allowUnsafe).toBe(true);
      expect(policy.auditLogging).toBe(false);
      expect(policy.failOnWarnings).toBe(false);
      expect(policy.maxExecutionTimeout).toBe(60);
      expect(policy.allowedCommands).toEqual([]); // Empty means all allowed
    });
  });

  describe('SecurityPolicyManager', () => {
    let manager: SecurityPolicyManager;

    beforeEach(() => {
      manager = new SecurityPolicyManager('moderate');
    });

    describe('Command validation', () => {
      it('should allow whitelisted commands', () => {
        expect(manager.isCommandAllowed('echo')).toBe(true);
        expect(manager.isCommandAllowed('git')).toBe(true);
      });

      it('should block non-whitelisted commands in strict mode', () => {
        const strictManager = new SecurityPolicyManager('strict');
        expect(strictManager.isCommandAllowed('git')).toBe(false);
        expect(strictManager.isCommandAllowed('rm')).toBe(false);
      });

      it('should allow all commands when whitelist is empty', () => {
        const permissiveManager = new SecurityPolicyManager('permissive');
        expect(permissiveManager.isCommandAllowed('any-command')).toBe(true);
      });

      it('should block commands matching blocked patterns', () => {
        expect(manager.isCommandAllowed('rm -rf')).toBe(false);
        expect(manager.isCommandAllowed('sudo rm')).toBe(false);
      });
    });

    describe('Pattern blocking', () => {
      it('should block dangerous patterns', () => {
        expect(manager.isPatternBlocked('rm -rf /')).toBe(true);
        expect(manager.isPatternBlocked('format C:')).toBe(true);
        expect(manager.isPatternBlocked('sudo rm')).toBe(true);
      });

      it('should allow safe patterns', () => {
        expect(manager.isPatternBlocked('echo hello')).toBe(false);
        expect(manager.isPatternBlocked('ls -la')).toBe(false);
      });

      it('should handle regex patterns', () => {
        const customManager = new SecurityPolicyManager('moderate', {
          blockedPatterns: ['\\d{4}'] // Block 4-digit numbers
        });
        expect(customManager.isPatternBlocked('pin 1234')).toBe(true);
        expect(customManager.isPatternBlocked('pin 123')).toBe(false);
      });
    });

    describe('Path validation', () => {
      it('should validate allowed paths', () => {
        expect(manager.isPathAllowed('./local-file')).toBe(true);
        expect(manager.isPathAllowed('/tmp/temp-file')).toBe(true);
      });

      it('should block non-allowed paths in strict mode', () => {
        const strictManager = new SecurityPolicyManager('strict');
        expect(strictManager.isPathAllowed('/etc/passwd')).toBe(false);
        expect(strictManager.isPathAllowed('./local-file')).toBe(true);
      });

      it('should allow all paths when list is empty', () => {
        const permissiveManager = new SecurityPolicyManager('permissive');
        expect(permissiveManager.isPathAllowed('/any/path')).toBe(true);
      });
    });

    describe('Input validation', () => {
      it('should validate input length', () => {
        expect(manager.validateInputLength('short')).toBe(true);
        expect(manager.validateInputLength('a'.repeat(6000))).toBe(false);
      });

      it('should respect custom input length limits', () => {
        const customManager = new SecurityPolicyManager('moderate', {
          maxInputLength: 10
        });
        expect(customManager.validateInputLength('short')).toBe(true);
        expect(customManager.validateInputLength('this is too long')).toBe(false);
      });
    });

    describe('Security type validation', () => {
      it('should validate allowed security types', () => {
        expect(manager.validateSecurityType('safe')).toBe(true);
        expect(manager.validateSecurityType('filepath')).toBe(true);
        expect(manager.validateSecurityType('unsafe')).toBe(false);
      });

      it('should allow unsafe in permissive mode', () => {
        const permissiveManager = new SecurityPolicyManager('permissive');
        expect(permissiveManager.validateSecurityType('unsafe')).toBe(true);
      });
    });

    describe('Policy configuration', () => {
      it('should allow policy updates', () => {
        manager.updatePolicy({ maxExecutionTimeout: 45 });
        expect(manager.getMaxExecutionTimeout()).toBe(45000); // converted to ms
      });

      it('should preserve other settings during updates', () => {
        const originalLevel = manager.getPolicy().level;
        manager.updatePolicy({ maxExecutionTimeout: 45 });
        expect(manager.getPolicy().level).toBe(originalLevel);
      });
    });

    describe('fromConfig factory method', () => {
      it('should create manager from config object', () => {
        const config = {
          level: 'strict',
          allowUnsafe: true,
          maxExecutionTimeout: 15
        };

        const manager = SecurityPolicyManager.fromConfig(config);
        expect(manager.getPolicy().level).toBe('strict');
        expect(manager.isUnsafeAllowed()).toBe(true);
        expect(manager.getMaxExecutionTimeout()).toBe(15000);
      });

      it('should handle missing config properties', () => {
        const config = { level: 'moderate' };
        const manager = SecurityPolicyManager.fromConfig(config);
        expect(manager.getPolicy().level).toBe('moderate');
        // Should use defaults for other properties
        expect(manager.getPolicy().allowUnsafe).toBe(false);
      });

      it('should use moderate as default level', () => {
        const manager = SecurityPolicyManager.fromConfig({});
        expect(manager.getPolicy().level).toBe('moderate');
      });
    });

    describe('Utility methods', () => {
      it('should return correct timeout in milliseconds', () => {
        expect(manager.getMaxExecutionTimeout()).toBe(30000);
      });

      it('should return correct default security type', () => {
        expect(manager.getDefaultSecurityType()).toBe('safe');
      });

      it('should return correct audit logging setting', () => {
        expect(manager.isAuditLoggingEnabled()).toBe(true);
      });

      it('should return correct warning handling setting', () => {
        expect(manager.shouldFailOnWarnings()).toBe(false);

        const strictManager = new SecurityPolicyManager('strict');
        expect(strictManager.shouldFailOnWarnings()).toBe(true);
      });
    });
  });
});