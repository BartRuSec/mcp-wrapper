import { describe, it, expect, beforeEach } from 'vitest';
import { SecuritySanitizer } from './sanitizer.js';

describe('SecuritySanitizer', () => {
  let sanitizer: SecuritySanitizer;

  beforeEach(() => {
    sanitizer = new SecuritySanitizer(['ls', 'echo', 'cat'], false);
  });

  describe('sanitizeFilePath', () => {
    it('should block path traversal attempts', () => {
      const result = sanitizer.sanitize('../../../etc/passwd', 'filepath');
      expect(result.safe).toBe(false);
      expect(result.warnings).toContain('Path traversal attempt detected and blocked');
      expect(result.value).not.toContain('..');
    });

    it('should block absolute paths', () => {
      const result = sanitizer.sanitize('/etc/passwd', 'filepath');
      expect(result.safe).toBe(false);
      expect(result.warnings).toContain('Absolute path detected, using basename only');
    });

    it('should allow safe relative paths', () => {
      const result = sanitizer.sanitize('documents/file.txt', 'filepath');
      expect(result.safe).toBe(true);
      expect(result.warnings).toHaveLength(0);
    });

    it('should remove dangerous characters', () => {
      const result = sanitizer.sanitize('file;rm -rf /', 'filepath');
      expect(result.value).not.toContain(';');
      // Should be quoted to prevent shell injection
      expect(result.value).toContain("'");
    });
  });

  describe('sanitizeCommand', () => {
    it('should allow whitelisted commands', () => {
      const result = sanitizer.sanitize('ls -la', 'command');
      expect(result.safe).toBe(true);
      expect(result.value).toContain('ls');
    });

    it('should block non-whitelisted commands', () => {
      const result = sanitizer.sanitize('rm -rf /', 'command');
      expect(result.safe).toBe(false);
      expect(result.warnings).toContain("Command 'rm' not in allowed list");
    });

    it('should block dangerous commands', () => {
      const allowAllSanitizer = new SecuritySanitizer([], false);
      const result = allowAllSanitizer.sanitize('sudo rm -rf /', 'command');
      expect(result.safe).toBe(false);
      expect(result.warnings).toContain("Potentially dangerous command 'sudo' detected");
    });

    it('should sanitize command arguments', () => {
      const result = sanitizer.sanitize('echo "hello; rm -rf /"', 'command');
      expect(result.value).not.toContain(';');
    });
  });

  describe('sanitizeText', () => {
    it('should remove dangerous shell characters', () => {
      const result = sanitizer.sanitize('hello; rm -rf /', 'text');
      expect(result.value).not.toContain(';');
      expect(result.safe).toBe(false);
      expect(result.warnings).toContain('Dangerous characters removed from text input');
      // Should be quoted to prevent shell injection
      expect(result.value).toContain("'");
    });

    it('should handle command substitution attempts', () => {
      const result = sanitizer.sanitize('hello $(rm -rf /)', 'text');
      expect(result.value).not.toContain('$(');
      // Should be quoted for safety
      expect(result.value).toContain("'");
    });

    it('should allow safe text', () => {
      const result = sanitizer.sanitize('Hello World 123', 'text');
      expect(result.safe).toBe(true);
      expect(result.warnings).toHaveLength(0);
    });
  });


  describe('sanitizeSafe', () => {
    it('should apply basic sanitization', () => {
      const result = sanitizer.sanitize('hello; world', 'safe');
      expect(result.value).not.toContain(';');
      expect(result.safe).toBe(false);
      expect(result.warnings).toContain('Input sanitized for shell safety');
    });

    it('should handle newlines and carriage returns', () => {
      const result = sanitizer.sanitize('hello\nworld\r', 'safe');
      expect(result.value).not.toContain('\n');
      expect(result.value).not.toContain('\r');
    });
  });

  describe('sanitizeUnsafe', () => {
    it('should block unsafe when not allowed', () => {
      const result = sanitizer.sanitize('rm -rf /', 'unsafe');
      expect(result.safe).toBe(false);
      expect(result.warnings).toContain('Unsafe sanitization not allowed, falling back to safe mode');
    });

    it('should allow unsafe when permitted', () => {
      const unsafeSanitizer = new SecuritySanitizer([], true);
      const result = unsafeSanitizer.sanitize('rm -rf /', 'unsafe');
      expect(result.safe).toBe(false); // Unsafe is always marked as not safe
      expect(result.value).toBe('rm -rf /');
      expect(result.warnings).toContain('Using unsafe mode - no sanitization applied');
    });
  });

  describe('Platform-specific quoting', () => {
    it('should quote spaces correctly on Unix', () => {
      // Mock platform to unix for this test
      const originalPlatform = process.platform;
      Object.defineProperty(process, 'platform', { value: 'linux' });

      const result = sanitizer.sanitize('hello world', 'safe');
      expect(result.value).toContain("'hello world'");

      // Restore original platform
      Object.defineProperty(process, 'platform', { value: originalPlatform });
    });
  });

  describe('Edge cases', () => {
    it('should handle null and undefined values', () => {
      expect(sanitizer.sanitize(null, 'safe').value).toBe('');
      expect(sanitizer.sanitize(undefined, 'safe').value).toBe('');
    });

    it('should handle empty strings', () => {
      const result = sanitizer.sanitize('', 'safe');
      expect(result.value).toBe("''");
      expect(result.safe).toBe(true);
    });

    it('should handle boolean values', () => {
      const result = sanitizer.sanitize(true, 'safe');
      expect(result.value).toContain('true');
    });
  });
});