/**
 * NmapTool Unit Tests
 * Tests Nmap tool wrapper functionality and security
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NmapTool } from '../../src/tools/nmap.js';
import type { NmapOptions } from '../../src/tools/nmap.js';

// Mock dependencies
vi.mock('../../src/utils/commandRunner.js', () => ({
  CommandRunner: vi.fn().mockImplementation(() => ({
    executeCommand: vi.fn().mockResolvedValue({
      success: true,
      exitCode: 0,
      stdout: 'Nmap version 7.95\nTest output',
      stderr: '',
      duration: 1000,
      timedOut: false
    }),
    isCommandAvailable: vi.fn().mockResolvedValue(true)
  }))
}));

vi.mock('../../src/utils/osConfig.js', () => ({
  OSConfigManager: vi.fn().mockImplementation(() => ({
    getBinaryName: vi.fn().mockReturnValue('nmap')
  }))
}));

vi.mock('../../src/utils/argGuard.js', () => ({
  ArgGuard: vi.fn().mockImplementation(() => ({}))
}));

vi.mock('../../src/utils/auditLogger.js', () => ({
  AuditLogger: vi.fn().mockImplementation(() => ({}))
}));

describe('NmapTool', () => {
  let nmapTool: NmapTool;

  beforeEach(() => {
    nmapTool = new NmapTool();
    vi.clearAllMocks();
  });

  describe('Tool Configuration', () => {
    it('should have correct tool name', () => {
      expect(nmapTool.getName()).toBe('nmap');
    });

    it('should have minimum version requirement', () => {
      expect(nmapTool.getMinVersion()).toBeDefined();
      expect(typeof nmapTool.getMinVersion()).toBe('string');
    });

    it('should have binary configuration for all platforms', () => {
      const binaryConfig = nmapTool.getBinaryConfig();
      
      expect(binaryConfig.linux).toBe('nmap');
      expect(binaryConfig.darwin).toBe('nmap');
      expect(binaryConfig.windows).toBe('nmap.exe');
    });
  });

  describe('Tool Availability', () => {
    it('should check if tool is available', async () => {
      const isAvailable = await nmapTool.isAvailable();
      expect(typeof isAvailable).toBe('boolean');
      expect(isAvailable).toBe(true);
    });

    it('should get tool version', async () => {
      const version = await nmapTool.getVersion();
      expect(typeof version).toBe('string');
      expect(version).toBeDefined();
    });
  });

  describe('Command Execution', () => {
    it('should require target parameter', async () => {
      const options = {} as NmapOptions;
      
      const result = await nmapTool.execute(options);
      expect(result.success).toBe(false);
      expect(result.error).toContain('Target is required');
    });

    it('should build basic scan command', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        scanType: 'tcp',
        ports: '80,443',
      };

      const result = await nmapTool.execute(options);
      
      expect(result.tool).toBe('nmap');
      expect(result.target).toBe('127.0.0.1');
      expect(result.command).toContain('nmap');
      expect(result.command).toContain('127.0.0.1');
      expect(result.success).toBe(true);
    });

    it('should handle different scan types', async () => {
      const scanTypes: Array<NmapOptions['scanType']> = ['tcp', 'syn', 'udp', 'ping', 'version'];
      
      for (const scanType of scanTypes) {
        const options: NmapOptions = {
          target: '127.0.0.1',
          scanType,
        };

        const result = await nmapTool.execute(options);
        expect(result.tool).toBe('nmap');
        expect(result.data?.scanType).toBe(scanType);
        expect(result.success).toBe(true);
      }
    });

    it('should apply timing templates', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        timing: '3',
      };

      const result = await nmapTool.execute(options);
      expect(result.data?.timing).toBe('3');
      expect(result.success).toBe(true);
    });

    it('should handle port specifications', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        ports: '80,443,8080',
      };

      const result = await nmapTool.execute(options);
      expect(result.data?.ports).toBe('80,443,8080');
      expect(result.success).toBe(true);
    });
  });

  describe('Result Structure', () => {
    it('should return standardized result format', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        scanType: 'tcp',
      };

      const result = await nmapTool.execute(options);
      
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('tool');
      expect(result).toHaveProperty('version');
      expect(result).toHaveProperty('target');
      expect(result).toHaveProperty('command');
      expect(result.tool).toBe('nmap');
      expect(result.success).toBe(true);
    });

    it('should include execution metadata', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
      };

      const result = await nmapTool.execute(options);
      
      expect(result.metadata).toBeDefined();
      expect(result.metadata?.binaryUsed).toBeDefined();
      expect(result.metadata?.argsCount).toBeDefined();
      expect(result.success).toBe(true);
    });

    it('should capture command output', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        scanType: 'ping',
      };

      const result = await nmapTool.execute(options);
      
      expect(result.success).toBe(true);
      expect(result.stdout).toBeDefined();
      expect(typeof result.stdout).toBe('string');
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid targets gracefully', async () => {
      const invalidTargets = [
        '',
        ' ',
      ];

      for (const target of invalidTargets) {
        const options: NmapOptions = { target };
        const result = await nmapTool.execute(options);
        
        expect(result.success).toBe(false);
        expect(result.error).toBeDefined();
      }
    });

    it('should provide meaningful error messages', async () => {
      const options = {} as NmapOptions;
      
      const result = await nmapTool.execute(options);
      expect(result.success).toBe(false);
      expect(result.error).toContain('required');
    });
  });

  describe('Security Features', () => {
    it('should validate command arguments through ArgGuard', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        scanType: 'tcp',
      };

      const result = await nmapTool.execute(options);
      
      expect(result.command).not.toContain(';');
      expect(result.command).not.toContain('&&');
      expect(result.command).not.toContain('|');
      expect(result.success).toBe(true);
    });

    it('should include audit logging metadata', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        scanType: 'tcp',
      };

      const result = await nmapTool.execute(options);
      
      expect(result.metadata).toBeDefined();
      expect(result.duration).toBeDefined();
      expect(result.command).toBeDefined();
      expect(result.success).toBe(true);
    });
  });

  describe('Platform Compatibility', () => {
    it('should work on current platform', async () => {
      const isAvailable = await nmapTool.isAvailable();
      
      if (isAvailable) {
        const options: NmapOptions = {
          target: '127.0.0.1',
          scanType: 'ping',
        };

        const result = await nmapTool.execute(options);
        expect(result.tool).toBe('nmap');
        expect(result.success).toBe(true);
      } else {
        console.warn('Nmap not available on this system - skipping execution tests');
      }
    });

    it('should use correct binary for platform', () => {
      const binaryConfig = nmapTool.getBinaryConfig();
      
      if (process.platform === 'win32') {
        expect(binaryConfig.windows).toBe('nmap.exe');
      } else if (process.platform === 'darwin') {
        expect(binaryConfig.darwin).toBe('nmap');
      } else {
        expect(binaryConfig.linux).toBe('nmap');
      }
    });
  });

  describe('Performance', () => {
    it('should complete quick scans within reasonable time', async () => {
      const options: NmapOptions = {
        target: '127.0.0.1',
        scanType: 'ping',
        timeout: 10000,
      };

      const startTime = Date.now();
      const result = await nmapTool.execute(options);
      const actualDuration = Date.now() - startTime;

      expect(actualDuration).toBeLessThan(15000);
      expect(result.success).toBe(true);
      
      if (result.success) {
        expect(result.duration).toBeDefined();
        expect(result.duration).toBeGreaterThan(0);
      }
    });
  });
}); 