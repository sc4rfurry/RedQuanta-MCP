import { describe, it, expect, beforeEach, vi } from 'vitest';
import { BaseTool } from '../../src/tools/base.js';

// Test implementation of BaseTool
class TestTool extends BaseTool {
  constructor() {
    super('test-tool', '1.0.0', {
      linux: 'test-tool',
      darwin: 'test-tool',
      windows: 'test-tool.exe'
    });
  }

  async execute(options: any): Promise<any> {
    return {
      success: true,
      tool: this.getName(),
      version: this.getMinVersion(),
      data: options
    };
  }
}

describe('BaseTool', () => {
  let testTool: TestTool;

  beforeEach(() => {
    testTool = new TestTool();
  });

  describe('Tool Configuration', () => {
    it('should initialize with correct name', () => {
      expect(testTool.getName()).toBe('test-tool');
    });

    it('should initialize with correct minimum version', () => {
      expect(testTool.getMinVersion()).toBe('1.0.0');
    });

    it('should initialize with binary configuration', () => {
      const binaryConfig = testTool.getBinaryConfig();
      
      expect(binaryConfig).toHaveProperty('linux');
      expect(binaryConfig).toHaveProperty('darwin'); 
      expect(binaryConfig).toHaveProperty('windows');
      expect(binaryConfig.linux).toBe('test-tool');
      expect(binaryConfig.darwin).toBe('test-tool');
      expect(binaryConfig.windows).toBe('test-tool.exe');
    });
  });

  describe('Abstract Implementation', () => {
    it('should implement execute method', async () => {
      const options = { target: 'test-target' };
      const result = await testTool.execute(options);
      
      expect(result).toBeDefined();
      expect(result.success).toBe(true);
      expect(result.tool).toBe('test-tool');
      expect(result.data).toEqual(options);
    });

    it('should return tool metadata in execution results', async () => {
      const result = await testTool.execute({});
      
      expect(result.tool).toBe('test-tool');
      expect(result.version).toBe('1.0.0');
    });
  });

  describe('Platform Support', () => {
    it('should provide platform-specific binary names', () => {
      const config = testTool.getBinaryConfig();
      
      // Test all supported platforms
      expect(config.linux).toBeDefined();
      expect(config.darwin).toBeDefined();
      expect(config.windows).toBeDefined();
      
      // Verify Windows has .exe extension
      expect(config.windows).toMatch(/\.exe$/);
    });
  });

  describe('Tool Identity', () => {
    it('should maintain consistent tool name', () => {
      const name1 = testTool.getName();
      const name2 = testTool.getName();
      
      expect(name1).toBe(name2);
      expect(name1).toBe('test-tool');
    });

    it('should maintain consistent version', () => {
      const version1 = testTool.getMinVersion();
      const version2 = testTool.getMinVersion();
      
      expect(version1).toBe(version2);
      expect(version1).toBe('1.0.0');
    });
  });

  describe('Inheritance Support', () => {
    it('should support method overriding', () => {
      class ExtendedTool extends BaseTool {
        constructor() {
          super('extended-tool', '2.0.0', {
            linux: 'extended',
            darwin: 'extended',
            windows: 'extended.exe'
          });
        }

        async execute(options: any): Promise<any> {
          return {
            success: true,
            tool: 'extended',
            enhanced: true
          };
        }

        getName(): string {
          return 'extended-tool-custom';
        }
      }

      const extendedTool = new ExtendedTool();
      expect(extendedTool.getName()).toBe('extended-tool-custom');
      expect(extendedTool.getMinVersion()).toBe('2.0.0');
    });

    it('should support property inheritance', () => {
      class CustomTool extends BaseTool {
        public customProperty: string = 'custom-value';

        constructor() {
          super('custom', '1.5.0', {
            linux: 'custom',
            darwin: 'custom',
            windows: 'custom.exe'
          });
        }

        async execute(options: any): Promise<any> {
          return { success: true, custom: this.customProperty };
        }
      }

      const customTool = new CustomTool();
      expect(customTool.customProperty).toBe('custom-value');
      expect(customTool.getName()).toBe('custom');
    });
  });

  describe('Error Handling', () => {
    it('should handle execution errors gracefully', async () => {
      class ErrorTool extends BaseTool {
        constructor() {
          super('error-tool', '1.0.0', {
            linux: 'error-tool',
            darwin: 'error-tool',
            windows: 'error-tool.exe'
          });
        }

        async execute(options: any): Promise<any> {
          throw new Error('Execution failed');
        }
      }

      const errorTool = new ErrorTool();
      
      await expect(errorTool.execute({})).rejects.toThrow('Execution failed');
    });
  });

  describe('Configuration Validation', () => {
    it('should accept valid binary configurations', () => {
      const validConfigs = [
        { linux: 'tool', darwin: 'tool', windows: 'tool.exe' },
        { linux: 'my-tool', darwin: 'my-tool', windows: 'my-tool.exe' },
        { linux: '/usr/bin/tool', darwin: '/usr/local/bin/tool', windows: 'C:\\tools\\tool.exe' }
      ];

      validConfigs.forEach((config, index) => {
        const tool = new class extends BaseTool {
          constructor() {
            super(`test-${index}`, '1.0.0', config);
          }
          
          async execute(options: any): Promise<any> {
            return { success: true };
          }
        }();

        expect(tool.getBinaryConfig()).toEqual(config);
      });
    });
  });

  describe('Type Safety', () => {
    it('should maintain type safety for tool results', async () => {
      interface TestOptions {
        target: string;
        port?: number;
      }

      interface TestResult {
        success: boolean;
        tool: string;
        data: TestOptions;
      }

      class TypedTool extends BaseTool {
        constructor() {
          super('typed-tool', '1.0.0', {
            linux: 'typed',
            darwin: 'typed',
            windows: 'typed.exe'
          });
        }

        async execute(options: TestOptions): Promise<TestResult> {
          return {
            success: true,
            tool: this.getName(),
            data: options
          };
        }
      }

      const typedTool = new TypedTool();
      const result = await typedTool.execute({ target: 'example.com', port: 80 });

      expect(result.success).toBe(true);
      expect(result.tool).toBe('typed-tool');
      expect(result.data.target).toBe('example.com');
      expect(result.data.port).toBe(80);
    });
  });
}); 