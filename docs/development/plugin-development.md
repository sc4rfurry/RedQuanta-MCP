# Plugin Development Guide

Comprehensive guide for developing custom security tools and extensions for RedQuanta MCP.

## Plugin Architecture

### Plugin Structure
```
custom-tool-plugin/
├── package.json
├── src/
│   ├── index.ts
│   ├── tool.ts
│   └── types.ts
├── tests/
│   └── tool.test.ts
├── config/
│   └── tool-config.json
└── README.md
```

### Base Plugin Interface
```typescript
// src/types.ts
export interface PluginManifest {
  name: string;
  version: string;
  description: string;
  author: string;
  license: string;
  tools: ToolDefinition[];
  dependencies?: string[];
  permissions?: Permission[];
}

export interface ToolDefinition {
  name: string;
  description: string;
  inputSchema: JSONSchema;
  outputSchema: JSONSchema;
  execute: (input: any) => Promise<ToolResult>;
  requiresDangerous?: boolean;
  timeout?: number;
}

export interface ToolResult {
  success: boolean;
  tool: string;
  version: string;
  target?: string;
  duration: number;
  exitCode?: number;
  stdout?: string;
  stderr?: string;
  data?: any;
  error?: string;
  metadata?: Record<string, any>;
}
```

## Creating Custom Tools

### Basic Tool Implementation
```typescript
// src/tool.ts
import { BaseTool, ToolExecutionOptions } from '@redquanta/mcp-core';

export interface CustomToolOptions extends ToolExecutionOptions {
  target: string;
  customParam?: string;
  timeout?: number;
}

export class CustomTool extends BaseTool {
  constructor() {
    super('custom-tool', '1.0.0', {
      linux: 'custom-tool',
      darwin: 'custom-tool',
      windows: 'custom-tool.exe'
    });
  }

  async execute(options: CustomToolOptions): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      // Validate input
      this.validateInput(options);
      
      // Build command arguments
      const args = this.buildArgs(options);
      
      // Execute tool
      const result = await this.executeCommand(args, {
        timeout: options.timeout || 30000,
        cwd: process.cwd()
      });
      
      // Process output
      const processedResult = this.processOutput(result.stdout, result.stderr);
      
      return {
        success: result.exitCode === 0,
        tool: this.getName(),
        version: this.getMinVersion(),
        target: options.target,
        duration: Date.now() - startTime,
        exitCode: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        data: processedResult,
        metadata: {
          binaryUsed: this.getBinaryName(),
          arguments: args
        }
      };
      
    } catch (error) {
      return {
        success: false,
        tool: this.getName(),
        version: this.getMinVersion(),
        target: options.target,
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private validateInput(options: CustomToolOptions): void {
    if (!options.target) {
      throw new Error('Target is required');
    }
    
    // Add custom validation logic
    if (options.customParam && options.customParam.length > 100) {
      throw new Error('Custom parameter too long');
    }
  }

  private buildArgs(options: CustomToolOptions): string[] {
    const args: string[] = [];
    
    // Add tool-specific arguments
    args.push('--target', options.target);
    
    if (options.customParam) {
      args.push('--custom', options.customParam);
    }
    
    return args;
  }

  private processOutput(stdout: string, stderr: string): any {
    // Process and parse tool output
    try {
      if (stdout.includes('JSON:')) {
        const jsonStart = stdout.indexOf('JSON:') + 5;
        return JSON.parse(stdout.substring(jsonStart));
      }
      
      return {
        rawOutput: stdout,
        errorOutput: stderr
      };
    } catch {
      return { rawOutput: stdout };
    }
  }

  async getVersion(): Promise<string> {
    try {
      const result = await this.executeCommand(['--version']);
      const versionMatch = result.stdout.match(/version (\d+\.\d+\.\d+)/);
      return versionMatch?.[1] || 'unknown';
    } catch {
      return 'unknown';
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      await this.executeCommand(['--help']);
      return true;
    } catch {
      return false;
    }
  }
}
```

### Plugin Entry Point
```typescript
// src/index.ts
import { PluginManifest, RedQuantaPlugin } from '@redquanta/mcp-core';
import { CustomTool } from './tool.js';

export class CustomToolPlugin implements RedQuantaPlugin {
  private customTool: CustomTool;
  
  constructor() {
    this.customTool = new CustomTool();
  }
  
  getManifest(): PluginManifest {
    return {
      name: 'custom-tool-plugin',
      version: '1.0.0',
      description: 'Custom security tool integration',
      author: 'Security Team',
      license: 'MIT',
      tools: [
        {
          name: 'custom_tool_scan',
          description: 'Custom security scanning tool',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target to scan'
              },
              customParam: {
                type: 'string',
                description: 'Custom parameter',
                default: 'default-value'
              }
            },
            required: ['target']
          },
          outputSchema: {
            type: 'object',
            properties: {
              success: { type: 'boolean' },
              data: { type: 'object' },
              metadata: { type: 'object' }
            }
          },
          execute: this.customTool.execute.bind(this.customTool),
          timeout: 60000
        }
      ],
      permissions: [
        'network.scan',
        'filesystem.read'
      ]
    };
  }
  
  async initialize(): Promise<void> {
    // Plugin initialization logic
    console.log('Initializing custom tool plugin...');
    
    // Check tool availability
    const available = await this.customTool.isAvailable();
    if (!available) {
      throw new Error('Custom tool not available on this system');
    }
  }
  
  async cleanup(): Promise<void> {
    // Plugin cleanup logic
    console.log('Cleaning up custom tool plugin...');
  }
}

// Export plugin instance
export default new CustomToolPlugin();
```

## Advanced Plugin Features

### Configuration Management
```typescript
// src/config.ts
export interface PluginConfig {
  enabled: boolean;
  logLevel: string;
  customSettings: {
    apiKey?: string;
    endpoint?: string;
    timeout: number;
  };
  toolPaths: Record<string, string>;
}

export class ConfigManager {
  private config: PluginConfig;
  
  constructor(configPath: string) {
    this.config = this.loadConfig(configPath);
  }
  
  private loadConfig(path: string): PluginConfig {
    try {
      return JSON.parse(fs.readFileSync(path, 'utf-8'));
    } catch (error) {
      return this.getDefaultConfig();
    }
  }
  
  private getDefaultConfig(): PluginConfig {
    return {
      enabled: true,
      logLevel: 'info',
      customSettings: {
        timeout: 30000
      },
      toolPaths: {}
    };
  }
  
  get<T>(key: string): T {
    return this.config[key] as T;
  }
  
  set(key: string, value: any): void {
    this.config[key] = value;
  }
}
```

### State Management
```typescript
// src/state.ts
export class PluginState {
  private state: Map<string, any> = new Map();
  private persistPath?: string;
  
  constructor(persistPath?: string) {
    this.persistPath = persistPath;
    this.load();
  }
  
  set(key: string, value: any): void {
    this.state.set(key, value);
    this.persist();
  }
  
  get<T>(key: string): T | undefined {
    return this.state.get(key) as T;
  }
  
  has(key: string): boolean {
    return this.state.has(key);
  }
  
  delete(key: string): boolean {
    const result = this.state.delete(key);
    this.persist();
    return result;
  }
  
  clear(): void {
    this.state.clear();
    this.persist();
  }
  
  private load(): void {
    if (!this.persistPath) return;
    
    try {
      const data = fs.readFileSync(this.persistPath, 'utf-8');
      const parsed = JSON.parse(data);
      this.state = new Map(Object.entries(parsed));
    } catch {
      // File doesn't exist or is invalid, start with empty state
    }
  }
  
  private persist(): void {
    if (!this.persistPath) return;
    
    try {
      const data = Object.fromEntries(this.state);
      fs.writeFileSync(this.persistPath, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error('Failed to persist state:', error);
    }
  }
}
```

### Event System
```typescript
// src/events.ts
export interface PluginEvent {
  type: string;
  timestamp: Date;
  data: any;
  source: string;
}

export class EventManager {
  private listeners: Map<string, Set<(event: PluginEvent) => void>> = new Map();
  
  on(eventType: string, listener: (event: PluginEvent) => void): void {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType)!.add(listener);
  }
  
  off(eventType: string, listener: (event: PluginEvent) => void): void {
    const listeners = this.listeners.get(eventType);
    if (listeners) {
      listeners.delete(listener);
    }
  }
  
  emit(eventType: string, data: any, source: string = 'unknown'): void {
    const event: PluginEvent = {
      type: eventType,
      timestamp: new Date(),
      data,
      source
    };
    
    const listeners = this.listeners.get(eventType);
    if (listeners) {
      listeners.forEach(listener => {
        try {
          listener(event);
        } catch (error) {
          console.error(`Error in event listener for ${eventType}:`, error);
        }
      });
    }
  }
}
```

## Web-Based Tools Integration

### HTTP API Tool
```typescript
// src/web-tool.ts
import axios from 'axios';

export interface WebToolOptions {
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers?: Record<string, string>;
  data?: any;
  timeout?: number;
}

export class WebBasedTool extends BaseTool {
  private httpClient: axios.AxiosInstance;
  
  constructor() {
    super('web-tool', '1.0.0', {
      linux: 'web-api',
      darwin: 'web-api',
      windows: 'web-api'
    });
    
    this.httpClient = axios.create({
      timeout: 30000,
      headers: {
        'User-Agent': 'RedQuanta-MCP/1.0.0'
      }
    });
  }
  
  async execute(options: WebToolOptions): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      const response = await this.httpClient.request({
        url: options.endpoint,
        method: options.method,
        headers: options.headers,
        data: options.data,
        timeout: options.timeout || 30000
      });
      
      return {
        success: response.status >= 200 && response.status < 300,
        tool: this.getName(),
        version: this.getMinVersion(),
        duration: Date.now() - startTime,
        data: response.data,
        metadata: {
          statusCode: response.status,
          headers: response.headers,
          responseSize: JSON.stringify(response.data).length
        }
      };
      
    } catch (error) {
      if (axios.isAxiosError(error)) {
        return {
          success: false,
          tool: this.getName(),
          version: this.getMinVersion(),
          duration: Date.now() - startTime,
          error: error.message,
          metadata: {
            statusCode: error.response?.status,
            responseData: error.response?.data
          }
        };
      }
      
      throw error;
    }
  }
  
  async getVersion(): Promise<string> {
    return '1.0.0';
  }
  
  async isAvailable(): Promise<boolean> {
    return true; // Web tools are always "available"
  }
}
```

### Custom Protocol Handler
```typescript
// src/protocol-handler.ts
export interface ProtocolHandler {
  name: string;
  schemes: string[];
  handle(url: URL, options: any): Promise<ToolResult>;
}

export class CustomProtocolHandler implements ProtocolHandler {
  name = 'custom-protocol';
  schemes = ['custom://'];
  
  async handle(url: URL, options: any): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      // Parse custom protocol URL
      const { hostname, pathname, searchParams } = url;
      
      // Implement custom protocol logic
      const result = await this.processCustomRequest(hostname, pathname, searchParams);
      
      return {
        success: true,
        tool: 'custom-protocol-handler',
        version: '1.0.0',
        duration: Date.now() - startTime,
        data: result
      };
      
    } catch (error) {
      return {
        success: false,
        tool: 'custom-protocol-handler',
        version: '1.0.0',
        duration: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }
  
  private async processCustomRequest(
    hostname: string, 
    pathname: string, 
    params: URLSearchParams
  ): Promise<any> {
    // Implement custom protocol processing logic
    return {
      hostname,
      pathname,
      parameters: Object.fromEntries(params)
    };
  }
}
```

## Plugin Testing

### Unit Testing Framework
```typescript
// tests/tool.test.ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CustomTool } from '../src/tool.js';

describe('CustomTool', () => {
  let customTool: CustomTool;
  
  beforeEach(() => {
    customTool = new CustomTool();
  });
  
  describe('Input Validation', () => {
    it('should require target parameter', async () => {
      const options = {} as any;
      
      const result = await customTool.execute(options);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Target is required');
    });
    
    it('should validate custom parameter length', async () => {
      const options = {
        target: 'example.com',
        customParam: 'a'.repeat(101) // Too long
      };
      
      const result = await customTool.execute(options);
      
      expect(result.success).toBe(false);
      expect(result.error).toContain('Custom parameter too long');
    });
  });
  
  describe('Command Execution', () => {
    it('should execute tool successfully', async () => {
      // Mock command execution
      vi.spyOn(customTool as any, 'executeCommand').mockResolvedValue({
        exitCode: 0,
        stdout: 'JSON:{"result": "success"}',
        stderr: ''
      });
      
      const options = {
        target: 'example.com'
      };
      
      const result = await customTool.execute(options);
      
      expect(result.success).toBe(true);
      expect(result.data).toEqual({ result: 'success' });
    });
    
    it('should handle execution failures', async () => {
      vi.spyOn(customTool as any, 'executeCommand').mockRejectedValue(
        new Error('Command not found')
      );
      
      const options = {
        target: 'example.com'
      };
      
      const result = await customTool.execute(options);
      
      expect(result.success).toBe(false);
      expect(result.error).toBe('Command not found');
    });
  });
  
  describe('Tool Availability', () => {
    it('should check if tool is available', async () => {
      vi.spyOn(customTool as any, 'executeCommand').mockResolvedValue({
        exitCode: 0,
        stdout: 'Help text',
        stderr: ''
      });
      
      const available = await customTool.isAvailable();
      
      expect(available).toBe(true);
    });
    
    it('should handle unavailable tools', async () => {
      vi.spyOn(customTool as any, 'executeCommand').mockRejectedValue(
        new Error('ENOENT')
      );
      
      const available = await customTool.isAvailable();
      
      expect(available).toBe(false);
    });
  });
});
```

### Integration Testing
```typescript
// tests/integration.test.ts
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { TestHarness } from '@redquanta/mcp-testing';
import { CustomToolPlugin } from '../src/index.js';

describe('CustomToolPlugin Integration', () => {
  let testHarness: TestHarness;
  let plugin: CustomToolPlugin;
  
  beforeAll(async () => {
    testHarness = new TestHarness();
    plugin = new CustomToolPlugin();
    
    await testHarness.initialize();
    await testHarness.loadPlugin(plugin);
  });
  
  afterAll(async () => {
    await testHarness.cleanup();
  });
  
  it('should register plugin successfully', async () => {
    const registeredPlugins = await testHarness.getRegisteredPlugins();
    
    expect(registeredPlugins).toContain('custom-tool-plugin');
  });
  
  it('should expose tool endpoints', async () => {
    const availableTools = await testHarness.getAvailableTools();
    
    expect(availableTools).toContain('custom_tool_scan');
  });
  
  it('should execute tool via API', async () => {
    const result = await testHarness.executeTool('custom_tool_scan', {
      target: 'example.com'
    });
    
    expect(result).toHaveProperty('success');
    expect(result).toHaveProperty('tool', 'custom-tool');
  });
});
```

## Plugin Distribution

### Package Configuration
```json
{
  "name": "@redquanta/custom-tool-plugin",
  "version": "1.0.0",
  "description": "Custom security tool integration for RedQuanta MCP",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "files": [
    "dist/",
    "config/",
    "README.md"
  ],
  "scripts": {
    "build": "tsc",
    "test": "vitest",
    "lint": "eslint src/",
    "prepublishOnly": "npm run build && npm test"
  },
  "keywords": [
    "redquanta",
    "security",
    "plugin",
    "mcp"
  ],
  "author": "Security Team",
  "license": "MIT",
  "peerDependencies": {
    "@redquanta/mcp-core": "^0.3.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "typescript": "^5.0.0",
    "vitest": "^1.0.0"
  }
}
```

### Plugin Registry
```typescript
// src/registry.ts
export interface PluginRegistry {
  plugins: Map<string, RedQuantaPlugin>;
  register(plugin: RedQuantaPlugin): Promise<void>;
  unregister(name: string): Promise<void>;
  get(name: string): RedQuantaPlugin | undefined;
  list(): string[];
}

export class DefaultPluginRegistry implements PluginRegistry {
  plugins = new Map<string, RedQuantaPlugin>();
  
  async register(plugin: RedQuantaPlugin): Promise<void> {
    const manifest = plugin.getManifest();
    
    // Validate plugin
    this.validatePlugin(manifest);
    
    // Initialize plugin
    await plugin.initialize();
    
    // Register plugin
    this.plugins.set(manifest.name, plugin);
    
    console.log(`Plugin ${manifest.name} registered successfully`);
  }
  
  async unregister(name: string): Promise<void> {
    const plugin = this.plugins.get(name);
    if (plugin) {
      await plugin.cleanup();
      this.plugins.delete(name);
      console.log(`Plugin ${name} unregistered`);
    }
  }
  
  get(name: string): RedQuantaPlugin | undefined {
    return this.plugins.get(name);
  }
  
  list(): string[] {
    return Array.from(this.plugins.keys());
  }
  
  private validatePlugin(manifest: PluginManifest): void {
    if (!manifest.name || !manifest.version) {
      throw new Error('Plugin must have name and version');
    }
    
    if (this.plugins.has(manifest.name)) {
      throw new Error(`Plugin ${manifest.name} already registered`);
    }
  }
}
```

## Best Practices

### Security Considerations
- **Input Validation**: Always validate and sanitize inputs
- **Privilege Minimization**: Request only necessary permissions
- **Error Handling**: Implement comprehensive error handling
- **Resource Management**: Clean up resources properly
- **Audit Logging**: Log all significant operations

### Performance Optimization
- **Async Operations**: Use async/await for I/O operations
- **Resource Pooling**: Reuse connections and resources
- **Caching**: Cache expensive operations
- **Timeouts**: Implement reasonable timeouts
- **Memory Management**: Avoid memory leaks

### Documentation Standards
- **README**: Comprehensive installation and usage guide
- **API Documentation**: Document all public interfaces
- **Examples**: Provide working examples
- **Changelog**: Maintain version history
- **Contributing**: Guidelines for contributors

## Next Steps

- [Performance Optimization](performance.md)
- [Contributing Guidelines](contributing.md)
- [Architecture Overview](../development/architecture.md) 