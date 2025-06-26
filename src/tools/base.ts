/**
 * Base Tool Wrapper Interface
 * 
 * Provides foundation for secure tool execution with:
 * - Standardized result interfaces
 * - Cross-platform binary support
 * - Security validation
 * - Output handling
 */

export interface ToolExecutionOptions {
  timeout?: number;
  workingDir?: string;
  outputDir?: string;
  dangerous?: boolean;
  [key: string]: any;
}

export interface ToolResult {
  success: boolean;
  tool?: string;
  version?: string;
  target?: string;
  duration?: number;
  exitCode?: number;
  command?: string;
  data?: any;
  error?: string;
  stdout?: string;
  stderr?: string;
  outputFiles?: string[];
  parsedData?: any;
  metadata?: Record<string, any>;
}

export interface BinaryConfig {
  linux: string;
  darwin: string;
  windows: string;
}

export abstract class ToolWrapper {
  protected name: string;

  constructor(name: string) {
    this.name = name;
  }

  public getName(): string {
    return this.name;
  }

  public abstract execute(options: Record<string, any>): Promise<ToolResult>;
}

export abstract class BaseTool extends ToolWrapper {
  protected minVersion: string;
  protected binaryConfig: BinaryConfig;

  constructor(name: string, minVersion: string = '1.0.0', binaryConfig: BinaryConfig) {
    super(name);
    this.minVersion = minVersion;
    this.binaryConfig = binaryConfig;
  }

  public getMinVersion(): string {
    return this.minVersion;
  }

  public getBinaryConfig(): BinaryConfig {
    return this.binaryConfig;
  }

  public abstract getVersion(): Promise<string>;
  public abstract isAvailable(): Promise<boolean>;
  public abstract override execute(options: ToolExecutionOptions): Promise<ToolResult>;
} 