/**
 * Masscan Tool Wrapper - High-speed port scanning
 */

import { BaseTool, ToolExecutionOptions, ToolResult } from './base.js';
import { CommandRunner } from '../utils/commandRunner.js';
import { OSConfigManager } from '../utils/osConfig.js';
import { ArgGuard } from '../utils/argGuard.js';
import { AuditLogger } from '../utils/auditLogger.js';

export interface MasscanOptions extends ToolExecutionOptions {
  target: string;
  ports?: string;
  rate?: number;
}

export class MasscanTool extends BaseTool {
  private commandRunner: CommandRunner;
  private osConfig: OSConfigManager;

  constructor() {
    super('masscan', '1.3.2', {
      linux: 'masscan',
      darwin: 'masscan',
      windows: 'masscan.exe'
    });
    
    const argGuard = new ArgGuard();
    const auditLogger = new AuditLogger();
    this.commandRunner = new CommandRunner(argGuard, auditLogger);
    this.osConfig = new OSConfigManager();
  }

  public async execute(options: MasscanOptions): Promise<ToolResult> {
    try {
      if (!options.target) {
        throw new Error('Target is required for Masscan');
      }

      const args = this.buildMasscanArgs(options);
      const binaryName = this.osConfig.getBinaryName('masscan');

      const startTime = Date.now();
      const result = await this.commandRunner.executeCommand(binaryName, args);
      const duration = Date.now() - startTime;

      return {
        success: result.success,
        tool: 'masscan',
        version: await this.getVersion(),
        target: options.target,
        duration,
        command: `${binaryName} ${args.join(' ')}`,
        stdout: result.stdout,
        data: {
          ports: options.ports || '1-65535',
          rate: options.rate || 10000
        }
      };

    } catch (error) {
      return {
        success: false,
        tool: 'masscan',
        version: await this.getVersion(),
        target: options.target,
        duration: 0,
        command: 'masscan (failed to execute)',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private buildMasscanArgs(options: MasscanOptions): string[] {
    const args: string[] = [];
    
    args.push(options.target);
    args.push('-p', options.ports || '1-65535');
    args.push('--rate', (options.rate || 10000).toString());
    
    return args;
  }

  public async getVersion(): Promise<string> {
    try {
      const binaryName = this.osConfig.getBinaryName('masscan');
      const result = await this.commandRunner.executeCommand(binaryName, ['--version']);
      return result.success ? '1.3.2' : 'unknown';
    } catch {
      return 'unknown';
    }
  }

  public async isAvailable(): Promise<boolean> {
    try {
      const binaryName = this.osConfig.getBinaryName('masscan');
      const result = await this.commandRunner.executeCommand(binaryName, ['--version']);
      return result.success;
    } catch {
      return false;
    }
  }
} 