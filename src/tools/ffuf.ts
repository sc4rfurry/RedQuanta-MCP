/**
 * FFUF Tool Wrapper - Web fuzzing and directory discovery
 */

import { BaseTool, ToolExecutionOptions, ToolResult } from './base.js';
import { CommandRunner } from '../utils/commandRunner.js';
import { OSConfigManager } from '../utils/osConfig.js';
import { ArgGuard } from '../utils/argGuard.js';
import { AuditLogger } from '../utils/auditLogger.js';

export interface FfufOptions extends ToolExecutionOptions {
  url: string;
  wordlist?: string;
  filterCodes?: string[];
  threads?: number;
}

export class FfufTool extends BaseTool {
  private commandRunner: CommandRunner;
  private osConfig: OSConfigManager;

  constructor() {
    super('ffuf', '2.0', {
      linux: 'ffuf',
      darwin: 'ffuf',
      windows: 'ffuf.exe'
    });
    
    const argGuard = new ArgGuard();
    const auditLogger = new AuditLogger();
    this.commandRunner = new CommandRunner(argGuard, auditLogger);
    this.osConfig = new OSConfigManager();
  }

  public async execute(options: FfufOptions): Promise<ToolResult> {
    try {
      if (!options.url) {
        throw new Error('URL is required for FFUF');
      }

      const args = this.buildFfufArgs(options);
      const binaryName = this.osConfig.getBinaryName('ffuf');

      const startTime = Date.now();
      const result = await this.commandRunner.executeCommand(binaryName, args);
      const duration = Date.now() - startTime;

      return {
        success: result.success,
        tool: 'ffuf',
        version: await this.getVersion(),
        target: options.url,
        duration,
        command: `${binaryName} ${args.join(' ')}`,
        stdout: result.stdout,
        data: {
          url: options.url,
          wordlist: options.wordlist || 'default',
          threads: options.threads || 200
        }
      };

    } catch (error) {
      return {
        success: false,
        tool: 'ffuf',
        version: await this.getVersion(),
        target: options.url,
        duration: 0,
        command: 'ffuf (failed to execute)',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  private buildFfufArgs(options: FfufOptions): string[] {
    const args: string[] = [];
    
    args.push('-u', options.url);
    
    if (options.wordlist) {
      args.push('-w', options.wordlist);
    }
    
    if (options.filterCodes && options.filterCodes.length > 0) {
      args.push('-fc', options.filterCodes.join(','));
    } else {
      args.push('-fc', '403,404');
    }
    
    args.push('-t', (options.threads || 200).toString());
    
    return args;
  }

  public async getVersion(): Promise<string> {
    try {
      const binaryName = this.osConfig.getBinaryName('ffuf');
      const result = await this.commandRunner.executeCommand(binaryName, ['--version']);
      return result.success ? '2.0' : 'unknown';
    } catch {
      return 'unknown';
    }
  }

  public async isAvailable(): Promise<boolean> {
    try {
      const binaryName = this.osConfig.getBinaryName('ffuf');
      const result = await this.commandRunner.executeCommand(binaryName, ['--version']);
      return result.success;
    } catch {
      return false;
    }
  }
} 