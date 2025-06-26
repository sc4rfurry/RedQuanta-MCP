/**
 * Nmap Tool Wrapper - Network discovery and port scanning
 */

import { BaseTool, ToolExecutionOptions, ToolResult } from './base.js';
import { CommandRunner } from '../utils/commandRunner.js';
import { OSConfigManager } from '../utils/osConfig.js';
import { ArgGuard } from '../utils/argGuard.js';
import { AuditLogger } from '../utils/auditLogger.js';

export interface NmapOptions extends ToolExecutionOptions {
  target: string;
  ports?: string;
  scanType?: 'tcp' | 'syn' | 'udp' | 'ping' | 'version' | 'script';
  timing?: '0' | '1' | '2' | '3' | '4' | '5';
}

export class NmapTool extends BaseTool {
  private commandRunner: CommandRunner;
  private osConfig: OSConfigManager;

  constructor() {
    super('nmap', '7.95', {
      linux: 'nmap',
      darwin: 'nmap', 
      windows: 'nmap.exe'
    });
    
    // Initialize with required dependencies
    const argGuard = new ArgGuard();
    const auditLogger = new AuditLogger();
    this.commandRunner = new CommandRunner(argGuard, auditLogger);
    this.osConfig = new OSConfigManager();
  }

  /**
   * Execute Nmap scan with specified options
   */
  public async execute(options: NmapOptions): Promise<ToolResult> {
    try {
      // Validate target
      if (!options.target) {
        throw new Error('Target is required for Nmap scan');
      }

      // Build basic Nmap command
      const args = this.buildNmapArgs(options);
      const binaryName = this.osConfig.getBinaryName('nmap');

      // Execute command
      const startTime = Date.now();
      const result = await this.commandRunner.executeCommand(binaryName, args);
      const duration = result.duration;

      return {
        success: result.success,
        tool: 'nmap',
        version: await this.getVersion(),
        target: options.target,
        duration,
        exitCode: result.exitCode,
        command: `${binaryName} ${args.join(' ')}`,
        stdout: result.stdout,
        stderr: result.stderr,
        data: {
          scanType: options.scanType || 'tcp',
          ports: options.ports || 'default',
          timing: options.timing || '4'
        },
        metadata: {
          binaryUsed: binaryName,
          argsCount: args.length,
          timedOut: result.timedOut
        }
      };

    } catch (error) {
      return {
        success: false,
        tool: 'nmap',
        version: await this.getVersion(),
        target: options.target,
        duration: 0,
        command: 'nmap (failed to execute)',
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  /**
   * Build Nmap command arguments
   */
  private buildNmapArgs(options: NmapOptions): string[] {
    const args: string[] = [];

    // Basic scan type
    switch (options.scanType) {
      case 'syn':
        args.push('-sS');
        break;
      case 'tcp':
        args.push('-sT');
        break;
      case 'udp':
        args.push('-sU');
        break;
      case 'ping':
        args.push('-sn');
        break;
      case 'version':
        args.push('-sV');
        break;
      case 'script':
        args.push('-sC');
        break;
      default:
        args.push('-sT'); // Default TCP connect scan
    }

    // Port specification
    if (options.ports) {
      args.push('-p', options.ports);
    }

    // Timing template
    if (options.timing) {
      args.push(`-T${options.timing}`);
    } else {
      args.push('-T4'); // Default aggressive timing
    }

    // Target (must be last)
    args.push(options.target);

    return args;
  }

  /**
   * Get Nmap version
   */
  public async getVersion(): Promise<string> {
    try {
      const binaryName = this.osConfig.getBinaryName('nmap');
      const result = await this.commandRunner.executeCommand(binaryName, ['--version']);
      
      if (result.success && result.stdout) {
        // Parse version from actual output
        const versionMatch = result.stdout.match(/Nmap version ([\d.]+)/);
        return versionMatch?.[1] || 'unknown';
      }
      return 'unknown';
    } catch {
      return 'unknown';
    }
  }

  /**
   * Check if tool is available
   */
  public async isAvailable(): Promise<boolean> {
    try {
      const binaryName = this.osConfig.getBinaryName('nmap');
      return await this.commandRunner.isCommandAvailable(binaryName);
    } catch {
      return false;
    }
  }
} 