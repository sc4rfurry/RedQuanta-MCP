/**
 * Hydra Tool - Network service brute forcer
 * 
 * Provides password brute forcing for various network services
 */

import { ToolWrapper, ToolExecutionOptions, ToolResult } from './base.js';
import { CommandRunner } from '../utils/commandRunner.js';
import { OSConfigManager } from '../utils/osConfig.js';

export interface HydraOptions extends ToolExecutionOptions {
  target: string;
  service: string;
  port?: number;
  userlist?: string;
  passlist?: string;
  username?: string;
  password?: string;
  threads?: number;
  stopOnSuccess?: boolean;
  verbose?: boolean;
  timeout?: number;
  maxAttempts?: number;
}

export class HydraTool extends ToolWrapper {
  private commandRunner: CommandRunner;
  private osConfig: OSConfigManager;

  constructor() {
    super('hydra_bruteforce');
    this.commandRunner = new CommandRunner(null as any, null as any);
    this.osConfig = new OSConfigManager();
  }

  override async execute(options: HydraOptions): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      const binaryName = this.osConfig.getBinaryName('hydra');
      const args = this.buildArguments(options);
      
      const result = await this.commandRunner.executeCommand(binaryName, args, {
        timeout: options.timeout || 600000, // 10 minutes default
      });

      const duration = Date.now() - startTime;

      if (result.success) {
        const parsedResults = this.parseHydraOutput(result.stdout);
        
        return {
          success: true,
          data: {
            ...parsedResults,
            target: options.target,
            service: options.service,
            rawOutput: result.stdout,
          },
          metadata: {
            executionTime: duration,
            command: `${binaryName} ${args.join(' ')}`,
            tool: 'hydra',
            version: await this.getVersion(),
          },
        };
      } else {
        return {
          success: false,
          error: `Hydra execution failed: ${result.stderr}`,
          data: {
            stdout: result.stdout,
            stderr: result.stderr,
          },
          metadata: {
            executionTime: duration,
            tool: 'hydra',
          },
        };
      }
    } catch (error) {
      return {
        success: false,
        error: `Hydra tool error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        metadata: {
          executionTime: Date.now() - startTime,
          tool: 'hydra',
        },
      };
    }
  }

  private buildArguments(options: HydraOptions): string[] {
    const args: string[] = [];
    
    // User list or username
    if (options.userlist) {
      args.push('-L', options.userlist);
    } else if (options.username) {
      args.push('-l', options.username);
    } else {
      args.push('-l', 'admin'); // Default username
    }
    
    // Password list or password
    if (options.passlist) {
      args.push('-P', options.passlist);
    } else if (options.password) {
      args.push('-p', options.password);
    } else {
      args.push('-P', '/usr/share/wordlists/rockyou.txt'); // Default wordlist
    }
    
    // Threads
    args.push('-t', String(options.threads || 16));
    
    // Stop on first success
    if (options.stopOnSuccess !== false) {
      args.push('-f');
    }
    
    // Verbose mode
    if (options.verbose) {
      args.push('-V');
    }
    
    // Target and service
    args.push(options.target);
    
    // Service with optional port
    if (options.port) {
      args.push(`${options.service}://${options.target}:${options.port}`);
    } else {
      args.push(options.service);
    }
    
    return args;
  }

  private parseHydraOutput(output: string): any {
    const results = {
      credentials: [] as any[],
      attempts: 0,
      successful: false,
      summary: {
        totalCredentials: 0,
        uniqueUsers: new Set<string>(),
        services: new Set<string>(),
      },
    };

    const lines = output.split('\n');
    
    for (const line of lines) {
      // Parse successful credentials
      const credMatch = line.match(/\[(\w+)\]\s+host:\s*([\w.-]+)\s+login:\s*(\w+)\s+password:\s*(.+)/);
      if (credMatch && credMatch[1] && credMatch[2] && credMatch[3] && credMatch[4]) {
        const [, service, host, username, password] = credMatch;
        const credential = {
          service,
          host,
          username,
          password: password.trim(),
          timestamp: new Date().toISOString(),
        };
        
        results.credentials.push(credential);
        results.summary.uniqueUsers.add(username);
        results.summary.services.add(service);
        results.successful = true;
      }
      
      // Count attempts
      if (line.includes('attempt')) {
        const attemptMatch = line.match(/(\d+) of (\d+)/);
        if (attemptMatch?.[1]) {
          results.attempts = parseInt(attemptMatch[1], 10);
        }
      }
    }
    
    results.summary.totalCredentials = results.credentials.length;
    
    return results;
  }

  private async getVersion(): Promise<string> {
    try {
      const binaryName = this.osConfig.getBinaryName('hydra');
      const result = await this.commandRunner.executeCommand(binaryName, ['-h'], { timeout: 5000 });
      
      if (result.success) {
        const versionMatch = result.stdout.match(/v?(\d+\.\d+)/);
        return versionMatch?.[1] || 'unknown';
      }
    } catch {
      // Ignore version detection errors
    }
    return 'unknown';
  }
} 