/**
 * Nikto Tool - Web vulnerability scanner
 * 
 * Provides comprehensive web application security testing
 */

import { ToolWrapper, ToolExecutionOptions, ToolResult } from './base.js';
import { CommandRunner } from '../utils/commandRunner.js';
import { OSConfigManager } from '../utils/osConfig.js';

export interface NiktoOptions extends ToolExecutionOptions {
  target: string;
  port?: number;
  maxTime?: number;
  format?: 'txt' | 'xml' | 'json' | 'csv';
  plugins?: string[];
  noSSL?: boolean;
  ssl?: boolean;
  followRedirects?: boolean;
  userAgent?: string;
  cookies?: string;
  output?: string;
  verbose?: boolean;
}

export class NiktoTool extends ToolWrapper {
  private commandRunner: CommandRunner;
  private osConfig: OSConfigManager;

  constructor() {
    super('nikto_scan');
    this.commandRunner = new CommandRunner(null as any, null as any);
    this.osConfig = new OSConfigManager();
  }

  override async execute(options: NiktoOptions): Promise<ToolResult> {
    const startTime = Date.now();
    
    try {
      const binaryName = this.osConfig.isWindows() ? 'nikto.pl' : 'nikto';
      const args = this.buildArguments(options);
      
      const result = await this.commandRunner.executeCommand(binaryName, args, {
        timeout: options.timeout || 300000, // 5 minutes
      });

      const duration = Date.now() - startTime;

      if (result.success) {
        const parsedResults = this.parseNiktoOutput(result.stdout);
        
        return {
          success: true,
          data: {
            ...parsedResults,
            target: options.target,
            port: options.port,
            rawOutput: result.stdout,
          },
          metadata: {
            executionTime: duration,
            command: `${binaryName} ${args.join(' ')}`,
            tool: 'nikto',
            version: await this.getVersion(),
          },
        };
      } else {
        return {
          success: false,
          error: `Nikto execution failed: ${result.stderr}`,
          data: {
            stdout: result.stdout,
            stderr: result.stderr,
          },
          metadata: {
            executionTime: duration,
            tool: 'nikto',
          },
        };
      }
    } catch (error) {
      return {
        success: false,
        error: `Nikto tool error: ${error instanceof Error ? error.message : 'Unknown error'}`,
        metadata: {
          executionTime: Date.now() - startTime,
          tool: 'nikto',
        },
      };
    }
  }

  private buildArguments(options: NiktoOptions): string[] {
    const args: string[] = [];
    
    // Target
    args.push('-h', options.target);
    
    // Port
    if (options.port) {
      args.push('-p', String(options.port));
    }
    
    // Max time
    if (options.maxTime) {
      args.push('-maxtime', String(options.maxTime));
    }
    
    // Format
    args.push('-Format', options.format || 'txt');
    
    // No interactive mode
    args.push('-ask', 'no');
    
    // Additional options
    if (options.noSSL) args.push('-nossl');
    if (options.ssl) args.push('-ssl');
    if (options.followRedirects) args.push('-followredirects');
    if (options.userAgent) args.push('-useragent', options.userAgent);
    if (options.cookies) args.push('-Cookies', options.cookies);
    if (options.verbose) args.push('-Display', 'V');
    
    return args;
  }

  private parseNiktoOutput(output: string): any {
    const results = {
      vulnerabilities: [] as any[],
      summary: {
        totalTests: 0,
        vulnerabilitiesFound: 0,
        severityCount: { high: 0, medium: 0, low: 0, info: 0 },
      },
    };

    const lines = output.split('\n');
    
    for (const line of lines) {
      if (line.includes('+ OSVDB-') || line.includes('+ /') || line.includes('+ Server:')) {
        const vuln = {
          description: line.trim(),
          severity: this.determineSeverity(line),
          category: this.categorizeVulnerability(line),
        };
        
        results.vulnerabilities.push(vuln);
        results.summary.vulnerabilitiesFound++;
        results.summary.severityCount[vuln.severity]++;
      }
    }
    
    results.summary.totalTests = results.vulnerabilities.length;
    
    return results;
  }

  private determineSeverity(line: string): 'high' | 'medium' | 'low' | 'info' {
    if (line.includes('OSVDB') || line.includes('CVE')) return 'high';
    if (line.includes('Server:') || line.includes('X-Powered-By')) return 'medium';
    if (line.includes('robots.txt') || line.includes('admin')) return 'low';
    return 'info';
  }

  private categorizeVulnerability(line: string): string {
    if (line.includes('Server:')) return 'Information Disclosure';
    if (line.includes('admin') || line.includes('login')) return 'Authentication';
    if (line.includes('CGI') || line.includes('script')) return 'Application';
    if (line.includes('SSL') || line.includes('TLS')) return 'Encryption';
    return 'General';
  }

  private async getVersion(): Promise<string> {
    try {
      const binaryName = this.osConfig.isWindows() ? 'nikto.pl' : 'nikto';
      const result = await this.commandRunner.executeCommand(binaryName, ['-Version'], { timeout: 5000 });
      
      if (result.success) {
        const versionMatch = result.stdout.match(/v?(\d+\.\d+\.\d+)/);
        return versionMatch?.[1] || 'unknown';
      }
    } catch {
      // Ignore version detection errors
    }
    return 'unknown';
  }

  /**
   * Check if Nikto tool is available
   */
  public async isAvailable(): Promise<boolean> {
    try {
      const binaryName = this.osConfig.isWindows() ? 'nikto.pl' : 'nikto';
      return await this.commandRunner.isCommandAvailable(binaryName);
    } catch {
      return false;
    }
  }
} 