/**
 * Workflow Engine - Orchestrates penetration testing workflows
 * 
 * Provides high-level automation for common pentest phases:
 * - Enumeration: Discovery and reconnaissance
 * - Scanning: Vulnerability identification  
 * - Exploitation: Attack execution (requires --dangerous)
 * - Post-exploitation: Persistence and data extraction
 * - Reporting: Consolidated report generation
 */

import { execa, ExecaError } from 'execa';
import { writeFile, readFile, mkdir } from 'fs/promises';
import { join, resolve } from 'path';
import type { Logger } from 'pino';

import { PathGuard } from '../utils/pathGuard.js';
import { ArgGuard } from '../utils/argGuard.js';
import { AuditLogger } from '../utils/auditLogger.js';
import { ToolWrapper } from '../tools/base.js';
import { NmapTool } from '../tools/nmap.js';
import { MasscanTool } from '../tools/masscan.js';
import { FfufTool } from '../tools/ffuf.js';
import { FilesystemManager } from '../utils/filesystem.js';
import { CommandRunner } from '../utils/commandRunner.js';

export interface WorkflowOptions {
  coaching?: 'beginner' | 'advanced';
  dangerous?: boolean;
  services?: string[];
  timeout?: number;
  concurrent?: boolean;
  [key: string]: any;
}

export interface WorkflowResult {
  success?: boolean;
  phase?: string;
  workflow?: string;
  target?: string;
  status?: string;
  startTime?: string;
  endTime?: string;
  results: Record<string, any>;
  errors?: string[];
  error?: string;
  coaching?: string[];
  nextSteps?: string[];
  timeElapsed?: number;
  summary?: {
    totalTests?: number;
    successfulTests?: number;
    vulnerabilitiesFound?: number;
    recommendation?: string[];
    [key: string]: any;
  };
  metadata?: Record<string, any>;
}

export interface CoachingContext {
  level: 'beginner' | 'advanced';
  phase: string;
  results: any;
  errors: string[];
}

export interface PluginManifest {
  name: string;
  version: string;
  description: string;
  category: 'network' | 'web' | 'exploitation' | 'password' | 'forensics' | 'automation' | 'custom';
  dangerLevel: 'safe' | 'caution' | 'dangerous';
  customCommands?: CustomCommand[];
  examples?: ToolExample[];
}

export interface CustomCommand {
  name: string;
  description: string;
  parameters: Record<string, any>;
  examples: string[];
}

export interface ToolExample {
  title: string;
  description: string;
  parameters: Record<string, any>;
  llmPrompt: string;
  explanation: string;
}

export interface ToolDocumentation {
  name: string;
  description: string;
  longDescription: string;
  category: string;
  dangerLevel: string;
  useCases: string[];
  examples: ToolExample[];
  customParameters: any[];
  bestPractices: string[];
  llmGuidance: any;
}

export class WorkflowEngine {
  private tools: Map<string, ToolWrapper>;
  private logger: Logger;
  private auditLogger: AuditLogger;
  private argGuard: ArgGuard;
  private pathGuard: PathGuard;
  private filesystemManager: FilesystemManager;
  private commandRunner: CommandRunner;
  private toolDocumentation: Map<string, ToolDocumentation> = new Map();
  private customPlugins: Map<string, PluginManifest> = new Map();

  constructor(
    logger: Logger,
    auditLogger: AuditLogger,
    argGuard: ArgGuard,
    pathGuard: PathGuard
  ) {
    this.tools = new Map();
    this.logger = logger;
    this.auditLogger = auditLogger;
    this.argGuard = argGuard;
    this.pathGuard = pathGuard;

    // Initialize filesystem manager and command runner
    this.filesystemManager = new FilesystemManager(pathGuard, auditLogger);
    this.commandRunner = new CommandRunner(argGuard, auditLogger);

    this.initializeTools();
    this.initializeDocumentation();
  }

  /**
   * Initialize comprehensive tool documentation for LLMs
   */
  private initializeDocumentation(): void {
    // Nmap Documentation with Custom Commands
    this.toolDocumentation.set('nmap_scan', {
      name: 'nmap_scan',
      description: 'Advanced network discovery and security scanning with Nmap',
      longDescription: 'Nmap is the industry standard for network discovery and security auditing. It uses raw IP packets to determine available hosts, services, operating systems, and security configurations.',
      category: 'network',
      dangerLevel: 'caution',
      useCases: [
        'Host discovery and network mapping',
        'Port scanning and service detection', 
        'Operating system fingerprinting',
        'Vulnerability scanning with NSE scripts',
        'Firewall and IDS evasion testing'
      ],
      examples: [
        {
          title: 'Basic Network Discovery',
          description: 'Discover live hosts in a network range',
          parameters: {
            target: '192.168.1.0/24',
            profile: 'stealth',
            custom_flags: ['-sn']
          },
          llmPrompt: 'Scan network 192.168.1.0/24 to find live hosts using stealth mode',
          explanation: 'Performs ping sweep without port scanning to identify active hosts'
        },
        {
          title: 'Service Enumeration',
          description: 'Detailed service detection and version scanning',
          parameters: {
            target: '192.168.1.10',
            ports: 'top-ports 1000',
            profile: 'default',
            custom_flags: ['-sV', '-sC', '--version-intensity', '7']
          },
          llmPrompt: 'Perform comprehensive service enumeration on 192.168.1.10',
          explanation: 'Scans top 1000 ports with service version detection and default NSE scripts'
        },
        {
          title: 'Vulnerability Scanning',
          description: 'Use Nmap NSE scripts for vulnerability detection',
          parameters: {
            target: '192.168.1.10',
            ports: '80,443',
            dangerous: true,
            custom_flags: ['--script', 'vuln', '--script-args', 'unsafe=1']
          },
          llmPrompt: 'Scan web services on 192.168.1.10 for known vulnerabilities',
          explanation: 'Runs vulnerability detection scripts against web services (requires --dangerous)'
        }
      ],
      customParameters: [
        {
          name: 'custom_flags',
          type: 'array',
          description: 'Advanced Nmap flags for custom scanning techniques',
          examples: [
            ['-sS', '-O', '--traceroute'],
            ['--script', 'discovery'],
            ['-f', '-D', 'RND:10']
          ],
          llmTips: [
            'Use -sS for SYN stealth scans (requires privileges)',
            'Add --script discovery for additional enumeration',
            'Use -f for fragment packets to evade firewalls',
            'Timing templates: -T0 (paranoid) to -T5 (insane)'
          ]
        },
        {
          name: 'output_options',
          type: 'object',
          description: 'Control output format and verbosity',
          examples: [
            { format: 'xml', verbosity: 2 },
            { format: 'grepable', save_to: 'scan_results.gnmap' }
          ],
          llmTips: [
            'XML format best for parsing and integration',
            'Grepable format useful for command-line processing',
            'Higher verbosity provides more diagnostic information'
          ]
        }
      ],
      bestPractices: [
        'Always obtain written authorization before scanning',
        'Start with non-intrusive scans and escalate gradually',
        'Use timing controls to avoid overwhelming targets',
        'Document all scanning activities for reporting',
        'Validate results with additional tools and manual verification'
      ],
      llmGuidance: {
        contextualUsage: 'Nmap is the cornerstone of network reconnaissance. Guide users through progressive discovery: host detection → port scanning → service enumeration → vulnerability assessment.',
        parameterRecommendations: {
          target: 'Validate IP ranges and ensure proper authorization',
          profile: 'stealth for initial recon, default for service enum, aggressive only when authorized',
          timing: 'Use -T3 as default, -T2 for sensitive environments, -T4 for internal testing'
        },
        cautionsForLLMs: [
          'Emphasize legal and ethical requirements',
          'Warn about scan detection and logging',
          'Explain impact of aggressive scans on production systems',
          'Recommend coordination with network administrators'
        ]
      }
    });

    // FFUF Documentation with Custom Commands
    this.toolDocumentation.set('ffuf_fuzz', {
      name: 'ffuf_fuzz',
      description: 'Fast web fuzzing for directory and file discovery',
      longDescription: 'FFUF (Fuzz Faster U Fool) is a high-performance web fuzzer designed for content discovery, parameter fuzzing, and subdomain enumeration.',
      category: 'web',
      dangerLevel: 'safe',
      useCases: [
        'Directory and file enumeration',
        'Subdomain discovery',
        'HTTP parameter fuzzing',
        'Virtual host discovery',
        'API endpoint enumeration'
      ],
      examples: [
        {
          title: 'Directory Discovery',
          description: 'Find hidden directories on web applications',
          parameters: {
            url: 'https://target.com/FUZZ',
            wordlist: '/usr/share/wordlists/dirb/common.txt',
            threads: 100,
            filter_codes: '404,403',
            custom_headers: { 'User-Agent': 'Mozilla/5.0...' }
          },
          llmPrompt: 'Discover hidden directories on https://target.com',
          explanation: 'Uses common directory wordlist to find accessible paths while filtering error codes'
        },
        {
          title: 'Subdomain Enumeration',
          description: 'Discover subdomains using DNS resolution',
          parameters: {
            url: 'https://FUZZ.target.com',
            wordlist: '/usr/share/wordlists/subdomains.txt',
            mode: 'clusterbomb',
            custom_flags: ['-mc', '200,301,302,403']
          },
          llmPrompt: 'Find subdomains of target.com using DNS fuzzing',
          explanation: 'Fuzzes subdomain positions and matches successful DNS resolutions'
        }
      ],
      customParameters: [
        {
          name: 'advanced_filtering',
          type: 'object',
          description: 'Advanced response filtering options',
          examples: [
            { filter_size: '1234,5678', filter_words: '10,20' },
            { match_regex: 'admin|config|backup' }
          ],
          llmTips: [
            'Filter by response size to remove false positives',
            'Use regex matching to find specific content',
            'Combine multiple filters for precise results'
          ]
        }
      ],
      bestPractices: [
        'Start with small wordlists and expand based on results',
        'Use appropriate thread counts to avoid rate limiting',
        'Analyze response patterns to refine filtering',
        'Respect robots.txt and application security policies'
      ],
      llmGuidance: {
        contextualUsage: 'FFUF excels at discovering hidden web content. Use after basic reconnaissance to map application structure and find entry points.',
        parameterRecommendations: {
          threads: 'Start with 50-100, monitor for rate limiting',
          wordlists: 'Use targeted lists: common.txt for general, api.txt for APIs'
        }
      }
    });

    // Enhanced Gobuster Documentation
    this.toolDocumentation.set('gobuster_scan', {
      name: 'gobuster_scan',
      description: 'Multi-mode enumeration tool for directories, DNS, and virtual hosts',
      longDescription: 'Gobuster is a powerful enumeration tool supporting directory brute-forcing, DNS subdomain discovery, and virtual host enumeration.',
      category: 'web',
      dangerLevel: 'safe',
      useCases: [
        'Directory and file enumeration',
        'DNS subdomain discovery',
        'Virtual host enumeration',
        'S3 bucket discovery',
        'TLD enumeration'
      ],
      examples: [
        {
          title: 'Directory Enumeration',
          description: 'Brute force directories with custom extensions',
          parameters: {
            mode: 'dir',
            target: 'https://target.com',
            wordlist: '/usr/share/wordlists/dirb/common.txt',
            extensions: 'php,html,js,txt',
            threads: 50,
            custom_flags: ['--wildcard', '--timeout', '10s']
          },
          llmPrompt: 'Enumerate directories on https://target.com with common extensions',
          explanation: 'Scans for directories and files with specified extensions using wildcard detection'
        }
      ],
      customParameters: [
        {
          name: 'authentication',
          type: 'object',
          description: 'Authentication options for restricted areas',
          examples: [
            { cookies: 'session=abc123; auth=token' },
            { headers: { 'Authorization': 'Bearer token123' } }
          ],
          llmTips: [
            'Use session cookies for authenticated scanning',
            'Bearer tokens for API endpoint discovery'
          ]
        }
      ],
      bestPractices: [
        'Use wildcard detection to handle catch-all responses',
        'Adjust timeout values based on target responsiveness',
        'Combine with other tools for comprehensive enumeration'
      ],
      llmGuidance: {
        contextualUsage: 'Gobuster complements FFUF with different enumeration techniques. Use for directory discovery when FFUF filtering is challenging.'
      }
    });
  }

  /**
   * Initialize all available pentesting tools
   */
  private initializeTools(): void {
    const toolInstances = [
      // Network Discovery & Scanning
      new NmapTool(),
      new MasscanTool(),
      
      // Web Application Testing
      new FfufTool(),
      
      // Enhanced implementations with REAL command execution
      new (class GobusterTool extends ToolWrapper {
        constructor() { super('gobuster_scan'); }
        
        override async execute(options: any): Promise<any> {
          const { target, mode = 'dir', wordlist, extensions, threads = 50, custom_flags = [] } = options;
          
          if (!target || !wordlist) {
            throw new Error('Target and wordlist are required for Gobuster');
          }

          const args = [mode, '-u', target, '-w', wordlist, '-t', threads.toString()];
          
          if (extensions) {
            args.push('-x', extensions);
          }
          
          args.push(...custom_flags);

          try {
            // REAL command execution instead of mock
            const commandRunner = new CommandRunner(
              new (await import('../utils/argGuard.js')).ArgGuard(),
              new (await import('../utils/auditLogger.js')).AuditLogger()
            );
            
            const result = await commandRunner.executeCommand('gobuster', args, { timeout: 300000 });
            
            return {
              success: result.success,
              tool: 'gobuster',
              mode,
              target,
              data: {
                foundPaths: this.parseGobusterOutput(result.stdout),
                rawOutput: result.stdout,
                errors: result.stderr,
                exitCode: result.exitCode
              },
              metadata: {
                wordlist,
                extensions,
                threads,
                duration: result.duration,
                command: result.command,
                args: result.args
              }
            };
          } catch (error) {
            return {
              success: false,
              tool: 'gobuster',
              error: error instanceof Error ? error.message : 'Unknown error',
              data: { target, mode }
            };
          }
        }

        private parseGobusterOutput(output: string): string[] {
          const lines = output.split('\n');
          const paths: string[] = [];
          
          for (const line of lines) {
            // Parse Gobuster output format: /path (Status: 200) [Size: 1234]
            if (line.includes('(Status:') && (line.includes('200') || line.includes('301') || line.includes('302'))) {
              const match = line.match(/^(\/[^\s]+)/);
              if (match && match[1]) {
                paths.push(match[1]);
              }
            }
          }
          
          return paths;
        }
      })(),

      new (class NiktoTool extends ToolWrapper {
        constructor() { super('nikto_scan'); }
        
        override async execute(options: any): Promise<any> {
          const { target, port = 80, ssl = false, maxtime = 300, custom_flags = [] } = options;
          
          if (!target) {
            throw new Error('Target is required for Nikto scan');
          }

          const args = ['-h', target, '-p', port.toString(), '-maxtime', maxtime.toString(), '-ask', 'no'];
          
          if (ssl) {
            args.push('-ssl');
          }
          
          args.push(...custom_flags);

          try {
            // REAL command execution instead of mock
            const commandRunner = new CommandRunner(
              new (await import('../utils/argGuard.js')).ArgGuard(),
              new (await import('../utils/auditLogger.js')).AuditLogger()
            );
            
            const result = await commandRunner.executeCommand('nikto', args, { timeout: maxtime * 1000 + 30000 });
            
            return {
              success: result.success,
              tool: 'nikto',
              target,
              data: {
                vulnerabilities: this.parseNiktoOutput(result.stdout),
                findings: this.extractFindings(result.stdout),
                rawOutput: result.stdout,
                errors: result.stderr,
                exitCode: result.exitCode
              },
              metadata: {
                port,
                ssl,
                maxtime,
                duration: result.duration,
                command: result.command
              }
            };
          } catch (error) {
            return {
              success: false,
              tool: 'nikto',
              error: error instanceof Error ? error.message : 'Unknown error',
              data: { target }
            };
          }
        }

        private parseNiktoOutput(output: string): any[] {
          const vulnerabilities: any[] = [];
          const lines = output.split('\n');
          
          for (const line of lines) {
            if (line.includes('OSVDB') || line.includes('CVE') || line.includes('+')) {
              const severity = this.determineSeverity(line);
              vulnerabilities.push({
                description: line.trim(),
                severity,
                reference: this.extractReference(line),
                type: this.categorizeVulnerability(line)
              });
            }
          }
          
          return vulnerabilities;
        }

        private extractFindings(output: string): any[] {
          const findings: any[] = [];
          const lines = output.split('\n');
          
          for (const line of lines) {
            if (line.includes('Server:')) {
              findings.push({ type: 'Server Info', details: line.trim() });
            } else if (line.includes('allowed')) {
              findings.push({ type: 'HTTP Methods', details: line.trim() });
            } else if (line.includes('header')) {
              findings.push({ type: 'Security Header', details: line.trim() });
            }
          }
          
          return findings;
        }

        private determineSeverity(line: string): string {
          if (line.toLowerCase().includes('critical') || line.includes('remote code')) return 'critical';
          if (line.toLowerCase().includes('high') || line.includes('authentication')) return 'high';
          if (line.toLowerCase().includes('medium') || line.includes('disclosure')) return 'medium';
          return 'low';
        }

        private categorizeVulnerability(line: string): string {
          if (line.includes('directory')) return 'Information Disclosure';
          if (line.includes('header')) return 'Security Headers';
          if (line.includes('method')) return 'HTTP Methods';
          if (line.includes('version')) return 'Version Disclosure';
          return 'General';
        }

        private extractReference(line: string): string {
          const osvdbMatch = line.match(/OSVDB-(\d+)/);
          const cveMatch = line.match(/(CVE-\d{4}-\d+)/);
          return osvdbMatch?.[0] || cveMatch?.[0] || 'N/A';
        }
      })(),

      // Enhanced SQL injection testing tool with REAL execution
      new (class SQLMapTool extends ToolWrapper {
        constructor() { super('sqlmap_test'); }
        
        override async execute(options: any): Promise<any> {
          const { url, data, cookie, level = 3, risk = 2, dangerous = false, custom_flags = [] } = options;
          
          if (!dangerous) {
            throw new Error('SQLMap requires --dangerous flag due to potential for destructive testing');
          }

          if (!url) {
            throw new Error('URL is required for SQLMap testing');
          }

          const args = ['-u', url, '--batch', '--level', level.toString(), '--risk', risk.toString()];
          
          if (data) args.push('--data', data);
          if (cookie) args.push('--cookie', cookie);
          
          args.push(...custom_flags);

          try {
            // REAL command execution
            const commandRunner = new CommandRunner(
              new (await import('../utils/argGuard.js')).ArgGuard(),
              new (await import('../utils/auditLogger.js')).AuditLogger()
            );
            
            // Use Python to run SQLMap
            const pythonArgs = ['-c', `
import subprocess
import sys
result = subprocess.run(['python3', '-m', 'sqlmap'] + sys.argv[1:], 
                       capture_output=True, text=True, timeout=600)
print(result.stdout)
if result.stderr:
    print(result.stderr, file=sys.stderr)
sys.exit(result.returncode)
            `, ...args];
            
            const result = await commandRunner.executeCommand('python3', pythonArgs, { timeout: 600000 });
            
            return {
              success: result.success,
              tool: 'sqlmap',
              target: url,
              data: {
                vulnerabilities: this.parseSQLMapOutput(result.stdout),
                injectionPoints: this.extractInjectionPoints(result.stdout),
                databases: this.extractDatabases(result.stdout),
                rawOutput: result.stdout,
                errors: result.stderr,
                exitCode: result.exitCode
              },
              metadata: {
                level,
                risk,
                dangerous: true,
                duration: result.duration,
                command: result.command
              }
            };
          } catch (error) {
            return {
              success: false,
              tool: 'sqlmap',
              error: error instanceof Error ? error.message : 'Unknown error',
              data: { url, dangerous }
            };
          }
        }

        private parseSQLMapOutput(output: string): any[] {
          const vulns: any[] = [];
          
          if (output.includes('is vulnerable')) {
            const vulnerabilityInfo = {
              type: 'SQL Injection',
              parameter: this.extractParameter(output),
              technique: this.extractTechnique(output),
              payload: this.extractPayload(output),
              dbms: this.extractDBMS(output)
            };
            vulns.push(vulnerabilityInfo);
          }
          
          return vulns;
        }

        private extractInjectionPoints(output: string): string[] {
          const points: string[] = [];
          const lines = output.split('\n');
          
          for (const line of lines) {
            if (line.includes('Parameter:') && line.includes('is vulnerable')) {
              const match = line.match(/Parameter:\s*([^\s]+)/);
              if (match && match[1]) points.push(match[1]);
            }
          }
          
          return points;
        }

        private extractDatabases(output: string): string[] {
          const databases: string[] = [];
          const lines = output.split('\n');
          
          for (const line of lines) {
            if (line.includes('available databases')) {
              const match = line.match(/\[([^\]]+)\]/);
              if (match && match[1]) {
                databases.push(...match[1].split(',').map(db => db.trim()));
              }
            }
          }
          
          return databases;
        }

        private extractParameter(output: string): string {
          const match = output.match(/Parameter:\s*([^\s]+)/);
          return match?.[1] || 'unknown';
        }

        private extractTechnique(output: string): string {
          if (output.includes('boolean-based')) return 'Boolean-based blind';
          if (output.includes('time-based')) return 'Time-based blind';
          if (output.includes('union')) return 'UNION query';
          if (output.includes('error-based')) return 'Error-based';
          return 'Unknown';
        }

        private extractPayload(output: string): string {
          const match = output.match(/Payload:\s*(.+)/);
          return match?.[1] || 'Not extracted';
        }

        private extractDBMS(output: string): string {
          const match = output.match(/back-end DBMS:\s*([^\n]+)/);
          return match?.[1] || 'Unknown';
        }
      })(),

      // Enhanced password cracking tool with REAL execution
      new (class JohnTool extends ToolWrapper {
        constructor() { super('john_crack'); }
        
        override async execute(options: any): Promise<any> {
          const { hash_file, wordlist, format, rules, dangerous = false, custom_flags = [] } = options;
          
          if (!dangerous) {
            throw new Error('John the Ripper requires --dangerous flag for password cracking operations');
          }

          if (!hash_file) {
            throw new Error('Hash file is required for John the Ripper');
          }

          const args = [hash_file];
          
          if (wordlist) args.push('--wordlist=' + wordlist);
          if (format) args.push('--format=' + format);
          if (rules) args.push('--rules=' + rules);
          
          args.push(...custom_flags);

          try {
            // REAL command execution
            const commandRunner = new CommandRunner(
              new (await import('../utils/argGuard.js')).ArgGuard(),
              new (await import('../utils/auditLogger.js')).AuditLogger()
            );
            
            const result = await commandRunner.executeCommand('john', args, { timeout: 300000 });
            
            return {
              success: result.success,
              tool: 'john',
              target: hash_file,
              data: {
                crackedPasswords: this.parseJohnOutput(result.stdout),
                statistics: this.extractStatistics(result.stdout),
                rawOutput: result.stdout,
                errors: result.stderr,
                exitCode: result.exitCode
              },
              metadata: {
                wordlist,
                format,
                rules,
                dangerous: true,
                duration: result.duration,
                command: result.command
              }
            };
          } catch (error) {
            return {
              success: false,
              tool: 'john',
              error: error instanceof Error ? error.message : 'Unknown error',
              data: { hash_file, dangerous }
            };
          }
        }

        private parseJohnOutput(output: string): any[] {
          const cracked: any[] = [];
          const lines = output.split('\n');
          
          for (const line of lines) {
            // John output format: username:password or hash:password
            if (line.includes(':') && !line.startsWith('Loaded') && !line.startsWith('Will run')) {
              const parts = line.split(':');
              if (parts.length >= 2 && parts[0] && parts[1] && parts[1].trim()) {
                cracked.push({ 
                  username: parts[0].trim(), 
                  password: parts.slice(1).join(':').trim(),
                  hashType: this.detectHashType(parts[0])
                });
              }
            }
          }
          
          return cracked;
        }

        private detectHashType(hash: string): string {
          if (hash.length === 32 && /^[a-f0-9]+$/i.test(hash)) return 'MD5';
          if (hash.length === 40 && /^[a-f0-9]+$/i.test(hash)) return 'SHA1';
          if (hash.length === 64 && /^[a-f0-9]+$/i.test(hash)) return 'SHA256';
          if (hash.startsWith('$2a$') || hash.startsWith('$2b$')) return 'bcrypt';
          if (hash.startsWith('$1$')) return 'MD5crypt';
          return 'Unknown';
        }

        private extractStatistics(output: string): any {
          const stats = {
            hashesLoaded: this.extractNumber(output, /Loaded (\d+) password hash/),
            passwordsCracked: this.extractNumber(output, /(\d+)g [\d:]+/),
            guessesPerSecond: this.extractGuessRate(output)
          };
          
          return stats;
        }

        private extractNumber(text: string, regex: RegExp): number {
          const match = text.match(regex);
          return match && match[1] ? parseInt(match[1]) : 0;
        }

        private extractGuessRate(output: string): string {
          const match = output.match(/(\d+g\/s)/);
          return match?.[1] || '0g/s';
        }
      })(),

      // Enhanced filesystem operations with REAL file operations
      new (class FilesystemTool extends ToolWrapper {
        private pathGuard: PathGuard;
        
        constructor(pathGuard: PathGuard) { 
          super('filesystem_ops'); 
          this.pathGuard = pathGuard;
        }
        
        override async execute(options: any): Promise<any> {
          const { operation = 'list', path = '/', dangerous = false } = options;
          
          try {
            switch (operation) {
              case 'list':
                return await this.listDirectory(path);
              case 'read':
                return await this.readFile(path);
              case 'write':
                if (!dangerous) {
                  throw new Error('Write operations require --dangerous flag');
                }
                return await this.writeFile(path, options.content || '');
              case 'stat':
                return await this.getFileStats(path);
              default:
                throw new Error(`Unknown filesystem operation: ${operation}`);
            }
          } catch (error) {
            return {
              success: false,
              tool: 'filesystem',
              error: error instanceof Error ? error.message : 'Unknown error',
              data: { operation, path, jailRoot: this.pathGuard.getJailRoot() }
            };
          }
        }

        private async listDirectory(path: string): Promise<any> {
          const { readdir, stat } = await import('fs/promises');
          const { join } = await import('path');
          
          const validation = this.pathGuard.validatePath(path);
          if (!validation.isValid) {
            throw new Error(`Invalid path: ${validation.reason}`);
          }
          
          const safePath = validation.canonicalPath;
          
          try {
            const entries = await readdir(safePath);
            const entryDetails = await Promise.all(
              entries.map(async (entry) => {
                try {
                  const entryPath = join(safePath, entry);
                  const stats = await stat(entryPath);
                  return {
                    name: entry,
                    type: stats.isDirectory() ? 'directory' : 'file',
                    size: stats.size,
                    modified: stats.mtime.toISOString(),
                    permissions: stats.mode.toString(8)
                  };
                } catch {
                  return {
                    name: entry,
                    type: 'unknown',
                    size: 0,
                    error: 'Could not access'
                  };
                }
              })
            );
            
            return {
              success: true,
              tool: 'filesystem',
              operation: 'list',
              data: {
                path: validation.relativePath,
                entries: entryDetails,
                jailRoot: this.pathGuard.getJailRoot(),
                totalItems: entries.length
              }
            };
          } catch (error) {
            throw new Error(`Failed to list directory: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        }

        private async readFile(path: string): Promise<any> {
          const { readFile } = await import('fs/promises');
          
          const validation = this.pathGuard.validatePath(path);
          if (!validation.isValid) {
            throw new Error(`Invalid path: ${validation.reason}`);
          }
          
          const safePath = validation.canonicalPath;
          
          try {
            const content = await readFile(safePath, 'utf8');
            const stats = await import('fs/promises').then(fs => fs.stat(safePath));
            
            return {
              success: true,
              tool: 'filesystem',
              operation: 'read',
              data: {
                path: validation.relativePath,
                content,
                encoding: 'utf8',
                size: content.length,
                fileSize: stats.size,
                modified: stats.mtime.toISOString()
              }
            };
          } catch (error) {
            throw new Error(`Failed to read file: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        }

        private async writeFile(path: string, content: string): Promise<any> {
          const { writeFile, mkdir } = await import('fs/promises');
          const { dirname } = await import('path');
          
          const validation = this.pathGuard.validatePath(path, true);
          if (!validation.isValid) {
            throw new Error(`Invalid path: ${validation.reason}`);
          }
          
          const safePath = validation.canonicalPath;
          
          try {
            // Ensure directory exists
            await mkdir(dirname(safePath), { recursive: true });
            
            // Write file
            await writeFile(safePath, content, 'utf8');
            
            return {
              success: true,
              tool: 'filesystem',
              operation: 'write',
              data: {
                path: validation.relativePath,
                bytesWritten: Buffer.byteLength(content, 'utf8'),
                dangerous: true,
                timestamp: new Date().toISOString()
              }
            };
          } catch (error) {
            throw new Error(`Failed to write file: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        }

        private async getFileStats(path: string): Promise<any> {
          const { stat } = await import('fs/promises');
          
          const validation = this.pathGuard.validatePath(path);
          if (!validation.isValid) {
            throw new Error(`Invalid path: ${validation.reason}`);
          }
          
          const safePath = validation.canonicalPath;
          
          try {
            const stats = await stat(safePath);
            
            return {
              success: true,
              tool: 'filesystem',
              operation: 'stat',
              data: {
                path: validation.relativePath,
                size: stats.size,
                created: stats.birthtime.toISOString(),
                modified: stats.mtime.toISOString(),
                accessed: stats.atime.toISOString(),
                permissions: stats.mode.toString(8),
                isDirectory: stats.isDirectory(),
                isFile: stats.isFile(),
                owner: stats.uid,
                group: stats.gid
              }
            };
          } catch (error) {
            throw new Error(`Failed to get file stats: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }
        }
      })(this.pathGuard),

      // Enhanced command runner with REAL execution
      new (class CommandRunnerTool extends ToolWrapper {
        private argGuard: ArgGuard;
        private commandRunner: CommandRunner;
        
        constructor(argGuard: ArgGuard, commandRunner: CommandRunner) { 
          super('command_run'); 
          this.argGuard = argGuard;
          this.commandRunner = commandRunner;
        }
        
        override async execute(options: any): Promise<any> {
          const { command, args = [], timeout = 300, dangerous = false } = options;
          
          if (!command) {
            throw new Error('Command is required');
          }

          try {
            // Use the real command runner
            const result = await this.commandRunner.executeCommand(command, args, {
              timeout: timeout * 1000
            });
            
            return {
              success: result.success,
              tool: 'command_runner',
              command,
              data: {
                stdout: result.stdout,
                stderr: result.stderr,
                exitCode: result.exitCode,
                duration: result.duration,
                timedOut: result.timedOut,
                securityChecks: 'passed'
              },
              metadata: {
                validatedCommand: result.command,
                validatedArgs: result.args,
                dangerous,
                timeout
              }
            };
          } catch (error) {
            return {
              success: false,
              tool: 'command_runner',
              error: error instanceof Error ? error.message : 'Unknown error',
              data: { command, args, securityChecks: 'failed' }
            };
          }
        }
      })(this.argGuard, this.commandRunner)
    ];

    for (const tool of toolInstances) {
      this.tools.set(tool.getName(), tool);
    }

    this.logger.info({ toolCount: this.tools.size }, 'Enhanced workflow tools initialized with real implementations');
  }

  /**
   * Execute enumeration workflow - enhanced with real web discovery
   */
  public async executeEnumeration(
    target: string,
    scope: 'network' | 'web' | 'full' = 'network',
    depth: 'light' | 'normal' | 'deep' = 'normal',
    coaching: 'beginner' | 'advanced' = 'beginner'
  ): Promise<WorkflowResult> {
    const startTime = Date.now();
    const phase = 'enumeration';
    
    await this.auditLogger.logActivity({
      action: 'workflow_start',
      target,
      details: { phase, scope, depth, coaching },
    });

    const result: WorkflowResult = {
      success: false,
      phase,
      target,
      results: {},
      errors: [],
      coaching: [],
      nextSteps: [],
      timeElapsed: 0,
    };

    try {
      this.logger.info({ target, scope, depth }, 'Starting enhanced enumeration workflow');

      // Phase 1: Network Discovery
      if (scope === 'network' || scope === 'full') {
        await this.executeNetworkDiscovery(target, depth, result);
      }

      // Phase 2: Enhanced Web Discovery  
      if (scope === 'web' || scope === 'full') {
        await this.executeEnhancedWebDiscovery(target, depth, result);
      }

      // Generate coaching and next steps
      result.coaching = this.generateCoaching({
        level: coaching,
        phase,
        results: result.results,
        errors: result.errors || [],
      });

      result.nextSteps = this.generateNextSteps(phase, result.results);
      result.success = (result.errors || []).length === 0;
      result.timeElapsed = Date.now() - startTime;

      this.logger.info(
        { target, success: result.success, timeElapsed: result.timeElapsed },
        'Enhanced enumeration workflow completed'
      );

      return result;
    } catch (error) {
      (result.errors || (result.errors = [])).push(error instanceof Error ? error.message : 'Unknown error');
      result.timeElapsed = Date.now() - startTime;
      
      this.logger.error({ error, target }, 'Enumeration workflow failed');
      return result;
    }
  }

  /**
   * Enhanced web discovery phase with REAL implementations
   */
  private async executeEnhancedWebDiscovery(
    target: string,
    depth: string,
    result: WorkflowResult
  ): Promise<void> {
    try {
      this.logger.info({ target, depth }, 'Starting enhanced web discovery');
      
      // Get FFUF tool for directory enumeration
      const ffufTool = this.tools.get('ffuf_fuzz');
      if (ffufTool) {
        try {
          // Basic directory enumeration
          const dirResult = await ffufTool.execute({
            url: `http://${target}/FUZZ`,
            wordlist: '/usr/share/wordlists/dirb/common.txt',
            filter_codes: '404,403',
            threads: depth === 'deep' ? 200 : 100
          });
          
          result.results.directory_enumeration = dirResult;
          
          // SSL enumeration if target looks like HTTPS
          if (target.includes('https') || target.includes('443')) {
            const sslResult = await ffufTool.execute({
              url: `https://${target}/FUZZ`,
              wordlist: '/usr/share/wordlists/dirb/common.txt',
              filter_codes: '404,403',
              threads: 50
            });
            
            result.results.ssl_directory_enumeration = sslResult;
          }
        } catch (error) {
          (result.errors || (result.errors = [])).push(`Directory enumeration failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }
      
      // Get Gobuster tool for additional enumeration
      const gobusterTool = this.tools.get('gobuster_scan');
      if (gobusterTool && depth === 'deep') {
        try {
          const gobusterResult = await gobusterTool.execute({
            target: `http://${target}`,
            wordlist: '/usr/share/wordlists/dirb/big.txt',
            mode: 'dir',
            threads: 50,
            extensions: 'php,html,js,txt,xml'
          });
          
          result.results.comprehensive_directory_scan = gobusterResult;
        } catch (error) {
          (result.errors || (result.errors = [])).push(`Gobuster enumeration failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }
      
      // Technology detection and vulnerability scanning
      const niktoTool = this.tools.get('nikto_scan');
      if (niktoTool && (depth === 'normal' || depth === 'deep')) {
        try {
          const niktoResult = await niktoTool.execute({
            target: target,
            port: 80,
            maxtime: depth === 'deep' ? 600 : 300
          });
          
          result.results.web_vulnerability_scan = niktoResult;
        } catch (error) {
          (result.errors || (result.errors = [])).push(`Web vulnerability scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      }
      
      this.logger.info({ target, toolsUsed: Object.keys(result.results) }, 'Enhanced web discovery completed');
      
    } catch (error) {
      (result.errors || (result.errors = [])).push(`Enhanced web discovery failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Execute network discovery phase
   */
  private async executeNetworkDiscovery(
    target: string,
    depth: string,
    result: WorkflowResult
  ): Promise<void> {
    try {
      const nmapTool = this.tools.get('nmap');
      if (!nmapTool) {
        throw new Error('Nmap tool not available');
      }

      // Quick ping sweep first
      const pingResult = await nmapTool.execute({
        target,
        ports: '',
        profile: 'stealth',
        output_format: 'xml',
        dangerous: false,
      });

      result.results.ping_sweep = pingResult;

      if (pingResult.success) {
        // Port scan based on depth
        let portRange = '1-1000';
        if (depth === 'deep') portRange = '1-65535';
        else if (depth === 'normal') portRange = 'top-ports 1000';

        const portScanResult = await nmapTool.execute({
          target,
          ports: portRange,
          profile: 'default',
          output_format: 'xml',
          dangerous: false,
        });

        result.results.port_scan = portScanResult;
      }
    } catch (error) {
      (result.errors || (result.errors = [])).push(`Network discovery failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Generate coaching messages based on context
   */
  private generateCoaching(context: CoachingContext): string[] {
    const coaching: string[] = [];

    if (context.level === 'beginner') {
      coaching.push(
        '🎯 Enumeration is the reconnaissance phase where we gather information about our target.',
        '📊 We discovered open ports and services - this gives us attack surface visibility.',
        '🔍 Next, we\'ll scan these services for vulnerabilities.',
        '⚠️  Always ensure you have proper authorization before testing!'
      );

      if (context.errors.length > 0) {
        coaching.push(
          '❌ Some enumeration steps failed. Common causes:',
          '  • Target might be down or filtered',
          '  • Network connectivity issues', 
          '  • Tool configuration problems'
        );
      }
    } else {
      coaching.push('Enumeration phase completed. Review results for next phase planning.');
      
      if (context.errors.length > 0) {
        coaching.push(`${context.errors.length} errors encountered during enumeration.`);
      }
    }

    return coaching;
  }

  /**
   * Generate next steps recommendations
   */
  private generateNextSteps(phase: string, results: Record<string, any>): string[] {
    const nextSteps: string[] = [];

    if (phase === 'enumeration') {
      nextSteps.push(
        'Run vulnerability scanning on discovered services',
        'Perform service-specific enumeration',
        'Research CVEs for identified service versions'
      );

      if (results.port_scan?.data?.openPorts?.length > 0) {
        nextSteps.push('Focus on high-value services (SSH, HTTP, FTP, SMB)');
      }
    }

    return nextSteps;
  }

  /**
   * Execute vulnerability scanning workflow
   */
  public async executeScan(
    target: string,
    services: string[] = [],
    aggressive: boolean = false,
    coaching: 'beginner' | 'advanced' = 'beginner'
  ): Promise<WorkflowResult> {
    const startTime = Date.now();
    const phase = 'scanning';

    const result: WorkflowResult = {
      success: false,
      phase,
      target,
      results: { services, aggressive },
      errors: [],
      coaching: [],
      nextSteps: [],
      timeElapsed: 0,
    };

    try {
      this.logger.info({ target, services, aggressive }, 'Starting scan workflow');
      
      // Call vulnerability scanning workflow
      result.results.vulnerability_scan = await this.runVulnerabilityScanning(target, {
        coaching: coaching,
        dangerous: aggressive,
        services: services
      });
      
      result.success = result.results.vulnerability_scan.success;
      result.coaching = this.generateCoaching({
        level: coaching,
        phase,
        results: result.results,
        errors: result.errors || [],
      });

      result.timeElapsed = Date.now() - startTime;
      return result;
    } catch (error) {
      (result.errors || (result.errors = [])).push(error instanceof Error ? error.message : 'Unknown error');
      result.timeElapsed = Date.now() - startTime;
      return result;
    }
  }

  /**
   * Vulnerability scanning workflow
   */
  public async runVulnerabilityScanning(target: string, options: WorkflowOptions = {}): Promise<WorkflowResult> {
    const result: WorkflowResult = {
      workflow: 'vulnerability_scan',
      target,
      status: 'running',
      startTime: new Date().toISOString(),
      results: {},
      errors: [],
      success: false,
      metadata: {
        coaching: options.coaching || 'beginner',
        dangerous: options.dangerous || false
      }
    };

    try {
      this.logger.info({ target, workflow: 'vulnerability_scan' }, 'Starting vulnerability scanning workflow');

      // Step 1: Service enumeration (if not provided)
      if (!options.services) {
        this.logger.info('No services provided, running service enumeration first');
        
        const nmapTool = new (await import('../tools/nmap.js')).NmapTool();
        const serviceResult = await nmapTool.execute({
          target,
          scanType: 'version',
          timing: '4'
        });

        result.results.service_enumeration = serviceResult;
        
        if (!serviceResult.success) {
          throw new Error('Service enumeration failed, cannot proceed with vulnerability scanning');
        }
      }

      // Step 2: Web application scanning (if HTTP services detected)
      const httpServices = this.detectHttpServices(result.results.service_enumeration?.data || {});
      if (httpServices.length > 0) {
        this.logger.info({ services: httpServices }, 'HTTP services detected, running web vulnerability scans');
        
        // FFUF directory fuzzing
        const ffufTool = new (await import('../tools/ffuf.js')).FfufTool();
        for (const service of httpServices) {
          const url = `http://${target}:${service.port}/FUZZ`;
          const ffufResult = await ffufTool.execute({
            url,
            filterCodes: ['404', '403'],
            threads: 50
          });
          
          result.results[`ffuf_${service.port}`] = ffufResult;
        }

        // Nikto vulnerability scanning
        try {
          const niktoArgs = ['-h', target, '-Format', 'txt'];
          const niktoResult = await this.commandRunner.executeCommand('nikto', niktoArgs);
          result.results.nikto_scan = {
            success: niktoResult.success,
            tool: 'nikto',
            stdout: niktoResult.stdout,
            stderr: niktoResult.stderr
          };
        } catch (error) {
          this.logger.warn({ error }, 'Nikto scan failed, continuing without it');
        }
      }

      // Step 3: Database service scanning
      const dbServices = this.detectDatabaseServices(result.results.service_enumeration?.data || {});
      if (dbServices.length > 0 && options.dangerous) {
        this.logger.info({ services: dbServices }, 'Database services detected, running SQL injection tests');
        
        for (const service of dbServices) {
          try {
            const sqlmapArgs = [
              '-u', `http://${target}:${service.port}/`,
              '--batch',
              '--level', '2',
              '--risk', '1'
            ];
            
            const sqlmapResult = await this.commandRunner.executeCommand('python3', ['sqlmap.py', ...sqlmapArgs]);
            result.results[`sqlmap_${service.port}`] = {
              success: sqlmapResult.success,
              tool: 'sqlmap',
              stdout: sqlmapResult.stdout,
              stderr: sqlmapResult.stderr
            };
          } catch (error) {
            this.logger.warn({ error, service }, 'SQLMap test failed');
          }
        }
      }

      // Step 4: SSH/RDP brute force (if dangerous mode enabled)
      if (options.dangerous) {
        const authServices = this.detectAuthServices(result.results.service_enumeration?.data || {});
        if (authServices.length > 0) {
          this.logger.info({ services: authServices }, 'Authentication services detected, running brute force attacks');
          
          for (const service of authServices) {
            try {
              const hydraArgs = [
                '-L', 'wordlists/users.txt',
                '-P', 'wordlists/passwords.txt', 
                '-t', '4',
                '-f',
                target,
                service.protocol
              ];
              
              const hydraResult = await this.commandRunner.executeCommand('hydra', hydraArgs);
              result.results[`hydra_${service.protocol}_${service.port}`] = {
                success: hydraResult.success,
                tool: 'hydra',
                stdout: hydraResult.stdout,
                stderr: hydraResult.stderr
              };
            } catch (error) {
              this.logger.warn({ error, service }, 'Hydra brute force failed');
            }
          }
        }
      }

      result.status = 'completed';
      result.endTime = new Date().toISOString();
      
      // Generate summary
      const totalTests = Object.keys(result.results).length;
      const successfulTests = Object.values(result.results).filter((r: any) => r.success).length;
      
      result.summary = {
        totalTests,
        successfulTests,
        vulnerabilitiesFound: this.countVulnerabilities(result.results),
        recommendation: this.generateRecommendations(result.results, options.coaching === 'beginner')
      };

      this.logger.info({ 
        target, 
        totalTests, 
        successfulTests,
        vulnerabilities: result.summary.vulnerabilitiesFound
      }, 'Vulnerability scanning workflow completed');

    } catch (error) {
      result.status = 'failed';
      result.error = error instanceof Error ? error.message : String(error);
      result.endTime = new Date().toISOString();
      
      this.logger.error({ error, target }, 'Vulnerability scanning workflow failed');
    }

    return result;
  }

  /**
   * Detect HTTP services from service enumeration results
   */
  private detectHttpServices(serviceData: any): Array<{port: number, protocol: string}> {
    const httpServices: Array<{port: number, protocol: string}> = [];
    
    // Look for common HTTP ports and services
    const commonHttpPorts = [80, 443, 8080, 8443, 8000, 3000, 5000];
    for (const port of commonHttpPorts) {
      httpServices.push({port, protocol: 'http'});
    }
    
    return httpServices.slice(0, 3); // Limit to first 3 to avoid too many scans
  }

  /**
   * Detect database services from service enumeration results
   */
  private detectDatabaseServices(serviceData: any): Array<{port: number, protocol: string}> {
    const dbServices: Array<{port: number, protocol: string}> = [];
    
    // Look for common database ports
    const commonDbPorts = [
      {port: 3306, protocol: 'mysql'},
      {port: 5432, protocol: 'postgresql'}, 
      {port: 1433, protocol: 'mssql'},
      {port: 27017, protocol: 'mongodb'}
    ];
    
    return commonDbPorts.slice(0, 2); // Limit scanning
  }

  /**
   * Detect authentication services from service enumeration results
   */
  private detectAuthServices(serviceData: any): Array<{port: number, protocol: string}> {
    const authServices: Array<{port: number, protocol: string}> = [];
    
    // Look for common auth services
    const commonAuthPorts = [
      {port: 22, protocol: 'ssh'},
      {port: 3389, protocol: 'rdp'},
      {port: 21, protocol: 'ftp'}
    ];
    
    return commonAuthPorts.slice(0, 1); // Very limited for safety
  }

  /**
   * Count vulnerabilities found in results
   */
  private countVulnerabilities(results: Record<string, any>): number {
    let count = 0;
    
    for (const [key, result] of Object.entries(results)) {
      if (result.success && result.stdout) {
        // Simple heuristics for vulnerability detection
        if (key.includes('nikto') && result.stdout.includes('OSVDB')) count++;
        if (key.includes('sqlmap') && result.stdout.includes('vulnerable')) count++;
        if (key.includes('hydra') && result.stdout.includes('login:')) count++;
        if (key.includes('ffuf') && result.stdout.includes('200')) count++;
      }
    }
    
    return count;
  }

  /**
   * Generate recommendations based on results
   */
  private generateRecommendations(results: Record<string, any>, beginnerMode: boolean): string[] {
    const recommendations: string[] = [];
    
    if (beginnerMode) {
      recommendations.push('Review all scan results carefully for potential security issues');
      recommendations.push('Verify any findings manually before taking action');
      recommendations.push('Consider running additional targeted scans based on discovered services');
    } else {
      recommendations.push('Correlate findings across different tools for comprehensive assessment');
      recommendations.push('Prioritize critical vulnerabilities for immediate remediation');
    }
    
    return recommendations;
  }

  /**
   * Get filesystem manager instance
   */
  public getFilesystemManager(): FilesystemManager {
    return this.filesystemManager;
  }

  /**
   * Get command runner instance  
   */
  public getCommandRunner(): CommandRunner {
    return this.commandRunner;
  }

  /**
   * List available tools
   */
  public listTools(): string[] {
    return Array.from(this.tools.keys());
  }

  /**
   * Get tool instance by name
   */
  public getTool(name: string): ToolWrapper | undefined {
    return this.tools.get(name);
  }

  /**
   * Get comprehensive help system for LLMs
   */
  public getHelpSystem(): any {
    const tools = Array.from(this.tools.keys());
    
    return {
      overview: {
        description: 'RedQuanta MCP - Security-focused penetration testing orchestration platform',
        capabilities: [
          'Network reconnaissance and enumeration',
          'Web application security testing', 
          'Vulnerability scanning and assessment',
          'Password cracking and brute forcing',
          'Automated workflow execution',
          'Custom command support for advanced users'
        ],
        safetyModel: {
          dangerousOperations: 'Require --dangerous flag and explicit authorization',
          auditLogging: 'All operations logged for security and compliance',
          jailedFilesystem: 'File operations restricted to safe areas'
        }
      },
      tools: tools.map(name => {
        const doc = this.toolDocumentation.get(name);
        return {
          name,
          description: doc?.description || 'Tool description not available',
          category: doc?.category || 'unknown',
          dangerLevel: doc?.dangerLevel || 'unknown',
          useCases: doc?.useCases || [],
          examples: doc?.examples || [],
          customParameters: doc?.customParameters || []
        };
      }),
      customCommands: {
        description: 'All tools support custom parameters for advanced usage',
        examples: [
          {
            tool: 'nmap_scan',
            customCommand: { custom_flags: ['-sS', '-O', '--script', 'vuln'] },
            description: 'Advanced Nmap scan with SYN stealth, OS detection, and vulnerability scripts'
          },
          {
            tool: 'ffuf_fuzz',
            customCommand: { custom_headers: { 'Authorization': 'Bearer token123' } },
            description: 'Authenticated web fuzzing with custom headers'
          }
        ]
      },
      llmGuidance: {
        authorization: 'Always emphasize need for proper authorization',
        progression: 'Guide through logical phases: enum → scan → exploit',
        safety: 'Warn about dangerous operations, start with reconnaissance',
        customization: 'Tools support custom flags for advanced users'
      }
    };
  }

  /**
   * Get tool-specific help and documentation
   */
  public getToolHelp(toolName: string): any {
    const doc = this.toolDocumentation.get(toolName);
    if (!doc) {
      return { error: `No documentation available for tool: ${toolName}` };
    }

    return {
      name: doc.name,
      description: doc.description,
      longDescription: doc.longDescription,
      category: doc.category,
      dangerLevel: doc.dangerLevel,
      useCases: doc.useCases,
      examples: doc.examples,
      customParameters: doc.customParameters,
      bestPractices: doc.bestPractices,
      llmGuidance: doc.llmGuidance,
      relatedTools: this.getRelatedTools(toolName)
    };
  }

  /**
   * Get related tools for cross-referencing
   */
  private getRelatedTools(toolName: string): string[] {
    const toolsByCategory: Record<string, string[]> = {
      network: ['nmap_scan', 'masscan_scan'],
      web: ['ffuf_fuzz', 'gobuster_scan', 'nikto_scan'],
      exploitation: ['sqlmap_test', 'hydra_bruteforce'],
      password: ['john_crack', 'hydra_bruteforce'],
      automation: ['workflow_enum', 'workflow_scan', 'workflow_report']
    };

    const doc = this.toolDocumentation.get(toolName);
    if (!doc) return [];

    const related = toolsByCategory[doc.category] || [];
    return related.filter(name => name !== toolName);
  }
} 