/**
 * Comprehensive Help System for RedQuanta MCP
 * Provides detailed documentation, examples, and guidance for LLMs and users
 */

import { Logger } from 'pino';
import { PluginSystem, LoadedPlugin } from './pluginSystem.js';

export interface ToolDocumentation {
  name: string;
  category: string;
  description: string;
  longDescription: string | undefined;
  purpose: string;
  useCases: string[];
  dangerLevel: 'safe' | 'caution' | 'dangerous';
  inputSchema: any;
  outputSchema: any;
  examples: ToolExample[];
  customParameters: CustomParameterDoc[];
  relatedTools: string[];
  commonErrors: ErrorDoc[];
  bestPractices: string[];
  llmGuidance: LLMGuidance;
}

export interface ToolExample {
  title: string;
  description: string;
  scenario: string;
  parameters: Record<string, any>;
  expectedOutput: any;
  llmPrompt?: string;
  explanation: string;
}

export interface CustomParameterDoc {
  name: string;
  type: string;
  description: string;
  required: boolean;
  default?: any;
  examples: any[];
  validationRules?: string[];
  llmTips: string[];
}

export interface ErrorDoc {
  error: string;
  cause: string;
  solution: string;
  prevention: string;
}

export interface LLMGuidance {
  contextualUsage: string;
  parameterRecommendations: Record<string, string>;
  sequenceRecommendations: string[];
  cautionsForLLMs: string[];
  outputInterpretation: string;
}

export interface WorkflowDocumentation {
  name: string;
  description: string;
  phases: WorkflowPhase[];
  tools: string[];
  prerequisites: string[];
  outputs: string[];
  scenarios: WorkflowScenario[];
}

export interface WorkflowPhase {
  name: string;
  description: string;
  tools: string[];
  duration: string;
  outputs: string[];
}

export interface WorkflowScenario {
  name: string;
  description: string;
  steps: string[];
  expectedResults: string[];
  llmPrompt: string;
}

export class HelpSystem {
  private logger: Logger;
  private pluginSystem: PluginSystem | undefined;
  private toolDocs: Map<string, ToolDocumentation> = new Map();
  private workflowDocs: Map<string, WorkflowDocumentation> = new Map();

  constructor(logger: Logger, pluginSystem?: PluginSystem) {
    this.logger = logger;
    this.pluginSystem = pluginSystem;
    this.initializeBuiltinDocumentation();
  }

  /**
   * Initialize documentation for built-in tools
   */
  private initializeBuiltinDocumentation(): void {
    // Nmap Documentation
    this.toolDocs.set('nmap_scan', {
      name: 'nmap_scan',
      category: 'network',
      description: 'Advanced network discovery and security scanning with Nmap',
      longDescription: 'Nmap is a network mapper that discovers hosts and services on a network, creating a map of the network. It uses raw IP packets to determine available hosts, services, operating systems, and firewall configurations.',
      purpose: 'Network reconnaissance and security assessment',
      useCases: [
        'Host discovery in a network range',
        'Port scanning and service detection',
        'Operating system fingerprinting',
        'Vulnerability scanning with NSE scripts',
        'Network topology mapping'
      ],
      dangerLevel: 'caution',
      inputSchema: {
        type: 'object',
        properties: {
          target: { type: 'string', description: 'Target IP, hostname, or CIDR range' },
          ports: { type: 'string', description: 'Port specification (e.g., "1-1000", "top-ports 100")' },
          profile: { type: 'string', enum: ['default', 'aggressive', 'stealth'], default: 'default' },
          output_format: { type: 'string', enum: ['xml', 'json', 'gnmap'], default: 'xml' },
          dangerous: { type: 'boolean', default: false }
        },
        required: ['target']
      },
      outputSchema: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          hosts: { type: 'array', items: { type: 'object' } },
          ports: { type: 'array', items: { type: 'object' } },
          services: { type: 'array', items: { type: 'object' } },
          vulnerabilities: { type: 'array', items: { type: 'object' } }
        }
      },
      examples: [
        {
          title: 'Basic Host Discovery',
          description: 'Discover live hosts in a network range',
          scenario: 'Initial reconnaissance of a target network',
          parameters: {
            target: '192.168.1.0/24',
            profile: 'stealth'
          },
          expectedOutput: {
            success: true,
            hosts: ['192.168.1.1', '192.168.1.10', '192.168.1.50'],
            totalHosts: 3
          },
          llmPrompt: 'Scan the network 192.168.1.0/24 to discover live hosts using stealth techniques',
          explanation: 'This performs a ping sweep to identify active hosts without being too aggressive'
        },
        {
          title: 'Service Enumeration',
          description: 'Detailed port and service scanning',
          scenario: 'Detailed reconnaissance of a specific target',
          parameters: {
            target: '192.168.1.10',
            ports: 'top-ports 1000',
            profile: 'default'
          },
          expectedOutput: {
            success: true,
            openPorts: [22, 80, 443, 3306],
            services: [
              { port: 22, service: 'ssh', version: 'OpenSSH 8.4' },
              { port: 80, service: 'http', version: 'Apache 2.4.46' }
            ]
          },
          llmPrompt: 'Perform detailed port scanning on 192.168.1.10 to identify running services',
          explanation: 'Scans the most common 1000 ports and attempts service version detection'
        }
      ],
      customParameters: [
        {
          name: 'custom_flags',
          type: 'array',
          description: 'Additional Nmap flags for advanced users',
          required: false,
          examples: [
            ['-sS', '-O', '--traceroute'],
            ['--script', 'vuln'],
            ['-A', '-T4', '--min-rate', '1000']
          ],
          llmTips: [
            'Use -sS for SYN stealth scans (requires root)',
            'Add -O for OS detection (aggressive)',
            'Use --script vuln for vulnerability scanning (dangerous)',
            'T4 timing is good balance of speed and stealth'
          ]
        }
      ],
      relatedTools: ['masscan_scan', 'ffuf_fuzz', 'nikto_scan'],
      commonErrors: [
        {
          error: 'Permission denied',
          cause: 'Some scan types require root privileges',
          solution: 'Run with sudo or use TCP connect scans (-sT)',
          prevention: 'Check scan type requirements before execution'
        }
      ],
      bestPractices: [
        'Always have written permission before scanning',
        'Start with light scans, then increase intensity',
        'Use rate limiting to avoid detection',
        'Save results in multiple formats for analysis'
      ],
      llmGuidance: {
        contextualUsage: 'Nmap is typically the first tool used in network reconnaissance. Guide users through progressive scanning: host discovery → port scanning → service enumeration → vulnerability assessment.',
        parameterRecommendations: {
          target: 'Always validate IP ranges and ensure authorization',
          profile: 'Use "stealth" for initial recon, "default" for detailed scans, "aggressive" only when authorized',
          ports: 'Start with "top-ports 100", expand to "1-65535" for comprehensive scans'
        },
        sequenceRecommendations: [
          '1. Host discovery with stealth profile',
          '2. Port scanning on discovered hosts',
          '3. Service enumeration on open ports',
          '4. Vulnerability scanning with scripts (if dangerous mode enabled)'
        ],
        cautionsForLLMs: [
          'Always emphasize authorization requirements',
          'Warn about noisy scans in production environments',
          'Explain legal and ethical implications',
          'Recommend starting with non-intrusive scans'
        ],
        outputInterpretation: 'Parse results to identify: open ports, running services, OS fingerprints, and potential vulnerabilities. Correlate findings with other tools for comprehensive assessment.'
      }
    });

    // FFUF Documentation
    this.toolDocs.set('ffuf_fuzz', {
      name: 'ffuf_fuzz',
      category: 'web',
      description: 'Fast web fuzzing for directory and file discovery',
      longDescription: 'FFUF (Fuzz Faster U Fool) is a fast web fuzzer for discovering hidden directories, files, and endpoints on web applications.',
      purpose: 'Web application enumeration and content discovery',
      useCases: [
        'Directory and file enumeration',
        'Subdomain discovery',
        'Parameter fuzzing',
        'Virtual host discovery',
        'API endpoint discovery'
      ],
      dangerLevel: 'safe',
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'Target URL with FUZZ keyword' },
          wordlist: { type: 'string', description: 'Path to wordlist file' },
          threads: { type: 'number', default: 200 },
          filter_codes: { type: 'string', default: '403,404' },
          extensions: { type: 'string', description: 'File extensions to append' }
        },
        required: ['url', 'wordlist']
      },
      outputSchema: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          results: { type: 'array', items: { type: 'object' } },
          totalRequests: { type: 'number' },
          foundPaths: { type: 'array', items: { type: 'string' } }
        }
      },
      examples: [
        {
          title: 'Directory Discovery',
          description: 'Basic directory enumeration',
          scenario: 'Finding hidden directories on a web application',
          parameters: {
            url: 'https://target.com/FUZZ',
            wordlist: '/usr/share/wordlists/dirb/common.txt',
            threads: 100,
            filter_codes: '404,403'
          },
          expectedOutput: {
            success: true,
            foundPaths: ['/admin', '/backup', '/config'],
            totalRequests: 4614,
            results: [
              { path: '/admin', status: 200, length: 1234 },
              { path: '/backup', status: 301, length: 0 }
            ]
          },
          llmPrompt: 'Fuzz the website https://target.com to find hidden directories',
          explanation: 'Uses common directory wordlist to discover accessible paths'
        }
      ],
      customParameters: [
        {
          name: 'custom_headers',
          type: 'object',
          description: 'Custom HTTP headers for authentication or bypass',
          required: false,
          examples: [
            { 'Authorization': 'Bearer token123' },
            { 'User-Agent': 'Mozilla/5.0...' },
            { 'X-Forwarded-For': '127.0.0.1' }
          ],
          llmTips: [
            'Use Authorization headers for authenticated fuzzing',
            'Custom User-Agent can bypass basic filtering',
            'X-Forwarded-For may bypass IP restrictions'
          ]
        }
      ],
      relatedTools: ['gobuster_scan', 'nikto_scan', 'nmap_scan'],
      commonErrors: [
        {
          error: 'Too many requests / Rate limited',
          cause: 'High thread count overwhelming the server',
          solution: 'Reduce threads to 50 or lower, add delays',
          prevention: 'Start with conservative thread counts'
        }
      ],
      bestPractices: [
        'Start with small wordlists and expand',
        'Filter common error codes (404, 403)',
        'Use appropriate thread counts to avoid rate limiting',
        'Analyze response sizes and content types'
      ],
      llmGuidance: {
        contextualUsage: 'FFUF is used after basic web reconnaissance to discover hidden content. It\'s particularly effective for finding admin panels, backup files, and API endpoints.',
        parameterRecommendations: {
          threads: 'Start with 50-100 threads, increase carefully',
          filter_codes: 'Always filter 404s, consider filtering 403s based on context',
          wordlist: 'Use targeted wordlists: common.txt for general, api.txt for APIs'
        },
        sequenceRecommendations: [
          '1. Start with directory fuzzing using common wordlists',
          '2. Fuzz discovered directories recursively',
          '3. Test for common file extensions',
          '4. Perform subdomain enumeration if applicable'
        ],
        cautionsForLLMs: [
          'High thread counts can cause DoS-like effects',
          'Some applications log fuzzing attempts',
          'Be mindful of bandwidth usage',
          'Respect robots.txt and security policies'
        ],
        outputInterpretation: 'Focus on 200/301/302 responses. Analyze response lengths to identify interesting content. Look for admin panels, configuration files, and backup directories.'
      }
    });

    // Add workflow documentation
    this.initializeWorkflowDocumentation();
  }

  /**
   * Initialize workflow documentation
   */
  private initializeWorkflowDocumentation(): void {
    this.workflowDocs.set('enumeration', {
      name: 'enumeration',
      description: 'Comprehensive network and web application enumeration workflow',
      phases: [
        {
          name: 'Discovery',
          description: 'Identify live hosts and services',
          tools: ['nmap_scan', 'masscan_scan'],
          duration: '5-15 minutes',
          outputs: ['Host list', 'Open ports', 'Service fingerprints']
        },
        {
          name: 'Web Enumeration',
          description: 'Discover web application content',
          tools: ['ffuf_fuzz', 'gobuster_scan'],
          duration: '10-30 minutes',
          outputs: ['Hidden directories', 'File listings', 'Subdomain enumeration']
        }
      ],
      tools: ['nmap_scan', 'masscan_scan', 'ffuf_fuzz', 'gobuster_scan'],
      prerequisites: ['Target authorization', 'Network connectivity', 'Wordlists'],
      outputs: ['Network map', 'Service inventory', 'Web application structure'],
      scenarios: [
        {
          name: 'External Network Assessment',
          description: 'Enumerate externally facing assets',
          steps: [
            'Discover live hosts with Nmap',
            'Identify web services',
            'Enumerate web directories with FFUF',
            'Map application structure'
          ],
          expectedResults: [
            'List of accessible services',
            'Web application entry points',
            'Potential attack vectors'
          ],
          llmPrompt: 'Perform external enumeration of target 192.168.1.0/24 to identify web applications and services'
        }
      ]
    });
  }

  /**
   * Get tool documentation
   */
  getToolDocumentation(toolName: string): ToolDocumentation | null {
    // Check built-in documentation first
    const builtinDoc = this.toolDocs.get(toolName);
    if (builtinDoc) return builtinDoc;

    // Check plugin documentation
    if (this.pluginSystem) {
      const plugin = this.pluginSystem.getPlugin(toolName);
      if (plugin) {
        return this.generatePluginDocumentation(plugin);
      }
    }

    return null;
  }

  /**
   * Generate documentation for plugin tools
   */
  private generatePluginDocumentation(plugin: LoadedPlugin): ToolDocumentation {
    const manifest = plugin.manifest;
    
    return {
      name: manifest.name,
      category: manifest.category,
      description: manifest.description,
      longDescription: manifest.documentation,
      purpose: `Custom ${manifest.category} tool`,
      useCases: manifest.examples?.map(ex => ex.description) || [],
      dangerLevel: manifest.dangerLevel,
      inputSchema: manifest.schema || {},
      outputSchema: { type: 'object', description: 'Plugin-specific output' },
      examples: manifest.examples?.map(ex => ({
        title: ex.title,
        description: ex.description,
        scenario: ex.description,
        parameters: ex.parameters,
        expectedOutput: ex.expectedOutput || {},
        explanation: `Custom command: ${ex.command}`
      })) || [],
      customParameters: manifest.customCommands?.map(cmd => ({
        name: cmd.name,
        type: 'string',
        description: cmd.description,
        required: false,
        examples: cmd.examples,
        llmTips: [`Custom command: ${cmd.name}`, ...cmd.examples]
      })) || [],
      relatedTools: [],
      commonErrors: [],
      bestPractices: [`Follow ${manifest.name} plugin guidelines`],
      llmGuidance: {
        contextualUsage: `This is a custom plugin for ${manifest.description}. Refer to plugin documentation for specific usage.`,
        parameterRecommendations: {},
        sequenceRecommendations: ['Check plugin help for specific workflow'],
        cautionsForLLMs: ['Custom plugin - verify compatibility', 'Check danger level before use'],
        outputInterpretation: 'Plugin-specific output format. Consult plugin documentation.'
      }
    };
  }

  /**
   * Get comprehensive help for LLMs
   */
  getLLMHelp(): any {
    const tools = Array.from(this.toolDocs.keys());
    const workflows = Array.from(this.workflowDocs.keys());
    
    let pluginInfo = {};
    if (this.pluginSystem) {
      pluginInfo = this.pluginSystem.getSystemInfo();
    }

    return {
      overview: {
        description: 'RedQuanta MCP is a security-focused penetration testing orchestration platform',
        capabilities: [
          'Network reconnaissance and enumeration',
          'Web application security testing',
          'Vulnerability scanning and assessment',
          'Automated workflow execution',
          'Custom plugin and tool integration'
        ],
        safetyModel: {
          dangerousOperations: 'Require --dangerous flag and explicit authorization',
          auditLogging: 'All operations are logged for security and compliance',
          jailedFilesystem: 'File operations are restricted to designated safe areas'
        }
      },
      availableTools: tools.map(name => {
        const doc = this.toolDocs.get(name);
        return {
          name,
          category: doc?.category,
          description: doc?.description,
          dangerLevel: doc?.dangerLevel,
          primaryUseCases: doc?.useCases.slice(0, 3)
        };
      }),
      workflows: workflows.map(name => {
        const workflow = this.workflowDocs.get(name);
        return {
          name,
          description: workflow?.description,
          tools: workflow?.tools,
          duration: workflow?.phases.reduce((acc, phase) => acc + phase.duration + ', ', '').slice(0, -2)
        };
      }),
      pluginSystem: pluginInfo,
      llmUsageGuidelines: {
        authorization: 'Always emphasize the need for proper authorization before testing',
        progression: 'Guide users through logical testing phases: enum → scan → exploit',
        safety: 'Warn about dangerous operations and recommend starting with safe reconnaissance',
        documentation: 'Provide context and explain the purpose of each tool and technique'
      },
      quickStart: {
        reconnaissance: 'Start with nmap_scan for network discovery',
        webTesting: 'Use ffuf_fuzz for web application enumeration', 
        automation: 'Leverage workflow_enum for comprehensive reconnaissance',
        reporting: 'Generate reports with workflow_report for documentation'
      }
    };
  }

  /**
   * Get tool usage examples for LLMs
   */
  getToolExamples(toolName: string): ToolExample[] {
    const doc = this.getToolDocumentation(toolName);
    return doc?.examples || [];
  }

  /**
   * Get workflow documentation
   */
  getWorkflowDocumentation(workflowName: string): WorkflowDocumentation | null {
    return this.workflowDocs.get(workflowName) || null;
  }

  /**
   * Search documentation
   */
  searchDocumentation(query: string): any[] {
    const results: any[] = [];
    const searchTerm = query.toLowerCase();

    // Search tool documentation
    for (const [name, doc] of this.toolDocs) {
      if (
        doc.name.toLowerCase().includes(searchTerm) ||
        doc.description.toLowerCase().includes(searchTerm) ||
        doc.useCases.some(use => use.toLowerCase().includes(searchTerm))
      ) {
        results.push({
          type: 'tool',
          name: doc.name,
          description: doc.description,
          category: doc.category,
          relevance: this.calculateRelevance(doc, searchTerm)
        });
      }
    }

    // Search workflow documentation
    for (const [name, workflow] of this.workflowDocs) {
      if (
        workflow.name.toLowerCase().includes(searchTerm) ||
        workflow.description.toLowerCase().includes(searchTerm)
      ) {
        results.push({
          type: 'workflow',
          name: workflow.name,
          description: workflow.description,
          tools: workflow.tools,
          relevance: this.calculateRelevance(workflow, searchTerm)
        });
      }
    }

    // Sort by relevance
    return results.sort((a, b) => b.relevance - a.relevance);
  }

  /**
   * Calculate search relevance score
   */
  private calculateRelevance(item: any, searchTerm: string): number {
    let score = 0;
    
    if (item.name?.toLowerCase().includes(searchTerm)) score += 10;
    if (item.description?.toLowerCase().includes(searchTerm)) score += 5;
    if (item.useCases?.some((use: string) => use.toLowerCase().includes(searchTerm))) score += 3;
    
    return score;
  }

  /**
   * Get contextual help based on current operation
   */
  getContextualHelp(context: any): any {
    const { currentTool, phase, target, errors } = context;
    
    const help = {
      currentContext: {
        tool: currentTool,
        phase: phase,
        target: target
      },
      recommendations: [] as string[],
      troubleshooting: [] as ErrorDoc[],
      nextSteps: [] as string[]
    };

    // Tool-specific help
    if (currentTool) {
      const doc = this.getToolDocumentation(currentTool);
      if (doc) {
        help.recommendations.push(...doc.bestPractices);
        
        if (errors?.length > 0) {
          help.troubleshooting = doc.commonErrors.filter(error => 
            errors.some((err: string) => err.includes(error.error))
          );
        }
      }
    }

    // Phase-specific recommendations
    if (phase === 'enumeration') {
      help.nextSteps.push(
        'Analyze discovered services for vulnerabilities',
        'Perform service-specific enumeration',
        'Document findings for exploitation phase'
      );
    }

    return help;
  }
} 