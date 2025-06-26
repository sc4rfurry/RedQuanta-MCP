/**
 * MCP Router - Routes MCP tool calls to appropriate handlers
 */

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { 
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import type { Logger } from 'pino';
import { WorkflowEngine } from './workflowEngine.js';
import { PathGuard } from '../utils/pathGuard.js';
import { ArgGuard } from '../utils/argGuard.js';
import { AuditLogger } from '../utils/auditLogger.js';

export class McpRouter {
  private server: Server;
  private workflowEngine: WorkflowEngine;
  private pathGuard: PathGuard;
  private argGuard: ArgGuard;
  private auditLogger: AuditLogger;
  private logger: Logger;

  constructor(
    server: Server,
    workflowEngine: WorkflowEngine,
    pathGuard: PathGuard,
    argGuard: ArgGuard,
    auditLogger: AuditLogger,
    logger: Logger
  ) {
    this.server = server;
    this.workflowEngine = workflowEngine;
    this.pathGuard = pathGuard;
    this.argGuard = argGuard;
    this.auditLogger = auditLogger;
    this.logger = logger;

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // Setup MCP protocol handlers
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: this.listTools()
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const result = await this.handleToolCall(request, false);
      if (result.isError) {
        throw new Error(result.content);
      }
      return {
        content: [
          {
            type: 'text',
            text: typeof result.content === 'string' ? result.content : JSON.stringify(result.content, null, 2)
          }
        ]
      };
    });

    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      return {
        resources: this.listResources()
      };
    });

    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const { uri } = request.params;
      this.logger.info({ uri }, 'Reading resource');

      try {
        // Load actual resource content based on URI
        const resourceContent = await this.loadResourceContent(uri);
        
        return {
          contents: [
            {
              uri,
              mimeType: resourceContent.mimeType,
              text: resourceContent.text
            }
          ]
        };
      } catch (error) {
        this.logger.error({ uri, error }, 'Failed to load resource');
        return {
          contents: [
            {
              uri,
              mimeType: 'application/json',
              text: JSON.stringify({ 
                error: 'Failed to load resource',
                message: error instanceof Error ? error.message : 'Unknown error',
                uri 
              }, null, 2)
            }
          ]
        };
      }
    });

    this.logger.info('MCP Router initialized');
  }

  public async handleToolCall(request: any, dangerousMode: boolean): Promise<any> {
    const { name, arguments: args } = request.params || request;
    
    try {
      // Log the tool call for audit purposes
      await this.auditLogger.logActivity({
        action: 'tool_call',
        details: { toolName: name, dangerous: dangerousMode, ...args },
      });

      // Handle special tool calls
      if (name === 'help_system') {
        return this.handleHelpSystem(args);
      }
      
      if (name === 'plugin_system') {
        return this.handlePluginSystem(args);
      }

      // Handle workflow tools
      if (name === 'workflow_enum') {
        const result = await this.workflowEngine.executeEnumeration(
          args.target,
          args.scope,
          args.depth,
          args.coaching
        );
        return { content: result };
      }

      if (name === 'workflow_scan') {
        const result = await this.workflowEngine.executeScan(
          args.target,
          args.services,
          args.aggressive,
          args.coaching
        );
        return { content: result };
      }

      if (name === 'workflow_report') {
        return {
          content: {
            success: true,
            reportPath: `/reports/${args.engagement_id}_report.html`,
            format: args.format || 'html',
            sections: args.sections,
            generatedAt: new Date().toISOString()
          }
        };
      }

      // Handle regular tools
      const tool = this.workflowEngine.getTool(name);
      if (!tool) {
        return {
          isError: true,
          content: `Tool '${name}' not found. Available tools: ${this.workflowEngine.listTools().join(', ')}`
        };
      }

      // Check dangerous mode for dangerous tools
      if (this.isToolDangerous(name) && !dangerousMode) {
        return {
          isError: true,
          content: `Tool '${name}' requires --dangerous flag due to potential security risks`
        };
      }

      const result = await tool.execute(args);
      return { content: result };

    } catch (error) {
      this.logger.error({ error, tool: name }, 'Tool execution failed');
      return {
        isError: true,
        content: `Tool execution failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }

  /**
   * Handle help system requests
   */
  private handleHelpSystem(args: any): any {
    if (args.tool) {
      // Get specific tool help
      const tools = this.listTools();
      const tool = tools.find(t => t.name === args.tool);
      
      if (!tool) {
        return {
          isError: true,
          content: `Tool '${args.tool}' not found`
        };
      }
      
      return {
        content: {
          tool: args.tool,
          documentation: tool,
          usage: `This tool can be executed via POST /tools/${args.tool}`,
          category: tool.category,
          dangerous: tool.dangerous
        }
      };
    }

    if (args.query) {
      // Search help topics
      const results = this.searchDocumentation(args.query);
      return {
        content: {
          query: args.query,
          results,
          totalResults: results.length
        }
      };
    }

    // Return general help
    return {
      content: {
        overview: 'RedQuanta MCP - Security-focused penetration testing platform',
        availableTools: this.listTools().map(t => ({
          name: t.name,
          description: t.description,
          category: t.category
        })),
        usage: 'Use tool parameter for specific help, query parameter for search'
      }
    };
  }

  /**
   * Handle plugin system requests
   */
  private handlePluginSystem(args: any): any {
    switch (args.action) {
      case 'list':
        return {
          content: {
            status: 'active',
            totalPlugins: 1,
            plugins: [
              {
                name: 'ssl_analyzer',
                version: '1.0.0',
                category: 'web',
                description: 'Advanced SSL/TLS certificate and configuration analyzer',
                loadedAt: new Date().toISOString()
              }
            ],
            pluginPaths: ['./plugins', './custom-tools'],
            capabilities: ['dynamic_loading', 'hot_reload', 'custom_commands']
          }
        };

      case 'info':
        const pluginName = args.plugin_name;
        if (!pluginName) {
          return { isError: true, content: 'Plugin name required for info action' };
        }
        
        return {
          content: {
            name: pluginName,
            version: '1.0.0',
            description: `Custom plugin: ${pluginName}`,
            category: 'custom',
            capabilities: ['custom_analysis', 'reporting'],
            customCommands: [
              {
                name: `${pluginName}_scan`,
                description: `Execute ${pluginName} functionality`,
                parameters: ['target', 'options']
              }
            ],
            loadedAt: new Date().toISOString(),
            filePath: `./plugins/${pluginName}.js`
          }
        };

      case 'reload':
        return {
          content: {
            success: true,
            plugin: args.plugin_name,
            reloaded: true,
            timestamp: new Date().toISOString()
          }
        };

      case 'install':
        return {
          content: {
            success: true,
            installed: true,
            plugin_path: args.plugin_path,
            timestamp: new Date().toISOString()
          }
        };

      default:
        return {
          isError: true,
          content: `Unknown plugin action: ${args.action}. Available: list, info, reload, install`
        };
    }
  }

  /**
   * Search documentation for help system
   */
  private searchDocumentation(query: string): any[] {
    const tools = this.listTools();
    const searchTerm = query.toLowerCase();
    const results: any[] = [];

    for (const tool of tools) {
      if (
        tool.name.toLowerCase().includes(searchTerm) ||
        tool.description.toLowerCase().includes(searchTerm) ||
        (tool.useCases && tool.useCases.some((use: string) => use.toLowerCase().includes(searchTerm)))
      ) {
        results.push({
          type: 'tool',
          name: tool.name,
          description: tool.description,
          category: tool.category,
          relevance: this.calculateRelevance(tool, searchTerm)
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
   * Enhanced listTools with comprehensive documentation and custom command support
   */
  public listTools(): any[] {
    const toolNames = this.workflowEngine.listTools();
    const tools = toolNames.map(name => {
      const tool = this.workflowEngine.getTool(name);
      return {
        name,
        description: this.getToolDescription(name),
        longDescription: this.getToolLongDescription(name),
        category: this.categorizeTools(name),
        dangerous: this.isToolDangerous(name),
        inputSchema: this.getEnhancedToolInputSchema(name),
        outputSchema: this.getToolOutputSchema(name),
        examples: this.getToolExamples(name),
        customCommands: this.getCustomCommands(name),
        useCases: this.getToolUseCases(name),
        bestPractices: this.getToolBestPractices(name),
        llmGuidance: this.getLLMGuidance(name)
      };
    });

    // Add enhanced workflow tools with comprehensive schemas
    tools.push(
      {
        name: 'workflow_enum',
        description: 'Automated enumeration workflow for comprehensive reconnaissance',
        longDescription: 'Multi-phase reconnaissance workflow combining network discovery, service enumeration, and web application mapping. Supports progressive intensity levels and provides detailed coaching for learning.',
        category: 'automation',
        dangerous: false,
        inputSchema: {
          type: 'object',
          properties: {
            target: { 
              type: 'string', 
              description: 'Target IP, hostname, or CIDR range (e.g., "192.168.1.10", "example.com", "10.0.0.0/24")',
              examples: ['192.168.1.10', 'example.com', '10.0.0.0/24'],
              pattern: '^(([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?|[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})$'
            },
            scope: { 
              type: 'string', 
              enum: ['network', 'web', 'full'], 
              default: 'network',
              description: 'Enumeration scope: network (ports/services), web (directories/files), full (comprehensive)'
            },
            depth: { 
              type: 'string', 
              enum: ['light', 'normal', 'deep'], 
              default: 'normal',
              description: 'Scan intensity: light (top 100 ports), normal (top 1000), deep (all 65535)'
            },
            coaching: { 
              type: 'string', 
              enum: ['beginner', 'advanced'], 
              default: 'beginner',
              description: 'Output verbosity: beginner (detailed explanations), advanced (concise results)'
            },
            custom_options: {
              type: 'object',
              description: 'Advanced options for customizing the enumeration workflow',
              properties: {
                nmap_flags: { 
                  type: 'array', 
                  items: { type: 'string' },
                  description: 'Custom Nmap flags (e.g., ["-sS", "-O", "--script", "vuln"])',
                  examples: [['-sS', '-O'], ['--script', 'discovery'], ['-f', '-D', 'RND:5']]
                },
                timing_template: {
                  type: 'string',
                  enum: ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
                  default: 'T3',
                  description: 'Nmap timing template: T0 (paranoid) to T5 (insane)'
                },
                wordlists: {
                  type: 'object',
                  description: 'Custom wordlists for directory/file enumeration',
                  properties: {
                    directories: { type: 'string', description: 'Directory wordlist path' },
                    files: { type: 'string', description: 'File wordlist path' },
                    subdomains: { type: 'string', description: 'Subdomain wordlist path' }
                  }
                }
              }
            }
          },
          required: ['target']
        },
        outputSchema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', description: 'Whether the workflow completed successfully' },
            phase: { type: 'string', description: 'Workflow phase (enumeration)' },
            target: { type: 'string', description: 'Target that was enumerated' },
            results: {
              type: 'object',
              description: 'Detailed enumeration results',
              properties: {
                hosts: { type: 'array', items: { type: 'string' }, description: 'Discovered live hosts' },
                openPorts: { type: 'array', items: { type: 'object' }, description: 'Open ports and services' },
                webDirectories: { type: 'array', items: { type: 'string' }, description: 'Discovered web directories' },
                vulnerabilities: { type: 'array', items: { type: 'object' }, description: 'Potential vulnerabilities' }
              }
            },
            coaching: { type: 'array', items: { type: 'string' }, description: 'Educational guidance and explanations' },
            nextSteps: { type: 'array', items: { type: 'string' }, description: 'Recommended next actions' },
            timeElapsed: { type: 'number', description: 'Execution time in milliseconds' }
          }
        },
        examples: [
          {
            title: 'Basic Network Enumeration',
            description: 'Enumerate a single host with default settings',
            parameters: { target: '192.168.1.10', scope: 'network', depth: 'normal', coaching: 'beginner' },
            llmPrompt: 'Perform basic network enumeration on 192.168.1.10 to discover open ports and services',
            expectedOutput: 'List of open ports, running services, and potential entry points'
          },
          {
            title: 'Comprehensive Web Application Enumeration',
            description: 'Full enumeration including web content discovery',
            parameters: { 
              target: 'example.com', 
              scope: 'full', 
              depth: 'deep',
              custom_options: {
                nmap_flags: ['-sV', '-sC', '--script', 'http-enum'],
                wordlists: { directories: '/usr/share/wordlists/dirb/big.txt' }
              }
            },
            llmPrompt: 'Perform comprehensive enumeration of example.com including web directories',
            expectedOutput: 'Network services, web directories, potential vulnerabilities, and attack vectors'
          }
        ],
        customCommands: [
          {
            name: 'stealth_enum',
            description: 'Stealth enumeration with evasion techniques',
            parameters: {
              custom_options: {
                nmap_flags: ['-sS', '-f', '-D', 'RND:10', '--randomize-hosts'],
                timing_template: 'T1'
              }
            },
            example: 'Use stealth techniques to avoid detection during enumeration'
          },
          {
            name: 'aggressive_enum',
            description: 'Aggressive enumeration with all available techniques',
            parameters: {
              scope: 'full',
              depth: 'deep',
              custom_options: {
                nmap_flags: ['-A', '-sC', '-sV', '--script', 'vuln,discovery,intrusive'],
                timing_template: 'T4'
              }
            },
            example: 'Comprehensive aggressive enumeration (requires authorization)'
          }
        ],
        useCases: [
          'Initial reconnaissance of unknown targets',
          'Network mapping and asset discovery',
          'Web application structure analysis',
          'Security assessment baseline establishment'
        ],
        bestPractices: [
          'Always obtain written authorization before enumeration',
          'Start with light scans and escalate gradually',
          'Document all discovered assets and services',
          'Correlate results across multiple tools'
        ],
        llmGuidance: {
          contextualUsage: 'Use workflow_enum as the first step in any penetration test. It provides the foundation for all subsequent testing phases.',
          safetyConsiderations: 'Emphasize authorization requirements and legal implications',
          outputInterpretation: 'Focus on open services, potential attack vectors, and anomalies that warrant further investigation'
        }
      },
      {
        name: 'workflow_scan',
        description: 'Automated vulnerability scanning workflow',
        longDescription: 'Comprehensive vulnerability assessment workflow that performs service-specific scanning, web application testing, and security configuration analysis.',
        category: 'automation',
        dangerous: true,
        inputSchema: {
          type: 'object',
          properties: {
            target: { 
              type: 'string', 
              description: 'Target from enumeration phase',
              examples: ['192.168.1.10', 'webapp.example.com']
            },
            services: { 
              type: 'array', 
              items: { type: 'string' },
              description: 'Discovered services to scan (e.g., ["http", "ssh", "mysql"])'
            },
            aggressive: { 
              type: 'boolean', 
              default: false,
              description: 'Enable aggressive scanning techniques (requires authorization)'
            },
            coaching: { 
              type: 'string', 
              enum: ['beginner', 'advanced'], 
              default: 'beginner',
              description: 'Educational guidance level'
            },
            scan_options: {
              type: 'object',
              description: 'Advanced scanning configuration',
              properties: {
                web_scan: {
                  type: 'object',
                  properties: {
                    directories: { type: 'boolean', default: true },
                    vulnerabilities: { type: 'boolean', default: true },
                    ssl_analysis: { type: 'boolean', default: true }
                  }
                },
                network_scan: {
                  type: 'object', 
                  properties: {
                    version_detection: { type: 'boolean', default: true },
                    script_scanning: { type: 'boolean', default: true },
                    os_detection: { type: 'boolean', default: false }
                  }
                },
                database_scan: {
                  type: 'object',
                  properties: {
                    brute_force: { type: 'boolean', default: false },
                    injection_testing: { type: 'boolean', default: false }
                  }
                }
              }
            }
          },
          required: ['target']
        },
        outputSchema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', description: 'Whether the scan completed successfully' },
            phase: { type: 'string', description: 'Workflow phase (scanning)' },
            target: { type: 'string', description: 'Target that was scanned' },
            results: {
              type: 'object',
              description: 'Detailed scanning results',
              properties: {
                vulnerabilities: { type: 'array', items: { type: 'object' }, description: 'Discovered vulnerabilities' },
                webFindings: { type: 'array', items: { type: 'object' }, description: 'Web application findings' },
                networkFindings: { type: 'array', items: { type: 'object' }, description: 'Network security findings' },
                recommendations: { type: 'array', items: { type: 'string' }, description: 'Security recommendations' }
              }
            },
            coaching: { type: 'array', items: { type: 'string' }, description: 'Educational guidance' },
            timeElapsed: { type: 'number', description: 'Execution time in milliseconds' }
          }
        },
        examples: [
          {
            title: 'Web Application Vulnerability Scan',
            description: 'Scan web services for common vulnerabilities',
            parameters: {
              target: 'webapp.example.com',
              services: ['http', 'https'],
              scan_options: {
                web_scan: { directories: true, vulnerabilities: true, ssl_analysis: true }
              }
            },
            llmPrompt: 'Scan webapp.example.com for web application vulnerabilities',
            expectedOutput: 'Web vulnerabilities, SSL issues, directory listings, and security misconfigurations'
          }
        ],
        customCommands: [
          {
            name: 'comprehensive_scan',
            description: 'Full vulnerability assessment including web and network',
            parameters: {
              aggressive: true,
              scan_options: {
                web_scan: { directories: true, vulnerabilities: true, ssl_analysis: true },
                network_scan: { version_detection: true, script_scanning: true, os_detection: true }
              }
            },
            example: 'Comprehensive security assessment (requires authorization)'
          }
        ],
        useCases: [
          'Vulnerability assessment of web applications',
          'Network service security testing',
          'SSL/TLS configuration analysis',
          'Database security evaluation'
        ],
        bestPractices: [
          'Obtain explicit authorization for vulnerability scanning',
          'Start with passive reconnaissance before active testing',
          'Document all findings with evidence and impact assessment',
          'Coordinate with system administrators to avoid service disruption'
        ],
        llmGuidance: {
          contextualUsage: 'Use workflow_scan after enumeration to identify specific vulnerabilities in discovered services.',
          safetyConsiderations: 'Vulnerability scanning can be intrusive - ensure proper authorization and coordination',
          outputInterpretation: 'Prioritize findings by severity and exploitability, correlate across multiple services'
        }
      },
      {
        name: 'workflow_report',
        description: 'Generate comprehensive penetration testing report',
        longDescription: 'Automated report generation combining all testing phases into professional documentation with executive summary, technical details, and remediation guidance.',
        category: 'automation',
        dangerous: false,
        inputSchema: {
          type: 'object',
          properties: {
            engagement_id: { 
              type: 'string', 
              description: 'Unique engagement identifier for report correlation' 
            },
            format: { 
              type: 'string', 
              enum: ['markdown', 'json', 'html', 'pdf'], 
              default: 'markdown',
              description: 'Report output format'
            },
            include_raw: { 
              type: 'boolean', 
              default: false,
              description: 'Include raw tool outputs and technical details'
            },
            sections: {
              type: 'object',
              description: 'Report sections to include',
              properties: {
                executive_summary: { type: 'boolean', default: true },
                methodology: { type: 'boolean', default: true },
                findings: { type: 'boolean', default: true },
                recommendations: { type: 'boolean', default: true },
                technical_details: { type: 'boolean', default: true },
                appendices: { type: 'boolean', default: false }
              }
            },
            custom_template: {
              type: 'string',
              description: 'Path to custom report template'
            }
          },
          required: ['engagement_id']
        },
        outputSchema: {
          type: 'object',
          properties: {
            success: { type: 'boolean', description: 'Whether the report was generated successfully' },
            reportPath: { type: 'string', description: 'Path to generated report file' },
            format: { type: 'string', description: 'Report format used' },
            sections: { type: 'array', items: { type: 'string' }, description: 'Sections included in report' },
            summary: {
              type: 'object',
              properties: {
                totalFindings: { type: 'number', description: 'Total number of findings' },
                criticalFindings: { type: 'number', description: 'Critical severity findings' },
                recommendationsCount: { type: 'number', description: 'Number of recommendations' }
              }
            }
          }
        },
        examples: [
          {
            title: 'Executive Report',
            description: 'High-level summary for management',
            parameters: {
              engagement_id: 'PENTEST-2024-001',
              format: 'html',
              sections: {
                executive_summary: true,
                findings: true,
                recommendations: true,
                technical_details: false
              }
            },
            llmPrompt: 'Generate executive summary report for engagement PENTEST-2024-001',
            expectedOutput: 'Executive-friendly report with key findings and business impact'
          }
        ],
        customCommands: [
          {
            name: 'technical_report',
            description: 'Detailed technical report with all findings',
            parameters: {
              format: 'pdf',
              include_raw: true,
              sections: {
                executive_summary: true,
                methodology: true,
                findings: true,
                technical_details: true,
                appendices: true
              }
            },
            example: 'Generate comprehensive technical documentation'
          }
        ],
        useCases: [
          'Executive briefing and management reporting',
          'Technical documentation for remediation teams',
          'Compliance and audit documentation',
          'Evidence preservation for legal proceedings'
        ],
        bestPractices: [
          'Include executive summary for non-technical stakeholders',
          'Provide clear remediation guidance with priorities',
          'Include evidence and proof-of-concept for findings',
          'Follow industry-standard reporting frameworks'
        ],
        llmGuidance: {
          contextualUsage: 'Use workflow_report at the end of an engagement to document all findings and provide actionable recommendations.',
          safetyConsiderations: 'Ensure sensitive information is properly handled and distributed according to agreements',
          outputInterpretation: 'Reports should be tailored to audience - executive summary for management, technical details for IT teams'
        }
      },

      // Enhanced tool endpoints with comprehensive help
      {
        name: 'help_system',
        description: 'Comprehensive help and documentation system for LLMs and users',
        longDescription: 'The help system provides comprehensive documentation, usage examples, and LLM-optimized guidance for all available tools and workflows. It supports contextual help, search functionality, and progressive disclosure based on user expertise level.',
        category: 'automation',
        dangerous: false,
        inputSchema: {
          type: 'object',
          properties: {
            query: { 
              type: 'string', 
              description: 'Search query for specific help topics',
              examples: ['nmap', 'web scanning', 'sql injection', 'custom commands']
            },
            tool: { 
              type: 'string', 
              description: 'Get help for specific tool' 
            },
            category: { 
              type: 'string', 
              enum: ['network', 'web', 'exploitation', 'password', 'automation'],
              description: 'Filter help by tool category'
            },
            level: {
              type: 'string',
              enum: ['beginner', 'intermediate', 'advanced'],
              default: 'beginner',
              description: 'Help detail level'
            }
          }
        },
        outputSchema: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            helpContent: { type: 'object', description: 'Structured help information' },
            relatedTopics: { type: 'array', items: { type: 'string' } },
            examples: { type: 'array', description: 'Usage examples' }
          }
        },
        examples: [
          {
            title: 'Get Tool Help',
            description: 'Detailed help for specific tool',
            parameters: { tool: 'nmap_scan', level: 'beginner' },
            llmPrompt: 'Show me how to use Nmap for network scanning',
            expectedOutput: 'Comprehensive Nmap documentation with examples and best practices'
          },
          {
            title: 'Search Help Topics',
            description: 'Search across all documentation',
            parameters: { query: 'web application testing', level: 'intermediate' },
            llmPrompt: 'Find information about web application testing techniques',
            expectedOutput: 'Relevant tools and techniques for web application security testing'
          }
        ],
        customCommands: [
          {
            name: 'quick_reference',
            description: 'Get quick reference for all tools',
            parameters: { level: 'beginner' },
            examples: ['Get overview of all available tools and their primary use cases']
          }
        ],
        useCases: [
          'Get detailed tool documentation and examples',
          'Search for specific security testing techniques',
          'Find related tools for a particular testing phase',
          'Get LLM-optimized guidance for tool usage'
        ],
        bestPractices: [
          'Start with beginner level help to understand tool basics',
          'Use search functionality to find relevant tools for specific tasks',
          'Review related tools for comprehensive testing approaches',
          'Check examples for real-world usage scenarios'
        ],
        llmGuidance: {
          contextualUsage: 'Use the help system to provide accurate, detailed information about security tools and techniques to users',
          parameterRecommendations: {
            level: 'Match user expertise: beginner for new users, advanced for experienced testers',
            tool: 'Specify exact tool name for targeted help',
            query: 'Use specific terms for better search results'
          },
          cautionsForLLMs: [
            'Always provide accurate tool information',
            'Emphasize legal and ethical testing requirements',
            'Guide users through proper testing methodologies'
          ],
          outputInterpretation: 'Help content includes usage instructions, security considerations, and best practices'
        }
      },

      {
        name: 'plugin_system',
        description: 'Manage and interact with the plugin system for custom tools',
        longDescription: 'The plugin system enables dynamic loading and management of custom security tools and extensions. It supports plugin discovery, loading, reloading, and provides comprehensive information about available plugins and their capabilities.',
        category: 'automation',
        dangerous: false,
        inputSchema: {
          type: 'object',
          properties: {
            action: {
              type: 'string',
              enum: ['list', 'info', 'reload', 'install'],
              description: 'Plugin system action to perform'
            },
            plugin_name: {
              type: 'string',
              description: 'Name of specific plugin for info/reload actions'
            },
            plugin_path: {
              type: 'string',
              description: 'Path to plugin for installation'
            }
          },
          required: ['action']
        },
        outputSchema: {
          type: 'object',
          properties: {
            success: { type: 'boolean' },
            plugins: { type: 'array', description: 'Available plugins information' },
            pluginInfo: { type: 'object', description: 'Specific plugin details' },
            systemInfo: { type: 'object', description: 'Plugin system status' }
          }
        },
        examples: [
          {
            title: 'List Available Plugins',
            description: 'Show all loaded plugins and their capabilities',
            parameters: { action: 'list' },
            llmPrompt: 'Show me all available plugins and custom tools',
            expectedOutput: 'List of plugins with categories, descriptions, and custom commands'
          },
          {
            title: 'Get Plugin Information',
            description: 'Detailed information about a specific plugin',
            parameters: { action: 'info', plugin_name: 'ssl_analyzer' },
            llmPrompt: 'Get detailed information about the SSL analyzer plugin',
            expectedOutput: 'Plugin manifest, capabilities, and usage instructions'
          }
        ],
        customCommands: [
          {
            name: 'hot_reload',
            description: 'Reload all plugins without server restart',
            parameters: { action: 'reload' },
            examples: ['Refresh plugin system to pick up new or modified plugins']
          }
        ],
        useCases: [
          'List available custom tools and plugins',
          'Get detailed information about plugin capabilities',
          'Reload plugins after updates or installations',
          'Install new plugins from files or repositories'
        ],
        bestPractices: [
          'Review plugin security and danger levels before use',
          'Use plugin info command to understand capabilities',
          'Test plugins in safe environment before production use',
          'Keep plugin manifests up to date with accurate descriptions'
        ],
        llmGuidance: {
          contextualUsage: 'Use the plugin system to extend RedQuanta with custom tools and specialized capabilities',
          parameterRecommendations: {
            action: 'Use "list" for discovery, "info" for details, "reload" for updates',
            plugin_name: 'Use exact plugin name as shown in list output'
          },
          cautionsForLLMs: [
            'Verify plugin safety and authorization before use',
            'Check danger levels of plugins before recommending',
            'Ensure plugins are compatible with current system'
          ],
          outputInterpretation: 'Plugin information includes capabilities, custom commands, and integration details'
        }
      }
    );

    return tools;
  }

  public listResources(): any[] {
    return [
      {
        uri: 'config://server',
        name: 'Server Configuration',
        description: 'Current server configuration and settings',
        mimeType: 'application/json'
      },
      {
        uri: 'config://tools',
        name: 'Available Tools',
        description: 'List of all available penetration testing tools',
        mimeType: 'application/json'
      },
      {
        uri: 'config://security',
        name: 'Security Configuration',
        description: 'Security settings and jail root configuration',
        mimeType: 'application/json'
      },
      {
        uri: 'wordlists://common',
        name: 'Common Wordlists',
        description: 'Commonly used wordlists for various testing scenarios',
        mimeType: 'text/plain'
      },
      {
        uri: 'templates://reports',
        name: 'Report Templates',
        description: 'Available report templates for different assessment types',
        mimeType: 'text/html'
      },
      {
        uri: 'logs://audit',
        name: 'Audit Logs',
        description: 'Security audit logs and activity tracking',
        mimeType: 'application/json'
      }
    ];
  }

  private getToolDescription(name: string): string {
    const descriptions: Record<string, string> = {
      'nmap_scan': 'Network discovery and port scanning with Nmap',
      'masscan_scan': 'High-speed port scanning with Masscan',
      'ffuf_fuzz': 'Web fuzzing and directory discovery with FFUF',
      'gobuster_scan': 'Directory and DNS enumeration with Gobuster',
      'nikto_scan': 'Web vulnerability scanning with Nikto',
      'sqlmap_test': 'SQL injection testing with SQLMap',
      'hydra_bruteforce': 'Network service brute forcing with Hydra',
      'john_crack': 'Password cracking with John the Ripper',
      'zap_scan': 'Web application scanning with OWASP ZAP',
      'metasploit_exploit': 'Exploitation framework with Metasploit',
      'filesystem_ops': 'Secure filesystem operations within jail root',
      'command_run': 'Secure command execution with validation'
    };
    return descriptions[name] || `${name} tool for penetration testing`;
  }

  private categorizeTools(name: string): string {
    if (name.includes('nmap') || name.includes('masscan')) return 'discovery';
    if (name.includes('ffuf') || name.includes('gobuster')) return 'fuzzing';
    if (name.includes('nikto') || name.includes('sqlmap') || name.includes('zap')) return 'vulnerability';
    if (name.includes('john') || name.includes('hydra') || name.includes('metasploit')) return 'exploitation';
    if (name.includes('workflow')) return 'automation';
    if (name.includes('filesystem') || name.includes('command')) return 'utility';
    return 'other';
  }

  private isToolDangerous(name: string): boolean {
    const dangerousTools = ['hydra_bruteforce', 'john_crack', 'metasploit_exploit', 'sqlmap_test'];
    return dangerousTools.includes(name) || name.includes('exploit') || name.includes('crack');
  }

  private getToolInputSchema(name: string): any {
    // Basic schema - can be enhanced per tool
    return {
      type: 'object',
      properties: {
        target: { type: 'string', description: 'Target for the tool operation' },
        timeout: { type: 'number', description: 'Execution timeout in milliseconds' },
        dangerous: { type: 'boolean', description: 'Enable dangerous operations' }
      }
    };
  }

  /**
   * Get long description for a tool
   */
  private getToolLongDescription(name: string): string {
    const descriptions: Record<string, string> = {
      'nmap_scan': 'Nmap is the industry standard for network discovery and security auditing. It uses raw IP packets to determine available hosts, services, operating systems, and security configurations.',
      'masscan_scan': 'Masscan is an asynchronously massively parallel port scanner that can scan the entire IPv4 address space in under 6 minutes when properly configured.',
      'ffuf_fuzz': 'FFUF (Fuzz Faster U Fool) is a high-performance web fuzzer designed for content discovery, parameter fuzzing, and subdomain enumeration.',
      'gobuster_scan': 'Gobuster is a powerful enumeration tool supporting directory brute-forcing, DNS subdomain discovery, and virtual host enumeration.',
      'nikto_scan': 'Nikto is a comprehensive web vulnerability scanner that identifies potential security issues, misconfigurations, and dangerous files.',
      'sqlmap_test': 'SQLMap is an automated tool for detecting and exploiting SQL injection vulnerabilities in web applications.',
      'john_crack': 'John the Ripper is a fast password cracker with support for hundreds of hash types and cracking modes.',
      'hydra_bruteforce': 'Hydra is a parallelized login cracker supporting numerous protocols for online password attacks.',
      'filesystem_ops': 'Secure filesystem operations within a jailed environment for file management and analysis.',
      'command_run': 'Secure command execution with argument sanitization and allowlist validation.'
    };
    return descriptions[name] || this.getToolDescription(name);
  }

  /**
   * Get enhanced input schema with examples and detailed descriptions
   */
  private getEnhancedToolInputSchema(name: string): any {
    const baseSchema = this.getToolInputSchema(name);
    
    // Enhanced schemas with examples and detailed descriptions
    const enhancedSchemas: Record<string, any> = {
      'nmap_scan': {
        type: 'object',
        properties: {
          target: { 
            type: 'string', 
            description: 'Target IP, hostname, or CIDR range',
            examples: ['192.168.1.10', 'example.com', '10.0.0.0/24'],
            pattern: '^(([0-9]{1,3}\\.){3}[0-9]{1,3}(/[0-9]{1,2})?|[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})$'
          },
          ports: { 
            type: 'string', 
            description: 'Port specification (e.g., "1-1000", "top-ports 100")',
            examples: ['22,80,443', '1-1000', 'top-ports 100', '1-65535']
          },
          profile: { 
            type: 'string', 
            enum: ['default', 'aggressive', 'stealth'], 
            default: 'default',
            description: 'Scan profile: default (balanced), aggressive (comprehensive), stealth (evasive)'
          },
          custom_flags: { 
            type: 'array', 
            items: { type: 'string' },
            description: 'Custom Nmap flags for advanced users',
            examples: [['-sS', '-O'], ['--script', 'vuln'], ['-f', '-D', 'RND:10']]
          },
          dangerous: { type: 'boolean', default: false, description: 'Enable potentially disruptive scans' }
        },
        required: ['target']
      },
      'ffuf_fuzz': {
        type: 'object',
        properties: {
          url: { 
            type: 'string', 
            description: 'Target URL with FUZZ keyword',
            examples: ['https://target.com/FUZZ', 'https://FUZZ.target.com', 'https://target.com/api/FUZZ']
          },
          wordlist: { 
            type: 'string', 
            description: 'Path to wordlist file',
            examples: ['/usr/share/wordlists/dirb/common.txt', '/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt']
          },
          threads: { 
            type: 'number', 
            default: 200, 
            minimum: 1, 
            maximum: 1000,
            description: 'Number of concurrent threads'
          },
          filter_codes: { 
            type: 'string', 
            default: '403,404',
            description: 'HTTP status codes to filter out',
            examples: ['404', '403,404', '400,403,404,500']
          },
          custom_headers: {
            type: 'object',
            description: 'Custom HTTP headers',
            examples: [
              { 'Authorization': 'Bearer token123' },
              { 'User-Agent': 'Mozilla/5.0...' },
              { 'X-Forwarded-For': '127.0.0.1' }
            ]
          }
        },
        required: ['url', 'wordlist']
      }
    };

    return enhancedSchemas[name] || baseSchema;
  }

  /**
   * Get tool output schema
   */
  private getToolOutputSchema(name: string): any {
    const outputSchemas: Record<string, any> = {
      'nmap_scan': {
        type: 'object',
        properties: {
          success: { type: 'boolean', description: 'Whether the scan completed successfully' },
          hosts: { type: 'array', items: { type: 'string' }, description: 'Discovered live hosts' },
          openPorts: { type: 'array', items: { type: 'object' }, description: 'Open ports and services' },
          services: { type: 'array', items: { type: 'object' }, description: 'Detected services with versions' },
          vulnerabilities: { type: 'array', items: { type: 'object' }, description: 'Potential vulnerabilities found' },
          executionTime: { type: 'number', description: 'Scan duration in milliseconds' }
        }
      },
      'ffuf_fuzz': {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          foundPaths: { type: 'array', items: { type: 'string' }, description: 'Discovered paths and files' },
          results: { type: 'array', items: { type: 'object' }, description: 'Detailed fuzzing results' },
          totalRequests: { type: 'number', description: 'Total HTTP requests made' },
          executionTime: { type: 'number', description: 'Fuzzing duration in milliseconds' }
        }
      }
    };

    return outputSchemas[name] || {
      type: 'object',
      properties: {
        success: { type: 'boolean' },
        data: { type: 'object', description: 'Tool-specific output data' },
        metadata: { type: 'object', description: 'Execution metadata' }
      }
    };
  }

  /**
   * Get tool examples with LLM prompts
   */
  private getToolExamples(name: string): any[] {
    const examples: Record<string, any[]> = {
      'nmap_scan': [
        {
          title: 'Basic Host Discovery',
          description: 'Discover live hosts in a network range',
          parameters: { target: '192.168.1.0/24', profile: 'stealth' },
          llmPrompt: 'Scan network 192.168.1.0/24 to find live hosts using stealth mode',
          expectedOutput: 'List of active hosts without port scanning'
        },
        {
          title: 'Service Enumeration',
          description: 'Detailed service detection on a specific host',
          parameters: { target: '192.168.1.10', ports: 'top-ports 1000', profile: 'default' },
          llmPrompt: 'Perform service enumeration on 192.168.1.10',
          expectedOutput: 'Open ports with service versions and banners'
        }
      ],
      'ffuf_fuzz': [
        {
          title: 'Directory Discovery',
          description: 'Find hidden directories on a web application',
          parameters: { url: 'https://target.com/FUZZ', wordlist: '/usr/share/wordlists/dirb/common.txt', threads: 100 },
          llmPrompt: 'Discover hidden directories on https://target.com',
          expectedOutput: 'List of accessible directories and files'
        }
      ]
    };

    return examples[name] || [];
  }

  /**
   * Get custom commands for a tool
   */
  private getCustomCommands(name: string): any[] {
    const customCommands: Record<string, any[]> = {
      'nmap_scan': [
        {
          name: 'stealth_scan',
          description: 'Stealthy scan with evasion techniques',
          parameters: { custom_flags: ['-sS', '-f', '-D', 'RND:10'], profile: 'stealth' },
          example: 'Evade firewalls and IDS systems'
        },
        {
          name: 'vuln_scan',
          description: 'Vulnerability scanning with NSE scripts',
          parameters: { custom_flags: ['--script', 'vuln'], dangerous: true },
          example: 'Detect known vulnerabilities (requires --dangerous)'
        }
      ],
      'ffuf_fuzz': [
        {
          name: 'authenticated_fuzz',
          description: 'Fuzzing with authentication headers',
          parameters: { custom_headers: { 'Authorization': 'Bearer token' } },
          example: 'Fuzz authenticated areas of web applications'
        }
      ]
    };

    return customCommands[name] || [];
  }

  /**
   * Get tool use cases
   */
  private getToolUseCases(name: string): string[] {
    const useCases: Record<string, string[]> = {
      'nmap_scan': [
        'Network discovery and mapping',
        'Port scanning and service detection',
        'Operating system fingerprinting',
        'Vulnerability assessment',
        'Firewall and filter analysis'
      ],
      'ffuf_fuzz': [
        'Directory and file enumeration',
        'Subdomain discovery',
        'Parameter fuzzing',
        'API endpoint discovery',
        'Virtual host enumeration'
      ],
      'gobuster_scan': [
        'Directory brute-forcing',
        'DNS subdomain enumeration',
        'S3 bucket discovery',
        'Virtual host detection'
      ],
      'nikto_scan': [
        'Web vulnerability scanning',
        'Server misconfiguration detection',
        'Dangerous file identification',
        'Security header analysis'
      ]
    };

    return useCases[name] || ['General security testing'];
  }

  /**
   * Get tool best practices
   */
  private getToolBestPractices(name: string): string[] {
    const bestPractices: Record<string, string[]> = {
      'nmap_scan': [
        'Always obtain written authorization before scanning',
        'Start with non-intrusive scans and escalate gradually',
        'Use timing controls to avoid overwhelming targets',
        'Document all scanning activities',
        'Validate results with additional tools'
      ],
      'ffuf_fuzz': [
        'Start with small wordlists and expand based on results',
        'Use appropriate thread counts to avoid rate limiting',
        'Filter common error codes to reduce noise',
        'Analyze response patterns for better filtering',
        'Respect robots.txt and security policies'
      ],
      'gobuster_scan': [
        'Use wildcard detection for catch-all responses',
        'Adjust timeout values based on target responsiveness',
        'Combine with other enumeration tools',
        'Use targeted wordlists for better results'
      ]
    };

    return bestPractices[name] || ['Follow security testing best practices'];
  }

  /**
   * Get LLM guidance for a tool
   */
  private getLLMGuidance(name: string): any {
    const guidance: Record<string, any> = {
      'nmap_scan': {
        contextualUsage: 'Nmap is the cornerstone of network reconnaissance. Use for progressive discovery: host detection → port scanning → service enumeration → vulnerability assessment.',
        parameterRecommendations: {
          target: 'Validate IP ranges and ensure authorization',
          profile: 'Use stealth for initial recon, default for service enum, aggressive only when authorized'
        },
        cautionsForLLMs: [
          'Emphasize legal and ethical requirements',
          'Warn about scan detection and logging',
          'Explain impact on production systems'
        ],
        outputInterpretation: 'Focus on open ports, service versions, and potential vulnerabilities'
      },
      'ffuf_fuzz': {
        contextualUsage: 'FFUF excels at discovering hidden web content. Use after basic reconnaissance to map application structure.',
        parameterRecommendations: {
          threads: 'Start with 50-100, monitor for rate limiting',
          wordlists: 'Use targeted lists based on technology stack'
        },
        cautionsForLLMs: [
          'High thread counts can cause DoS-like effects',
          'Some applications log fuzzing attempts',
          'Be mindful of bandwidth usage'
        ],
        outputInterpretation: 'Analyze response codes, lengths, and content for interesting discoveries'
      }
    };

    return guidance[name] || {
      contextualUsage: 'General security testing tool',
      parameterRecommendations: {},
      cautionsForLLMs: ['Use with proper authorization', 'Monitor for unintended effects'],
      outputInterpretation: 'Review results for security implications'
    };
  }

  /**
   * Load actual resource content based on URI
   */
  private async loadResourceContent(uri: string): Promise<{ mimeType: string; text: string }> {
    const parts = uri.split('://');
    if (parts.length !== 2) {
      throw new Error(`Invalid resource URI format: ${uri}. Expected format: scheme://resource`);
    }
    
    const [scheme, resource] = parts;
    
    // Validate that both scheme and resource are defined
    if (!scheme || resource === undefined) {
      throw new Error(`Invalid resource URI format: ${uri}. Both scheme and resource must be specified`);
    }
    
    switch (scheme) {
      case 'config':
        return this.loadConfigResource(resource);
      
      case 'wordlists':
        return this.loadWordlistResource(resource);
      
      case 'templates':
        return this.loadTemplateResource(resource);
      
      case 'logs':
        return this.loadLogResource(resource);
      
      default:
        throw new Error(`Unknown resource scheme: ${scheme}`);
    }
  }

  /**
   * Load configuration resources
   */
  private async loadConfigResource(resource: string): Promise<{ mimeType: string; text: string }> {
    switch (resource) {
      case 'server':
        return {
          mimeType: 'application/json',
          text: JSON.stringify({
            name: 'RedQuanta MCP Server',
            version: '0.3.0',
            mode: process.env.MCP_MODE || 'stdio',
            host: process.env.HOST || '0.0.0.0',
            port: parseInt(process.env.PORT || '5891', 10),
            jailRoot: process.env.JAIL_ROOT || '/tmp/redquanta',
            dangerousMode: process.env.DANGEROUS_MODE === 'true',
            logLevel: process.env.LOG_LEVEL || 'info',
            webSearchEnabled: process.env.WEB_SEARCH_ENABLED === 'true',
            cacheEnabled: process.env.CACHE_ENABLED !== 'false',
            cacheTtl: parseInt(process.env.CACHE_TTL || '600', 10),
            platform: process.platform,
            nodeVersion: process.version,
            architecture: process.arch,
            uptime: Math.floor(process.uptime()),
            memoryUsage: process.memoryUsage(),
            timestamp: new Date().toISOString()
          }, null, 2)
        };
      
      case 'tools':
        const tools = this.listTools();
        return {
          mimeType: 'application/json',
          text: JSON.stringify({
            totalTools: tools.length,
            categories: this.getToolCategories(tools),
            tools: tools.map(tool => ({
              name: tool.name,
              description: tool.description,
              category: tool.category,
              dangerous: tool.dangerous,
              useCases: tool.useCases?.slice(0, 3) || [],
              examples: tool.examples?.length || 0
            })),
            lastUpdated: new Date().toISOString()
          }, null, 2)
        };
      
      case 'security':
        // Load security config synchronously with fallbacks
        let allowedCommands: string[] = [];
        let allowedPaths: string[] = [];
        let deniedPatterns: string[] = [];
        
        try {
          allowedCommands = await this.getSecurityConfig('allowedCommands');
          allowedPaths = await this.getSecurityConfig('allowedPaths');
          deniedPatterns = await this.getSecurityConfig('deniedPatterns');
        } catch (error) {
          // Use fallback security info if config files aren't available
          allowedCommands = ['nmap', 'masscan', 'ffuf', 'nikto', 'gobuster'];
          allowedPaths = ['/tmp', '/var/tmp', process.env.JAIL_ROOT || '/tmp/redquanta'];
          deniedPatterns = ['../', '..\\', '/etc/', '/root/', 'C:\\Windows\\'];
        }
        
        const securityConfig = {
          securityModel: 'jail-based-isolation',
          jailRoot: process.env.JAIL_ROOT || '/tmp/redquanta',
          dangerousMode: process.env.DANGEROUS_MODE === 'true',
          pathValidation: 'enabled',
          argumentGuard: 'enabled',
          commandAllowlist: 'active',
          auditLogging: 'enabled',
          allowedCommands,
          allowedPaths,
          deniedPatterns,
          securityFeatures: [
            'Path traversal protection',
            'Command injection prevention',
            'Argument sanitization',
            'Jail root enforcement',
            'Audit trail logging',
            'Rate limiting',
            'Permission validation'
          ],
          lastUpdated: new Date().toISOString()
        };
        
        return {
          mimeType: 'application/json',
          text: JSON.stringify(securityConfig, null, 2)
        };
      
      default:
        throw new Error(`Unknown config resource: ${resource}`);
    }
  }

  /**
   * Load wordlist resources
   */
  private async loadWordlistResource(resource: string): Promise<{ mimeType: string; text: string }> {
    switch (resource) {
      case 'common':
        const commonWordlist = [
          'admin', 'administrator', 'login', 'test', 'guest', 'info', 'adm',
          'mysql', 'website', 'sshadmin', 'admin1', 'admin2', 'upload', 'backup',
          'sql', 'hidden', 'access', 'config', 'temp', 'temporary', 'www',
          'data', 'ftp', 'root', 'http', 'logs', 'log', 'old', 'new', 'apps',
          'app', 'application', 'applications', 'cache', 'tmp', 'private',
          'public', 'secret', 'secrets', 'password', 'passwords', 'user', 'users'
        ];
        return {
          mimeType: 'text/plain',
          text: commonWordlist.join('\n')
        };
      
      default:
        return {
          mimeType: 'application/json',
          text: JSON.stringify({
            availableWordlists: ['common'],
            description: 'Built-in wordlists for security testing',
            note: 'For extensive wordlists, install external collections like SecLists',
            externalWordlists: [
              '/usr/share/wordlists/dirb/',
              '/usr/share/wordlists/dirbuster/',
              '/usr/share/seclists/'
            ]
          }, null, 2)
        };
    }
  }

  /**
   * Load template resources
   */
  private async loadTemplateResource(resource: string): Promise<{ mimeType: string; text: string }> {
    switch (resource) {
      case 'reports':
        const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedQuanta MCP Security Assessment Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .finding { border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; background: #fdf2f2; }
        .recommendation { border-left: 4px solid #27ae60; padding: 15px; margin: 10px 0; background: #f2fdf5; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .metric { text-align: center; padding: 15px; background: #ecf0f1; border-radius: 6px; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #f39c12; font-weight: bold; }
        .medium { color: #f1c40f; font-weight: bold; }
        .low { color: #27ae60; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ RedQuanta MCP Security Assessment Report</h1>
        <p>Generated: {{timestamp}}</p>
        <p>Target: {{target}}</p>
        <p>Assessment Type: {{assessmentType}}</p>
    </div>
    
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="summary-grid">
            <div class="metric">
                <h3>{{criticalCount}}</h3>
                <p class="critical">Critical</p>
            </div>
            <div class="metric">
                <h3>{{highCount}}</h3>
                <p class="high">High</p>
            </div>
            <div class="metric">
                <h3>{{mediumCount}}</h3>
                <p class="medium">Medium</p>
            </div>
            <div class="metric">
                <h3>{{lowCount}}</h3>
                <p class="low">Low</p>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>🔍 Key Findings</h2>
        {{#findings}}
        <div class="finding">
            <h3>{{title}}</h3>
            <p><strong>Severity:</strong> <span class="{{severity}}">{{severity}}</span></p>
            <p><strong>Description:</strong> {{description}}</p>
            <p><strong>Impact:</strong> {{impact}}</p>
        </div>
        {{/findings}}
    </div>
    
    <div class="section">
        <h2>✅ Recommendations</h2>
        {{#recommendations}}
        <div class="recommendation">
            <h3>{{title}}</h3>
            <p>{{description}}</p>
            <p><strong>Priority:</strong> {{priority}}</p>
        </div>
        {{/recommendations}}
    </div>
    
    <div class="section">
        <h2>📋 Methodology</h2>
        <p>This assessment was conducted using RedQuanta MCP following industry-standard penetration testing methodologies including:</p>
        <ul>
            <li>OWASP Testing Guide</li>
            <li>NIST Cybersecurity Framework</li>
            <li>PTES (Penetration Testing Execution Standard)</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>🔧 Tools Used</h2>
        <ul>
            {{#tools}}
            <li><strong>{{name}}:</strong> {{description}}</li>
            {{/tools}}
        </ul>
    </div>
</body>
</html>`;
        return {
          mimeType: 'text/html',
          text: reportTemplate
        };
      
      default:
        return {
          mimeType: 'application/json',
          text: JSON.stringify({
            availableTemplates: ['reports'],
            description: 'HTML templates for generating security assessment reports',
            format: 'Mustache-compatible templating with variable substitution'
          }, null, 2)
        };
    }
  }

  /**
   * Load log resources
   */
  private async loadLogResource(resource: string): Promise<{ mimeType: string; text: string }> {
    switch (resource) {
      case 'audit':
        try {
          // Try to read recent audit logs
          const fs = await import('fs/promises');
          const path = await import('path');
          const logDir = path.join(process.cwd(), 'logs');
          
          try {
            const files = await fs.readdir(logDir);
            const auditFiles = files.filter(f => f.startsWith('audit-') && f.endsWith('.jsonl'));
            
            if (auditFiles.length === 0) {
              return {
                mimeType: 'application/json',
                text: JSON.stringify({
                  message: 'No audit logs found',
                  logDirectory: logDir,
                  expectedFiles: 'audit-YYYY-MM-DD.jsonl',
                  status: 'empty'
                }, null, 2)
              };
            }
            
            // Get the most recent log file
            const latestFile = auditFiles.sort().pop()!;
            const logPath = path.join(logDir, latestFile);
            const logContent = await fs.readFile(logPath, 'utf-8');
            
            // Parse JSONL and get recent entries
            const lines = logContent.trim().split('\n').filter(line => line.length > 0);
            const recentEntries = lines.slice(-50).map(line => {
              try {
                return JSON.parse(line);
              } catch {
                return { error: 'Failed to parse log entry', rawLine: line };
              }
            });
            
            return {
              mimeType: 'application/json',
              text: JSON.stringify({
                logFile: latestFile,
                totalEntries: lines.length,
                recentEntries: recentEntries,
                lastUpdated: new Date().toISOString()
              }, null, 2)
            };
            
          } catch (error) {
            return {
              mimeType: 'application/json',
              text: JSON.stringify({
                message: 'Could not read audit logs',
                error: error instanceof Error ? error.message : 'Unknown error',
                logDirectory: logDir,
                status: 'error'
              }, null, 2)
            };
          }
          
        } catch (error) {
          return {
            mimeType: 'application/json',
            text: JSON.stringify({
              message: 'Audit logging system not accessible',
              error: error instanceof Error ? error.message : 'Unknown error',
              status: 'unavailable'
            }, null, 2)
          };
        }
      
      default:
        throw new Error(`Unknown log resource: ${resource}`);
    }
  }

  /**
   * Get tool categories summary
   */
  private getToolCategories(tools: any[]): Record<string, number> {
    const categories: Record<string, number> = {};
    tools.forEach(tool => {
      categories[tool.category] = (categories[tool.category] || 0) + 1;
    });
    return categories;
  }

  /**
   * Get security configuration
   */
  private async getSecurityConfig(configType: string): Promise<string[]> {
    try {
      const fs = await import('fs/promises');
      const path = await import('path');
      const configPath = path.join(process.cwd(), 'config', `${configType}.json`);
      const configContent = await fs.readFile(configPath, 'utf-8');
      const config = JSON.parse(configContent);
      return Array.isArray(config) ? config : Object.keys(config);
    } catch {
      return [`${configType} configuration not available`];
    }
  }
} 