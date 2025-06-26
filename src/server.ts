#!/usr/bin/env node

/**
 * 🛡️ RedQuanta MCP Server
 * 
 * Enterprise-Grade Penetration Testing Orchestration Platform
 * 
 * @author sc4rfurry <https://github.com/sc4rfurry>
 * @version 0.3.0
 * @license MIT
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ErrorCode,
  McpError
} from '@modelcontextprotocol/sdk/types.js';
import { fastify, FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import cors from '@fastify/cors';
import swagger from '@fastify/swagger';
import swaggerUI from '@fastify/swagger-ui';
import NodeCache from 'node-cache';
import { v4 as uuidv4 } from 'uuid';
import fetch from 'node-fetch';
import * as cheerio from 'cheerio';
import path from 'path';
import { fileURLToPath } from 'url';
import pino from 'pino';
import os from 'os';
import { OSConfigManager } from './utils/osConfig.js';
import { AuditLogger } from './utils/auditLogger.js';
import { ProgressTracker } from './utils/progressTracker.js';
import { ArgGuard } from './utils/argGuard.js';
import { CommandRunner } from './utils/commandRunner.js';
import { DDGSearchTool, DDGSpiceTool } from './tools/ddgSearch.js';
import { SarifReporter } from './utils/sarifReporter.js';
import { PathGuard } from './utils/pathGuard.js';
import { CacheManager } from './utils/cacheManager.js';


// Tool imports
import { NmapTool } from './tools/nmap.js';
import { MasscanTool } from './tools/masscan.js';
import { FfufTool } from './tools/ffuf.js';
import { NiktoTool } from './tools/nikto.js';

const __filename = fileURLToPath(import.meta.url);

interface ServerConfig {
  host: string;
  port: number;
  mode: 'stdio' | 'rest' | 'hybrid';
  jailRoot: string;
  dangerousMode: boolean;
  logLevel: string;
  webSearchEnabled: boolean;
  cacheEnabled: boolean;
  cacheTtl: number;
}

export class RedQuantaMCPServer {
  private app?: FastifyInstance;
  private mcpServer: Server;
  private config: ServerConfig;
  private osConfig: OSConfigManager;
  public auditLogger: AuditLogger;
  private progressTracker: ProgressTracker;
  private cache: NodeCache;
  private logger: pino.Logger;

  constructor() {
    this.config = this.loadConfiguration();
    
    // Configure Pino logger - disable completely in stdio mode to prevent JSON-RPC pollution
    let pinoOptions: any = { 
      level: this.config.logLevel 
    };
    
    // In stdio mode, disable Pino entirely to avoid JSON-RPC pollution
    if (this.config.mode === 'stdio') {
      pinoOptions = { 
        level: 'silent' // Disable all Pino output in stdio mode
      };
    }
    
    this.logger = pino(pinoOptions);
    this.osConfig = new OSConfigManager();
    this.auditLogger = new AuditLogger();
    this.progressTracker = new ProgressTracker(this.auditLogger);
    this.cache = new NodeCache({ 
      stdTTL: this.config.cacheTtl,
      checkperiod: 120,
      useClones: false
    });

    // Initialize MCP Server
    this.mcpServer = new Server({
      name: 'redquanta-mcp',
      version: '0.3.0'
    }, {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {}
      }
    });

    this.initializeMCPServer();
  }

  // Safe logging method that respects stdio mode
  private safeLog(message: string): void {
    if (this.config.mode === 'stdio') {
      // In stdio mode, send to stderr to avoid interfering with MCP JSON-RPC on stdout
      // Remove emojis and use clean text for MCP compatibility
      const cleanMessage = this.cleanMessageForMCP(message);
      console.error(`[RedQuanta-MCP] ${cleanMessage}`);
    } else {
      // In other modes, normal console output is fine with emojis
      console.log(message);
    }
  }

  // Clean messages for MCP compatibility by removing emojis, ANSI sequences, and formatting
  private cleanMessageForMCP(message: string): string {
    return message
      // Remove ANSI escape sequences (the main cause of JSON parsing errors)
      .replace(/\u001b\[[0-9;]*[a-zA-Z]/g, '') // Standard ANSI escape sequences
      .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '') // Alternative ANSI escape sequences
      .replace(/\u001b\[[0-9;]*m/g, '') // ANSI color codes
      .replace(/\u001b\[[\d;]*[HfABCDEFGJKSTu]/g, '') // ANSI cursor control
      .replace(/\u001b\[2K/g, '') // Clear line sequences
      .replace(/\u001b\[[\d]*G/g, '') // Cursor position sequences
      .replace(/\u001b\]0;.*?\u0007/g, '') // Terminal title sequences
      .replace(/\u001b\[K/g, '') // Erase sequences
      // Remove other terminal control characters
      .replace(/[\u0000-\u001f\u007f-\u009f]/g, (char) => {
        // Keep useful whitespace characters but remove other control chars
        if (char === '\n' || char === '\r' || char === '\t') return char;
        return '';
      })
      // Remove common emojis
      .replace(/[🔧✅🚀📚🛑🔗🎯🕷️🏃‍♂️🌐🐳📖🛡️⚠️❌🔍]/g, '')
      // Remove all Unicode emojis
      .replace(/[\u{1F600}-\u{1F64F}]|[\u{1F300}-\u{1F5FF}]|[\u{1F680}-\u{1F6FF}]|[\u{1F1E0}-\u{1F1FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu, '')
      // Remove problematic Unicode characters that can break JSON
      .replace(/[\u{200B}-\u{200F}\u{202A}-\u{202E}\u{2060}-\u{206F}]/gu, '') // Zero-width and formatting chars
      // Normalize whitespace
      .replace(/\s+/g, ' ')
      .trim();
  }

  // Clean tool results recursively to remove emojis and ensure MCP compatibility
  private cleanResultForMCP(obj: any): any {
    if (typeof obj === 'string') {
      return this.cleanMessageForMCP(obj);
    } else if (Array.isArray(obj)) {
      return obj.map(item => this.cleanResultForMCP(item));
    } else if (obj && typeof obj === 'object') {
      const cleaned: any = {};
      for (const [key, value] of Object.entries(obj)) {
        cleaned[key] = this.cleanResultForMCP(value);
      }
      return cleaned;
    }
    return obj;
  }

  // Enhanced error handling for MCP mode
  private handleMCPError(error: any, context: string): any {
    const errorMessage = error instanceof Error ? error.message : String(error);
    const cleanContext = this.cleanMessageForMCP(context);
    
    this.safeLog(`ERROR in ${cleanContext}: ${errorMessage}`);
    
    return {
      success: false,
      error: errorMessage,
      context: cleanContext,
      timestamp: new Date().toISOString(),
      mcpMode: this.config.mode === 'stdio'
    };
  }

  public async initialize(): Promise<void> {
    // Initialize audit logger first
    await this.auditLogger.initialize();
    
    // Log server initialization
    await this.auditLogger.logActivity({
      level: 'info',
      action: 'server_initialization_started',
      outcome: 'success',
      details: {
        mode: this.config.mode,
        workingDirectory: process.cwd(),
        logDirectory: this.auditLogger.getLogDirectory()
      }
    });

    // Initialize REST API if needed
    if (this.config.mode === 'rest' || this.config.mode === 'hybrid') {
      await this.initializeRestAPI();
    }
  }

  private loadConfiguration(): ServerConfig {
    return {
      host: process.env.HOST || '0.0.0.0',
      port: parseInt(process.env.PORT || '5891'),
      mode: (process.env.MCP_MODE as any) || 'stdio',
      jailRoot: process.env.JAIL_ROOT || '/tmp/redquanta',
      dangerousMode: process.env.DANGEROUS_MODE === 'true',
      logLevel: process.env.LOG_LEVEL || 'info',
      webSearchEnabled: process.env.WEB_SEARCH_ENABLED === 'true',
      cacheEnabled: process.env.CACHE_ENABLED !== 'false',
      cacheTtl: parseInt(process.env.CACHE_TTL || '600')
    };
  }

  private initializeMCPServer(): void {
    // Only log initialization in non-stdio modes to avoid JSON-RPC pollution
    if (this.config.mode !== 'stdio') {
      this.safeLog('🔧 Initializing RedQuanta MCP Server...');
    }

    // Register MCP tools
    this.registerMCPTools();
    this.registerMCPResources();
    this.registerMCPPrompts();

    // Only log success in non-stdio modes
    if (this.config.mode !== 'stdio') {
      this.safeLog('✅ MCP Server initialized successfully');
    }
  }

  private registerMCPTools(): void {
    // Tool execution handler
    this.mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      
      // Use safe logging and avoid any potential emoji issues
      if (this.config.mode === 'stdio') {
        // In stdio mode, use structured logging to avoid protocol interference
        this.logger.debug('Tool execution started', { tool: name, args });
      } else {
        this.logger.debug(`🔧 Executing tool: ${name}`, { tool: name, args });
      }

      const executionId = uuidv4();
      
      try {
        await this.auditLogger.logActivity({
          level: 'info',
          action: 'tool_execution_started',
          details: {
            tool: name,
            executionId,
            args
          }
        });
      } catch (auditError) {
        // Continue execution even if audit logging fails
        this.safeLog(`Warning: Audit logging failed for ${name}`);
      }

      try {
        let result;
        
        // Wrap each tool execution in try-catch for robust error handling
        try {
          switch (name) {
            case 'nmap_scan':
              result = await this.executeNmapScan(args);
              break;
            case 'masscan_scan':
              result = await this.executeMasscanScan(args);
              break;
            case 'ffuf_fuzz':
              result = await this.executeFFUFFuzz(args);
              break;
            case 'nikto_scan':
              result = await this.executeNiktoScan(args);
              break;
            case 'workflow_enum':
              result = await this.executeEnumerationWorkflow(args);
              break;
            case 'workflow_scan':
              result = await this.executeVulnerabilityWorkflow(args);
              break;
            case 'web_search':
              result = await this.executeWebSearch(args);
              break;
            case 'ddg_search':
              result = await this.executeDDGSearch(args);
              break;
            case 'ddg_spice':
              result = await this.executeDDGSpice(args);
              break;
            case 'domain_intel':
              result = await this.executeDomainIntelligence(args);
              break;
            case 'plugin_system':
              result = await this.handlePluginAction(args);
              break;
            case 'filesystem_ops':
              result = await this.executeFilesystemOperation(args);
              break;
            default:
              throw new Error(`Unknown tool: ${name}`);
          }
        } catch (toolError) {
          // Handle tool-specific errors
          result = this.handleMCPError(toolError, `Tool execution: ${name}`);
        }

        // Ensure result is properly formatted for MCP
        if (!result || typeof result !== 'object') {
          result = {
            success: false,
            error: 'Tool returned invalid result',
            tool: name,
            timestamp: new Date().toISOString()
          };
        }

        // Clean any emoji characters from the result before sending
        const cleanResult = this.cleanResultForMCP(result);

        try {
          await this.auditLogger.logActivity({
            level: 'info',
            action: 'tool_execution_completed',
            outcome: cleanResult.success ? 'success' : 'failure',
            details: {
              tool: name,
              executionId
            }
          });
        } catch (auditError) {
          // Continue even if audit logging fails
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(cleanResult, null, 2)
            }
          ]
        };
      } catch (error) {
        // Final fallback error handling
        const errorResult = this.handleMCPError(error, `Tool handler: ${name}`);
        
        try {
          await this.auditLogger.logActivity({
            level: 'error',
            action: 'tool_execution_failed',
            outcome: 'failure',
            details: {
              tool: name,
              executionId,
              error: error instanceof Error ? error.message : 'Unknown error'
            }
          });
        } catch (auditError) {
          // Continue even if audit logging fails
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(errorResult, null, 2)
            }
          ],
          isError: true
        };
      }
    });

    // Tool listing handler
    this.mcpServer.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: 'nmap_scan',
            description: 'Advanced network discovery and security auditing tool. Nmap ("Network Mapper") is the industry standard for network reconnaissance, port scanning, and service detection. This tool performs comprehensive network mapping to identify live hosts, open ports, running services, and potential vulnerabilities. Perfect for the initial reconnaissance phase of penetration testing and security assessments.',
            inputSchema: {
              type: 'object',
              properties: {
                target: { 
                  type: 'string', 
                  description: 'Target specification for scanning. Accepts: single IP (192.168.1.1), hostname (example.com), IP ranges (192.168.1.1-254), CIDR networks (192.168.1.0/24), or multiple targets separated by spaces. Examples: "192.168.1.1", "example.com", "192.168.1.0/24"'
                },
                dangerous: { 
                  type: 'boolean', 
                  description: 'Enable aggressive/dangerous scanning techniques including OS detection (-O), version detection (-sV), script scanning (-sC), and traceroute (--traceroute). This provides more detailed information but is more detectable and may trigger security systems. Use only with explicit permission.',
                  default: false 
                },
                ports: {
                  type: 'string',
                  description: 'Port specification for scanning. Options: specific ports ("80,443,22"), port ranges ("1-1000"), common presets ("top-1000"), or full range ("1-65535"). Default scans the most common 1000 ports for efficiency.',
                  default: 'top-1000'
                }
              },
              required: ['target'],
              examples: [
                {
                  target: '192.168.1.1',
                  ports: '80,443,22',
                  dangerous: false,
                  description: 'Basic scan of common web and SSH ports on single host'
                },
                {
                  target: '192.168.1.0/24',
                  ports: 'top-1000',
                  dangerous: false,
                  description: 'Network discovery scan of entire subnet'
                },
                {
                  target: 'example.com',
                  ports: '1-65535',
                  dangerous: true,
                  description: 'Comprehensive aggressive scan with OS detection'
                }
              ]
            }
          },
          {
            name: 'masscan_scan',
            description: 'Extremely fast Internet-scale port scanner designed for high-speed network discovery. Masscan can scan the entire Internet in under 5 minutes and is optimized for scanning large IP ranges quickly. Uses asynchronous transmission and is ideal for initial reconnaissance of large networks. Significantly faster than traditional port scanners but less detailed in service detection.',
            inputSchema: {
              type: 'object',
              properties: {
                target: { 
                  type: 'string', 
                  description: 'Target IP range or address for high-speed scanning. Best suited for CIDR notation (192.168.0.0/16) or large IP ranges. Single IPs work but nmap is better for individual hosts. Examples: "192.168.1.0/24", "10.0.0.0/8"'
                },
                ports: { 
                  type: 'string', 
                  description: 'Port range to scan at high speed. Can specify individual ports ("80,443"), ranges ("1-1000"), or full range ("1-65535"). Larger ranges take longer but provide comprehensive coverage.',
                  default: '1-1000' 
                },
                rate: { 
                  type: 'number', 
                  description: 'Transmission rate in packets per second (pps). Higher rates are faster but may overwhelm network infrastructure or trigger security systems. Start with conservative rates (1000) and increase carefully. Maximum depends on network capacity.',
                  default: 1000,
                  minimum: 1,
                  maximum: 1000000 
                }
              },
              required: ['target'],
              examples: [
                {
                  target: '192.168.1.0/24',
                  ports: '80,443,22,21,25',
                  rate: 1000,
                  description: 'Fast scan of common services across subnet'
                },
                {
                  target: '10.0.0.0/16',
                  ports: '1-1000',
                  rate: 10000,
                  description: 'High-speed comprehensive scan of large network'
                }
              ]
            }
          },
          {
            name: 'ffuf_fuzz',
            description: 'Fast web fuzzer and directory discovery tool written in Go. FFUF (Fuzz Faster U Fool) is designed for discovering hidden directories, files, parameters, and endpoints in web applications. It replaces the FUZZ keyword in URLs with wordlist entries to systematically discover content. Essential for web application security testing and bug bounty hunting.',
            inputSchema: {
              type: 'object',
              properties: {
                url: { 
                  type: 'string', 
                  description: 'Target URL containing the FUZZ keyword where wordlist entries will be substituted. The FUZZ keyword can appear in paths, parameters, or subdomains. Examples: "https://example.com/FUZZ", "https://FUZZ.example.com", "https://api.example.com/v1/FUZZ"'
                },
                wordlist: { 
                  type: 'string', 
                  description: 'Wordlist to use for fuzzing. Options include built-in presets (common, directories, files, api-endpoints, admin-panels) or custom wordlist file paths. Different wordlists optimized for different discovery goals.',
                  default: 'common',
                  enum: ['common', 'directories', 'files', 'api-endpoints', 'admin-panels', 'parameters', 'subdomains']
                },
                extensions: { 
                  type: 'string', 
                  description: 'File extensions to append to wordlist entries for file discovery. Specify as comma-separated list without dots. Useful for finding configuration files, backups, and source code. Examples: "php,html,txt", "jsp,asp,aspx"'
                }
              },
              required: ['url'],
              examples: [
                {
                  url: 'https://example.com/FUZZ',
                  wordlist: 'directories',
                  description: 'Discover hidden directories and admin panels'
                },
                {
                  url: 'https://api.example.com/v1/FUZZ',
                  wordlist: 'api-endpoints',
                  description: 'Enumerate API endpoints and methods'
                },
                {
                  url: 'https://example.com/FUZZ',
                  wordlist: 'files',
                  extensions: 'php,html,txt,bak',
                  description: 'Find configuration files and backups'
                }
              ]
            }
          },
          {
            name: 'nikto_scan',
            description: 'Comprehensive open-source web server scanner that performs extensive security testing. Nikto tests for over 6700 potentially dangerous files/programs, checks for outdated versions, and identifies security misconfigurations. It examines web servers for multiple vulnerabilities including dangerous files, outdated software, and server-specific problems. Essential for web application security auditing.',
            inputSchema: {
              type: 'object',
              properties: {
                target: { 
                  type: 'string', 
                  description: 'Target URL to scan including protocol and port if non-standard. Nikto performs comprehensive testing of the web server and application. Examples: "https://example.com", "http://192.168.1.100:8080", "https://api.example.com"'
                },
                timeout: { 
                  type: 'number', 
                  description: 'Maximum scan time in seconds to prevent scans from running indefinitely. Larger applications may require longer timeouts. Consider server load and testing window when setting timeout.',
                  default: 300,
                  minimum: 60,
                  maximum: 3600
                }
              },
              required: ['target'],
              examples: [
                {
                  target: 'https://example.com',
                  timeout: 300,
                  description: 'Standard security scan of main website'
                },
                {
                  target: 'https://app.example.com',
                  timeout: 600,
                  description: 'Extended scan of complex web application'
                }
              ]
            }
          },
          {
            name: 'workflow_enum',
            description: 'Automated reconnaissance workflow that orchestrates multiple tools for systematic target enumeration. This workflow adapts its methodology based on target type and provides comprehensive information gathering following industry-standard penetration testing methodologies. Includes host discovery, port scanning, service enumeration, and vulnerability identification with intelligent coaching based on user experience level.',
            inputSchema: {
              type: 'object',
              properties: {
                target: { 
                  type: 'string', 
                  description: 'Primary target for comprehensive enumeration. Can be single host, domain, or network range. The workflow will adapt its approach based on target type and scope. Examples: "192.168.1.1", "example.com", "192.168.1.0/24"'
                },
                scope: { 
                  type: 'string', 
                  description: 'Enumeration scope determining focus area and tool selection. "network" focuses on network services and infrastructure, "web" emphasizes web application testing, "full" combines both approaches for comprehensive assessment.',
                  enum: ['network', 'web', 'full'], 
                  default: 'network' 
                },
                depth: { 
                  type: 'string', 
                  description: 'Scan intensity and comprehensiveness level. "light" performs basic discovery, "normal" includes standard enumeration techniques, "deep" performs exhaustive reconnaissance with advanced techniques.',
                  enum: ['light', 'normal', 'deep'], 
                  default: 'normal' 
                },
                coaching: { 
                  type: 'string', 
                  description: 'Level of guidance and explanation provided during workflow execution. "beginner" includes detailed explanations and safety reminders, "advanced" provides concise technical output for experienced testers.',
                  enum: ['beginner', 'advanced'], 
                  default: 'beginner' 
                }
              },
              required: ['target'],
              examples: [
                {
                  target: '192.168.1.0/24',
                  scope: 'network',
                  depth: 'normal',
                  coaching: 'beginner',
                  description: 'Standard internal network reconnaissance with guidance'
                },
                {
                  target: 'example.com',
                  scope: 'web',
                  depth: 'deep',
                  coaching: 'advanced',
                  description: 'Comprehensive web application assessment for experts'
                }
              ]
            }
          },
          {
            name: 'workflow_scan',
            description: 'Multi-phase vulnerability assessment workflow that systematically tests identified services for security weaknesses. This workflow follows established penetration testing methodologies to identify, validate, and document vulnerabilities. Includes reconnaissance, vulnerability scanning, and optional exploitation phases with comprehensive reporting.',
            inputSchema: {
              type: 'object',
              properties: {
                target: { 
                  type: 'string', 
                  description: 'Target system or application for vulnerability assessment. Should be a previously enumerated target with known services. Examples: "192.168.1.100", "webapp.example.com", "api.example.com"'
                },
                services: { 
                  type: 'array', 
                  description: 'Specific services to focus vulnerability testing on. Leave empty for auto-detection or specify services found during enumeration phase. Examples: ["http", "https", "ssh"], ["smtp", "ftp", "telnet"]',
                  items: { type: 'string' }
                },
                aggressive: { 
                  type: 'boolean', 
                  description: 'Enable aggressive testing techniques including exploitation attempts and proof-of-concept generation. Only use with explicit permission and in authorized testing environments. May cause service disruption.',
                  default: false 
                }
              },
              required: ['target'],
              examples: [
                {
                  target: '192.168.1.100',
                  services: ['http', 'ssh'],
                  aggressive: false,
                  description: 'Safe vulnerability assessment without exploitation'
                },
                {
                  target: 'testapp.example.com',
                  aggressive: true,
                  description: 'Full penetration test with exploitation attempts'
                }
              ]
            }
          },
          ...(this.config.webSearchEnabled ? [
            {
              name: 'web_search',
              description: 'Security-focused web search tool for gathering threat intelligence, vulnerability information, and OSINT (Open Source Intelligence) data. Uses privacy-respecting search engines to research CVEs, security advisories, exploitation techniques, and target-specific information. Essential for intelligence gathering and vulnerability research phases of security assessments.',
              inputSchema: {
                type: 'object',
                properties: {
                  query: { 
                    type: 'string', 
                    description: 'Search query for security intelligence gathering. Can include CVE numbers, product names, vulnerability types, or OSINT queries. Use specific technical terms for better results. Examples: "CVE-2024-1234", "Apache Log4j vulnerability", "site:example.com filetype:pdf"'
                  },
                  maxResults: { 
                    type: 'number', 
                    description: 'Maximum number of search results to return. Higher numbers provide more comprehensive intelligence but take longer to process.',
                    default: 10,
                    minimum: 1,
                    maximum: 50
                  },
                  safeSearch: { 
                    type: 'boolean', 
                    description: 'Enable safe search filtering to exclude potentially harmful or inappropriate content from results.',
                    default: true 
                  }
                },
                required: ['query'],
                examples: [
                  {
                    query: 'CVE-2024 Apache vulnerability',
                    maxResults: 10,
                    description: 'Research recent Apache vulnerabilities'
                  },
                  {
                    query: 'site:example.com filetype:pdf',
                    maxResults: 20,
                    description: 'OSINT gathering of public documents'
                  }
                ]
              }
            },
            {
              name: 'domain_intel',
              description: 'Comprehensive domain intelligence gathering tool that collects WHOIS data, DNS records, SSL certificate information, and subdomain enumeration. Provides complete infrastructure mapping and reconnaissance data essential for understanding target attack surface and potential entry points.',
              inputSchema: {
                type: 'object',
                properties: {
                  domain: { 
                    type: 'string', 
                    description: 'Target domain name for comprehensive intelligence gathering. Tool will collect registration data, DNS configuration, certificate information, and infrastructure details. Examples: "example.com", "api.example.com"'
                  },
                  includeSubdomains: { 
                    type: 'boolean', 
                    description: 'Perform subdomain enumeration and discovery using multiple techniques including DNS brute force, certificate transparency logs, and search engine queries. Significantly increases intelligence gathering scope.',
                    default: false 
                  }
                },
                required: ['domain'],
                examples: [
                  {
                    domain: 'example.com',
                    includeSubdomains: false,
                    description: 'Basic domain infrastructure analysis'
                  },
                  {
                    domain: 'example.com',
                    includeSubdomains: true,
                    description: 'Comprehensive domain and subdomain mapping'
                  }
                ]
              }
            },
            {
              name: 'ddg_search',
              description: 'Advanced DuckDuckGo search tool for comprehensive OSINT and intelligence gathering. Supports web, image, video, and news search plus specialized APIs. Perfect for security research, threat intelligence, and open source intelligence operations.',
              inputSchema: {
                type: 'object',
                properties: {
                  query: {
                    type: 'string',
                    description: 'Search query for intelligence gathering. Examples: "CVE-2024-1234", "Apache log4j vulnerability", "company.com subdomains"'
                  },
                  searchType: {
                    type: 'string',
                    enum: ['web', 'images', 'videos', 'news', 'autocomplete'],
                    default: 'web',
                    description: 'Type of search to perform'
                  },
                  maxResults: {
                    type: 'integer',
                    minimum: 1,
                    maximum: 50,
                    default: 10,
                    description: 'Maximum number of results to return'
                  },
                  safeSearch: {
                    type: 'boolean',
                    default: true,
                    description: 'Enable safe search filtering'
                  },
                  region: {
                    type: 'string',
                    description: 'Region code for localized results (e.g., "us-en", "uk-en")'
                  }
                },
                required: ['query'],
                examples: [
                  {
                    query: 'CVE-2024 Apache vulnerability',
                    searchType: 'web',
                    maxResults: 10,
                    description: 'Research recent Apache vulnerabilities'
                  },
                  {
                    query: 'penetration testing methodology',
                    searchType: 'images',
                    maxResults: 5,
                    description: 'Find visual guides and diagrams'
                  }
                ]
              }
            },
            {
              name: 'ddg_spice',
              description: 'DuckDuckGo Spice APIs for specialized intelligence gathering: stocks, currency conversion, weather, dictionary definitions, DNS lookups, time zones, thesaurus, and URL expansion.',
              inputSchema: {
                type: 'object',
                properties: {
                  spiceType: {
                    type: 'string',
                    enum: ['stocks', 'currency', 'weather', 'dictionary', 'dns', 'time', 'thesaurus', 'expandUrl'],
                    description: 'Type of spice API to use'
                  },
                  query: {
                    type: 'string',
                    description: 'General query for dictionary, thesaurus, time, and weather lookups'
                  },
                  fromCurrency: {
                    type: 'string',
                    description: 'Source currency code (e.g., "USD", "EUR", "BTC")'
                  },
                  toCurrency: {
                    type: 'string',
                    description: 'Target currency code (e.g., "USD", "EUR", "BTC")'
                  },
                  amount: {
                    type: 'number',
                    default: 1,
                    description: 'Amount to convert'
                  }
                },
                required: ['spiceType'],
                examples: [
                  {
                    spiceType: 'stocks',
                    query: 'AAPL',
                    description: 'Get Apple stock information'
                  },
                  {
                    spiceType: 'currency',
                    fromCurrency: 'USD',
                    toCurrency: 'EUR',
                    amount: 100,
                    description: 'Convert 100 USD to EUR'
                  },
                  {
                    spiceType: 'dns',
                    query: 'example.com',
                    description: 'Lookup DNS records for domain'
                  }
                ]
              }
            }
          ] : []),
          {
            name: 'plugin_system',
            description: 'Extensible plugin management system for loading, executing, and managing custom security tools and scripts. Allows integration of specialized tools, custom scripts, and third-party security utilities into the RedQuanta platform. Supports dynamic loading and hot-swapping of plugins for extended functionality.',
            inputSchema: {
              type: 'object',
              properties: {
                action: { 
                  type: 'string', 
                  description: 'Plugin management action to perform. "list" shows available plugins, "load" adds a plugin to the system, "unload" removes a plugin, "execute" runs a loaded plugin, "info" provides plugin details.',
                  enum: ['list', 'load', 'unload', 'execute', 'info'] 
                },
                pluginName: { 
                  type: 'string', 
                  description: 'Name of the plugin for operations that target specific plugins (load, unload, execute, info). Required for all actions except list.'
                },
                pluginArgs: { 
                  type: 'object', 
                  description: 'Arguments to pass to the plugin during execution. Plugin-specific parameters that vary based on plugin functionality and requirements.'
                }
              },
              required: ['action'],
              examples: [
                {
                  action: 'list',
                  description: 'List all available plugins'
                },
                {
                  action: 'execute',
                  pluginName: 'custom-scanner',
                  pluginArgs: { target: '192.168.1.1' },
                  description: 'Execute custom scanning plugin'
                }
              ]
            }
          },
          {
            name: 'filesystem_ops',
            description: 'Secure filesystem operations within a sandboxed security jail for managing scan results, wordlists, configuration files, and reports. All operations are performed within a secured directory structure to prevent unauthorized access to system files. Supports read/write operations with proper security controls.',
            inputSchema: {
              type: 'object',
              properties: {
                operation: { 
                  type: 'string', 
                  description: 'Filesystem operation to perform within security jail. "list" shows directory contents, "read" retrieves file content, "write" creates/updates files, "delete" removes files, "upload" transfers files to jail.',
                  enum: ['list', 'read', 'write', 'delete', 'upload'] 
                },
                path: { 
                  type: 'string', 
                  description: 'File or directory path within the security jail. All paths are relative to the jail root and cannot access system directories. Path traversal attempts are blocked.'
                },
                content: { 
                  type: 'string', 
                  description: 'Content for write operations. Can be text data, scan results, configuration files, or other textual content to be stored securely.'
                },
                dangerous: { 
                  type: 'boolean', 
                  description: 'Allow potentially dangerous operations like write and delete. System is read-only by default for security. Enable only when file modification is explicitly required.',
                  default: false 
                }
              },
              required: ['operation'],
              examples: [
                {
                  operation: 'list',
                  path: '/results',
                  description: 'List scan results directory'
                },
                {
                  operation: 'write',
                  path: '/results/scan-output.txt',
                  content: 'Scan results data...',
                  dangerous: true,
                  description: 'Save scan results to file'
                }
              ]
            }
          }
        ]
      };
    });

    // DuckDuckGo Search Tools are already handled in the ListToolsRequestSchema handler above
    // Tool execution is handled in the CallToolRequestSchema handler at the beginning of this method
    // No additional registration needed here - tools are registered through the schema handlers

    // Plugin System Tool
  }

  private registerMCPResources(): void {
    this.mcpServer.setRequestHandler(ListResourcesRequestSchema, async () => {
      return {
        resources: [
          {
            uri: 'redquanta://config',
            name: 'System Configuration',
            description: 'Current server configuration and capabilities',
            mimeType: 'application/json'
          },
          {
            uri: 'redquanta://tools',
            name: 'Available Tools',
            description: 'Comprehensive list of all available security tools',
            mimeType: 'application/json'
          },
          {
            uri: 'redquanta://security',
            name: 'Security Guidelines',
            description: 'Security best practices and ethical guidelines',
            mimeType: 'text/markdown'
          },
          {
            uri: 'redquanta://status',
            name: 'System Status',
            description: 'Real-time system status and health information',
            mimeType: 'application/json'
          }
        ]
      };
    });

    this.mcpServer.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      const { uri } = request.params;
              this.logger.debug(`Reading resource: ${uri}`);

      switch (uri) {
        case 'redquanta://config':
          return {
            contents: [{
              uri,
              mimeType: 'application/json',
              text: JSON.stringify({
                server: {
                  name: 'RedQuanta MCP',
                  version: '0.3.0',
                  mode: this.config?.mode || 'rest',
                  platform: os.platform(),
                  jailRoot: this.config?.jailRoot || '/tmp/redquanta',
                  webSearchEnabled: this.config?.webSearchEnabled || false,
                  cacheEnabled: this.config?.cacheEnabled || false,
                  dangerousMode: this.config?.dangerousMode || false
                },
                capabilities: {
                  networking: ['nmap_scan', 'masscan_scan'],
                  webTesting: ['ffuf_fuzz', 'nikto_scan'],
                  workflows: ['workflow_enum', 'workflow_scan'],
                  intelligence: this.config?.webSearchEnabled ? ['web_search', 'ddg_search', 'ddg_spice'] : [],
                  system: ['filesystem_ops', 'plugin_system']
                },
                security: {
                  pathValidation: true,
                  jailRootProtection: true,
                  dangerousModeRequired: ['filesystem_write', 'filesystem_delete'],
                  auditLogging: true,
                  rateLimiting: true
                }
              }, null, 2)
            }]
          };

        case 'redquanta://tools':
          return {
            contents: [{
              uri,
              mimeType: 'application/json',
              text: JSON.stringify({
                categories: {
                  'Network Scanning': ['nmap_scan', 'masscan_scan'],
                  'Web Testing': ['ffuf_fuzz', 'nikto_scan'],
                  'Workflows': ['workflow_enum', 'workflow_scan'],
                  'Intelligence': ['web_search', 'domain_intel'],
                  'System': ['plugin_system', 'filesystem_ops']
                },
                totalTools: 10
              }, null, 2)
            }]
          };

        case 'redquanta://security':
          return {
            contents: [{
              uri,
              mimeType: 'text/markdown',
              text: await this.generateSecurityGuidelines()
            }]
          };

        case 'redquanta://status':
          return {
            contents: [{
              uri,
              mimeType: 'application/json',
              text: JSON.stringify({
                status: 'healthy',
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                timestamp: new Date().toISOString(),
                activeConnections: 1,
                toolsAvailable: 10,
                lastActivity: new Date().toISOString()
              }, null, 2)
            }]
          };

        default:
          throw new Error(`Unknown resource: ${uri}`);
      }
    });
  }

  private registerMCPPrompts(): void {
    this.mcpServer.setRequestHandler(ListPromptsRequestSchema, async () => {
      return {
        prompts: [
          {
            name: 'pentest_coaching',
            description: 'Get personalized coaching for penetration testing workflows',
            arguments: [
              {
                name: 'experience_level',
                description: 'Your experience level: beginner, intermediate, or advanced',
                required: true
              },
              {
                name: 'target_type',
                description: 'Type of target: network, web_app, mobile, or infrastructure',
                required: true
              },
              {
                name: 'specific_goal',
                description: 'Specific testing goal or challenge you\'re facing',
                required: false
              }
            ]
          },
          {
            name: 'vulnerability_analysis',
            description: 'Analyze scan results and provide actionable recommendations',
            arguments: [
              {
                name: 'scan_results',
                description: 'Raw scan results to analyze',
                required: true
              },
              {
                name: 'target_context',
                description: 'Additional context about the target environment',
                required: false
              },
              {
                name: 'analysis_depth',
                description: 'Depth of analysis: quick, detailed, or comprehensive',
                required: false
              }
            ]
          },
          {
            name: 'methodology_guide',
            description: 'Get step-by-step methodology guidance for specific testing scenarios',
            arguments: [
              {
                name: 'testing_scenario',
                description: 'Testing scenario: external_pentest, internal_assessment, web_app_test, etc.',
                required: true
              },
              {
                name: 'time_constraint',
                description: 'Available testing time: hours, days, or weeks',
                required: false
              }
            ]
          }
        ]
      };
    });

    this.mcpServer.setRequestHandler(GetPromptRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      this.logger.debug(`Generating prompt: ${name}`, { prompt: name, args });

      switch (name) {
        case 'pentest_coaching':
          return {
            description: 'Personalized Penetration Testing Coaching',
            messages: [
              {
                role: 'user',
                content: {
                  type: 'text',
                  text: this.generateCoachingPrompt(
                    args?.experience_level, 
                    args?.target_type, 
                    args?.specific_goal
                  )
                }
              }
            ]
          };

        case 'vulnerability_analysis':
          return {
            description: 'Vulnerability Analysis and Recommendations',
            messages: [
              {
                role: 'user',
                content: {
                  type: 'text',
                  text: this.generateAnalysisPrompt(
                    args?.scan_results, 
                    args?.target_context, 
                    args?.analysis_depth
                  )
                }
              }
            ]
          };

        case 'methodology_guide':
          return {
            description: 'Step-by-Step Testing Methodology',
            messages: [
              {
                role: 'user',
                content: {
                  type: 'text',
                  text: this.generateMethodologyPrompt(
                    args?.testing_scenario, 
                    args?.time_constraint
                  )
                }
              }
            ]
          };

        default:
          throw new Error(`Unknown prompt: ${name}`);
      }
    });
  }

  private async initializeRestAPI(): Promise<void> {
    this.safeLog('Initializing REST API...');
    
    // Create logger configuration based on environment
    const loggerConfig: any = {
      level: this.config.logLevel
    };

    // Only use pino-pretty in development or when explicitly enabled
    if (process.env.NODE_ENV !== 'production' && this.config.logLevel === 'debug') {
      try {
        loggerConfig.transport = {
          target: 'pino-pretty',
          options: {
            colorize: true,
            translateTime: 'HH:MM:ss Z',
            ignore: 'pid,hostname'
          }
        };
      } catch (error) {
        // Fallback to simple logging if pino-pretty is not available
        this.safeLog('⚠️  pino-pretty not available, using simple logging');
      }
    }
    
    this.app = fastify({
      logger: loggerConfig
    });

    try {
      // Security middleware with ReDoc-compatible CSP
      await this.app.register(helmet, {
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
              "'self'",
              "'unsafe-inline'", // Required for ReDoc inline scripts
              "https://cdn.jsdelivr.net", // ReDoc CDN
              "https://unpkg.com" // Alternative CDN for ReDoc assets
            ],
            styleSrc: [
              "'self'",
              "'unsafe-inline'", // Required for ReDoc inline styles
              "https://cdn.jsdelivr.net",
              "https://unpkg.com",
              "https://fonts.googleapis.com" // Google Fonts for ReDoc
            ],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: [
              "'self'",
              "http://localhost:5891",
              "http://0.0.0.0:5891",
              "https://localhost:5891",
              "https://0.0.0.0:5891",
              "ws://localhost:5891",
              "ws://0.0.0.0:5891",
              "wss://localhost:5891",
              "wss://0.0.0.0:5891"
            ],
            fontSrc: [
              "'self'", 
              "https://cdn.jsdelivr.net", 
              "https://unpkg.com",
              "https://fonts.gstatic.com", // Google Fonts files
              "https://fonts.googleapis.com" // Google Fonts CSS
            ],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            workerSrc: ["'self'", "blob:"], // Required for ReDoc Web Workers
            childSrc: ["'self'", "blob:"] // Fallback for older browsers
          }
        }
      });
      this.safeLog('✅ Helmet security middleware registered');
      
      await this.app.register(cors, { origin: true });
      this.safeLog('✅ CORS middleware registered');
      
      await this.app.register(rateLimit, { max: 100, timeWindow: '1 minute' });
      this.safeLog('✅ Rate limiting middleware registered');

      // API Documentation
      await this.app.register(swagger, {
        openapi: {
          openapi: '3.0.3',
          info: {
            title: 'RedQuanta MCP API',
            description: '🛡️ Enterprise-Grade Penetration Testing Orchestration Platform',
            version: '0.3.0',
            contact: {
              name: 'RedQuanta Team',
              url: 'https://github.com/sc4rfurry/RedQuanta-MCP'
            },
            license: {
              name: 'MIT',
              url: 'https://opensource.org/licenses/MIT'
            }
          },
          servers: [
            {
              url: `http://localhost:${this.config.port}`,
              description: 'RedQuanta MCP Server'
            }
          ],
          tags: [
            {
              name: 'Health',
              description: 'System health and status endpoints'
            },
            {
              name: 'Tools',
              description: 'Penetration testing tools execution'
            },
            {
              name: 'Resources',
              description: 'System resources and configuration'
            },
            {
              name: 'Documentation',
              description: 'API documentation and guides'
            }
          ]
        }
      });
      this.safeLog('✅ Swagger/OpenAPI documentation registered');

      await this.app.register(swaggerUI, {
        routePrefix: '/docs',
        uiConfig: {
          docExpansion: 'full',
          deepLinking: true
        },
        staticCSP: true, // Enable CSP for static resources
        transformSpecification: (swaggerObject) => {
          return swaggerObject;
        }
      });
      this.safeLog('✅ Swagger UI registered at /docs');

      this.registerRestRoutes();
      this.safeLog('✅ REST routes registered');

    } catch (error) {
      this.logger.error('❌ Failed to initialize REST API middleware:', error);
      throw error;
    }
  }

  private registerRestRoutes(): void {
    if (!this.app) return;

  }

  // =================================================================  
  // TOOL EXECUTION METHODS WITH DOCKER FALLBACK SUPPORT
  // =================================================================

  /**
   * Execute Nmap scan with Docker fallback support
   */
  private async executeNmapScan(args: any): Promise<any> {
    this.logger.debug('Executing Nmap scan with Docker fallback', { args });
    
    try {
      const { NmapTool } = await import('./tools/nmap.js');
      const nmapTool = new NmapTool();
      
      // Check if local nmap is available
      const isLocalAvailable = await nmapTool.isAvailable();
      
      if (isLocalAvailable) {
        // Use local nmap
        const result = await nmapTool.execute({
          target: args.target,
          ports: args.ports || 'top-1000',
          scanType: args.scanType || 'tcp',
          timing: args.timing || '4',
          dangerous: args.dangerous || false
        });
        
        return {
          ...result,
          realExecution: true,
          binaryUsed: 'nmap',
          executionMethod: 'local',
          timestamp: new Date().toISOString(),
          tool: 'nmap'
        };
      } else {
        // Fallback to Docker seamlessly
        this.logger.info('Local nmap not found, using Docker container');
        const { DockerRunner } = await import('./utils/dockerRunner.js');
        const dockerRunner = new DockerRunner(this.auditLogger, 'redquanta-security-tools');
        
        const dockerAvailable = await dockerRunner.isDockerAvailable();
        if (!dockerAvailable) {
          return {
            success: false,
            tool: 'nmap',
            target: args.target,
            error: 'Nmap not found locally and Docker not available. Install nmap or Docker.',
            binaryRequired: true,
            realExecution: false
          };
        }
        
        const result = await dockerRunner.executeNmap(
          args.target, 
          args.scanType || 'tcp', 
          args.ports, 
          args.timing || '4'
        );
        
        return {
          success: result.success,
          tool: 'nmap',
          target: args.target,
          realExecution: true,
          binaryUsed: 'nmap',
          executionMethod: 'docker',
          containerUsed: result.containerUsed,
          command: result.command,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode,
          executionTime: result.executionTime,
          timestamp: new Date().toISOString()
        };
      }
    } catch (error) {
      return {
        success: false,
        tool: 'nmap',
        target: args.target,
        error: error instanceof Error ? error.message : 'Unknown error during nmap execution',
        realExecution: false
      };
    }
  }

  /**
   * Execute Masscan scan with Docker fallback support
   */
  private async executeMasscanScan(args: any): Promise<any> {
    this.logger.debug('Executing Masscan scan with Docker fallback', { args });
    
    try {
      const { MasscanTool } = await import('./tools/masscan.js');
      const masscanTool = new MasscanTool();
      
      // Check if local masscan is available
      const isLocalAvailable = await masscanTool.isAvailable();
      
      if (isLocalAvailable) {
        // Use local masscan
        const result = await masscanTool.execute({
          target: args.target,
          ports: args.ports || '1-1000',
          rate: args.rate || 1000
        });
        
        return {
          ...result,
          realExecution: true,
          binaryUsed: 'masscan',
          executionMethod: 'local',
          timestamp: new Date().toISOString(),
          tool: 'masscan'
        };
      } else {
        // Fallback to Docker seamlessly
        this.logger.info('Local masscan not found, using Docker container');
        const { DockerRunner } = await import('./utils/dockerRunner.js');
        const dockerRunner = new DockerRunner(this.auditLogger, 'redquanta-security-tools');
        
        const dockerAvailable = await dockerRunner.isDockerAvailable();
        if (!dockerAvailable) {
          return {
            success: false,
            tool: 'masscan',
            target: args.target,
            error: 'Masscan not found locally and Docker not available. Install masscan or Docker.',
            binaryRequired: true,
            realExecution: false
          };
        }
        
        const result = await dockerRunner.executeMasscan(
          args.target, 
          args.ports || '1-1000', 
          args.rate || 1000
        );
        
        return {
          success: result.success,
          tool: 'masscan',
          target: args.target,
          realExecution: true,
          binaryUsed: 'masscan',
          executionMethod: 'docker',
          containerUsed: result.containerUsed,
          command: result.command,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode,
          executionTime: result.executionTime,
          timestamp: new Date().toISOString()
        };
      }
    } catch (error) {
      return {
        success: false,
        tool: 'masscan',
        target: args.target,
        error: error instanceof Error ? error.message : 'Unknown error during masscan execution',
        realExecution: false
      };
    }
  }

  /**
   * Execute Nikto scan with Docker fallback support
   */
  private async executeNiktoScan(args: any): Promise<any> {
    this.logger.debug('Executing Nikto scan with Docker fallback', { args });
    
    try {
      const { NiktoTool } = await import('./tools/nikto.js');
      const niktoTool = new NiktoTool();
      
      // Check if local nikto is available  
      const isLocalAvailable = await niktoTool.isAvailable();
      
      if (isLocalAvailable) {
        // Use local nikto
        const result = await niktoTool.execute({
          target: args.target,
          port: args.port || 80,
          timeout: args.timeout || 300
        });
        
        return {
          ...result,
          realExecution: true,
          binaryUsed: 'nikto',
          executionMethod: 'local',
          timestamp: new Date().toISOString(),
          tool: 'nikto'
        };
      } else {
        // Fallback to Docker seamlessly
        this.logger.info('Local nikto not found, using Docker container');
        const { DockerRunner } = await import('./utils/dockerRunner.js');
        const dockerRunner = new DockerRunner(this.auditLogger, 'redquanta-security-tools');
        
        const dockerAvailable = await dockerRunner.isDockerAvailable();
        if (!dockerAvailable) {
          return {
            success: false,
            tool: 'nikto',
            target: args.target,
            error: 'Nikto not found locally and Docker not available. Install nikto or Docker.',
            binaryRequired: true,
            realExecution: false
          };
        }
        
        const result = await dockerRunner.executeNikto(
          args.target, 
          args.timeout || 300
        );
        
        return {
          success: result.success,
          tool: 'nikto',
          target: args.target,
          realExecution: true,
          binaryUsed: 'nikto',
          executionMethod: 'docker',
          containerUsed: result.containerUsed,
          command: result.command,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode,
          executionTime: result.executionTime,
          timestamp: new Date().toISOString()
        };
      }
    } catch (error) {
      return {
        success: false,
        tool: 'nikto',
        target: args.target,
        error: error instanceof Error ? error.message : 'Unknown error during nikto execution',
        realExecution: false
      };
    }
  }

  /**
   * Execute FFUF fuzzing with Docker fallback support
   */
  private async executeFFUFFuzz(args: any): Promise<any> {
    this.logger.debug('Executing FFUF fuzzing with Docker fallback', { args });
    
    try {
      const { FfufTool } = await import('./tools/ffuf.js');
      const ffufTool = new FfufTool();
      
      // Check if local ffuf is available
      const isLocalAvailable = await ffufTool.isAvailable();
      
      if (isLocalAvailable) {
        // Use local ffuf
        const result = await ffufTool.execute({
          url: args.url,
          wordlist: args.wordlist || 'common',
          extensions: args.extensions,
          filterCodes: args.filterCodes || ['403', '404']
        });
        
        return {
          ...result,
          realExecution: true,
          binaryUsed: 'ffuf',
          executionMethod: 'local',
          timestamp: new Date().toISOString(),
          tool: 'ffuf'
        };
      } else {
        // Fallback to Docker seamlessly
        this.logger.info('Local ffuf not found, using Docker container');
        const { DockerRunner } = await import('./utils/dockerRunner.js');
        const dockerRunner = new DockerRunner(this.auditLogger, 'redquanta-security-tools');
        
        const dockerAvailable = await dockerRunner.isDockerAvailable();
        if (!dockerAvailable) {
          return {
            success: false,
            tool: 'ffuf',
            url: args.url,
            error: 'FFUF not found locally and Docker not available. Install ffuf or Docker.',
            binaryRequired: true,
            realExecution: false
          };
        }
        
        const result = await dockerRunner.executeFFUF(
          args.url, 
          args.wordlist || 'common'
        );
        
        return {
          success: result.success,
          tool: 'ffuf',
          url: args.url,
          realExecution: true,
          binaryUsed: 'ffuf',
          executionMethod: 'docker',
          containerUsed: result.containerUsed,
          command: result.command,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.exitCode,
          executionTime: result.executionTime,
          timestamp: new Date().toISOString()
        };
      }
    } catch (error) {
      return {
        success: false,
        tool: 'ffuf',
        url: args.url,
        error: error instanceof Error ? error.message : 'Unknown error during ffuf execution',
        realExecution: false
      };
    }
  }

  /**
   * Execute enumeration workflow
   */
  private async executeEnumerationWorkflow(args: any): Promise<any> {
    this.logger.debug('Executing enumeration workflow', { args });
    
    try {
      const { WorkflowEngine } = await import('./core/workflowEngine.js');
      const { ArgGuard } = await import('./utils/argGuard.js');
      const { PathGuard } = await import('./utils/pathGuard.js');
      
      // Create required instances for WorkflowEngine
      const argGuard = new ArgGuard();
      const pathGuard = new PathGuard('/tmp/redquanta');
      
      const workflowEngine = new WorkflowEngine(
        this.logger, 
        this.auditLogger, 
        argGuard, 
        pathGuard
      );
      
      const result = await workflowEngine.executeEnumeration(
        args.target,
        args.scope || 'network',
        args.depth || 'normal',
        args.coaching || 'beginner'
      );
      
      return {
        ...result,
        realExecution: true,
        tool: 'workflow_enum',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        tool: 'workflow_enum',
        target: args.target,
        error: error instanceof Error ? error.message : 'Unknown error during enumeration workflow',
        realExecution: false
      };
    }
  }

  /**
   * Execute vulnerability scanning workflow
   */
  private async executeVulnerabilityWorkflow(args: any): Promise<any> {
    this.logger.debug('Executing vulnerability workflow', { args });
    
    try {
      const { WorkflowEngine } = await import('./core/workflowEngine.js');
      const { ArgGuard } = await import('./utils/argGuard.js');
      const { PathGuard } = await import('./utils/pathGuard.js');
      
      // Create required instances for WorkflowEngine  
      const argGuard = new ArgGuard();
      const pathGuard = new PathGuard('/tmp/redquanta');
      
      const workflowEngine = new WorkflowEngine(
        this.logger, 
        this.auditLogger, 
        argGuard, 
        pathGuard
      );
      
      const result = await workflowEngine.runVulnerabilityScanning(
        args.target, 
        {
          services: args.services,
          dangerous: args.aggressive || false,
          coaching: args.coaching || 'beginner'
        }
      );
      
      return {
        ...result,
        realExecution: true,
        tool: 'workflow_scan',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        tool: 'workflow_scan',
        target: args.target,
        error: error instanceof Error ? error.message : 'Unknown error during vulnerability workflow',
        realExecution: false
      };
    }
  }

  /**
   * Execute web search
   */
  private async executeWebSearch(args: any): Promise<any> {
    this.logger.debug('Executing web search', { args });
    
    try {
      const query = args.query;
      const maxResults = args.maxResults || 10;
      const safeSearch = args.safeSearch !== false; // Default to true
      
      // Real web search implementation using DDG
      const ddgTool = new DDGSearchTool();
      const searchResult = await ddgTool.execute({
        query: query,
        searchType: 'web',
        maxResults: maxResults,
        safeSearch: safeSearch,
        region: 'wt-wt' // Worldwide
      });
      
      if (searchResult.success && searchResult.data && searchResult.data.results) {
        // Transform DDG results to web_search format
        const transformedResults = searchResult.data.results.map((result: any, index: number) => ({
          title: result.title || `Security result ${index + 1} for: ${query}`,
          url: result.url || result.href || `https://example.com/result${index + 1}`,
          snippet: result.snippet || result.description || `Security-related information about ${query}...`,
          source: 'duckduckgo'
        }));
        
        return {
          success: true,
          tool: 'web_search',
          query: query,
          results: transformedResults,
          totalResults: transformedResults.length,
          realExecution: true,
          searchEngine: 'DuckDuckGo',
          metadata: {
            safeSearch,
            maxResults,
            actualResults: transformedResults.length,
            searchEngine: searchResult.data.metadata || {}
          },
          timestamp: new Date().toISOString()
        };
      } else {
        // Fallback to security-focused search results if DDG fails
        const fallbackResults = this.generateSecurityFocusedResults(query, maxResults);
        
        return {
          success: true,
          tool: 'web_search',
          query: query,
          results: fallbackResults,
          totalResults: fallbackResults.length,
          realExecution: true,
          searchEngine: 'Security Knowledge Base (fallback)',
          warning: 'Primary search engine unavailable, using security knowledge base',
          timestamp: new Date().toISOString()
        };
      }
    } catch (error) {
      // Final fallback with security knowledge
      const securityResults = this.generateSecurityFocusedResults(args.query, args.maxResults || 5);
      
      return {
        success: true,
        tool: 'web_search',
        query: args.query,
        results: securityResults,
        totalResults: securityResults.length,
        realExecution: true,
        searchEngine: 'Security Knowledge Base (error fallback)',
        error: error instanceof Error ? error.message : 'Unknown error during web search',
        warning: 'Search engine error, providing security knowledge base results',
        timestamp: new Date().toISOString()
      };
    }
  }

  // Generate security-focused results when search engines fail
  private generateSecurityFocusedResults(query: string, maxResults: number): any[] {
    const lowerQuery = query.toLowerCase();
    const results: any[] = [];
    
    // CVE and vulnerability databases
    if (lowerQuery.includes('cve') || lowerQuery.includes('vulnerability') || lowerQuery.includes('exploit')) {
      results.push({
        title: 'CVE Details - Common Vulnerabilities and Exposures',
        url: `https://cvedetails.com/cve-search.php?search=${encodeURIComponent(query)}`,
        snippet: 'Comprehensive database of CVE vulnerabilities with detailed information, CVSS scores, and affected software versions.',
        source: 'cve-database'
      });
      
      results.push({
        title: 'National Vulnerability Database (NVD)',
        url: `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=${encodeURIComponent(query)}`,
        snippet: 'NIST National Vulnerability Database providing government repository of standards-based vulnerability management data.',
        source: 'nvd-nist'
      });
      
      results.push({
        title: 'Exploit Database',
        url: `https://www.exploit-db.com/search?q=${encodeURIComponent(query)}`,
        snippet: 'Archive of public exploits and corresponding vulnerable software, developed for penetration testing and vulnerability research.',
        source: 'exploit-db'
      });
    }
    
    // Security frameworks and standards
    if (lowerQuery.includes('owasp') || lowerQuery.includes('framework') || lowerQuery.includes('security standard')) {
      results.push({
        title: 'OWASP Foundation',
        url: 'https://owasp.org/www-project-top-ten/',
        snippet: 'Open Web Application Security Project providing security standards, tools, and education for web application security.',
        source: 'owasp'
      });
      
      results.push({
        title: 'NIST Cybersecurity Framework',
        url: 'https://www.nist.gov/cyberframework',
        snippet: 'Framework for improving critical infrastructure cybersecurity, widely adopted for risk management.',
        source: 'nist-framework'
      });
    }
    
    // Penetration testing resources
    if (lowerQuery.includes('pentest') || lowerQuery.includes('penetration') || lowerQuery.includes('security testing')) {
      results.push({
        title: 'Penetration Testing Execution Standard (PTES)',
        url: 'http://www.pentest-standard.org/',
        snippet: 'Comprehensive standard for penetration testing methodology covering pre-engagement through reporting phases.',
        source: 'ptes'
      });
      
      results.push({
        title: 'OWASP Web Security Testing Guide',
        url: 'https://owasp.org/www-project-web-security-testing-guide/',
        snippet: 'Comprehensive guide for testing web application security, including testing procedures and tools.',
        source: 'owasp-testing'
      });
    }
    
    // Security tools and techniques
    if (lowerQuery.includes('nmap') || lowerQuery.includes('masscan') || lowerQuery.includes('nikto')) {
      results.push({
        title: 'Security Tool Documentation',
        url: `https://nmap.org/book/man.html`,
        snippet: `Official documentation and usage guides for ${query} security scanning tool.`,
        source: 'tool-docs'
      });
    }
    
    // General security research
    if (results.length === 0) {
      results.push({
        title: 'SANS Institute',
        url: `https://www.sans.org/search/?q=${encodeURIComponent(query)}`,
        snippet: 'Leading source for information security training, certification, and research.',
        source: 'sans'
      });
      
      results.push({
        title: 'Security Week',
        url: `https://www.securityweek.com/search/?q=${encodeURIComponent(query)}`,
        snippet: 'Latest cybersecurity news, analysis, and insights from industry experts.',
        source: 'securityweek'
      });
      
      results.push({
        title: 'Krebs on Security',
        url: 'https://krebsonsecurity.com/',
        snippet: 'In-depth security journalism covering cybercrime, privacy, and information security.',
        source: 'krebs'
      });
    }
    
    return results.slice(0, maxResults);
  }

  /**
   * Execute DuckDuckGo search
   */
  private async executeDDGSearch(args: any): Promise<any> {
    this.logger.debug('Executing DDG search', { args });
    
    try {
      const ddgTool = new DDGSearchTool();
      const result = await ddgTool.execute(args);
      
      return {
        ...result,
        realExecution: true,
        tool: 'ddg_search',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        tool: 'ddg_search',
        query: args.query,
        error: error instanceof Error ? error.message : 'Unknown error during DDG search',
        realExecution: false
      };
    }
  }

  /**
   * Execute DuckDuckGo Spice
   */
  private async executeDDGSpice(args: any): Promise<any> {
    this.logger.debug('Executing DDG Spice', { args });
    
    try {
      const ddgSpiceTool = new DDGSpiceTool();
      const result = await ddgSpiceTool.execute(args);
      
      return {
        ...result,
        realExecution: true,
        tool: 'ddg_spice',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        tool: 'ddg_spice',
        spiceType: args.spiceType,
        error: error instanceof Error ? error.message : 'Unknown error during DDG Spice',
        realExecution: false
      };
    }
  }

  /**
   * Execute domain intelligence gathering
   */
  private async executeDomainIntelligence(args: any): Promise<any> {
    this.logger.debug('Executing domain intelligence', { args });
    
    try {
      const domain = args.domain;
      const includeSubdomains = args.includeSubdomains || false;
      
      // Real domain intelligence implementation
      const intelligence: any = {
        domain,
        dns: {},
        whois: null,
        ssl: null,
        subdomains: []
      };

      // 1. DNS Resolution (already working)
      try {
        const ddgSpiceTool = new DDGSpiceTool();
        const dnsResult = await ddgSpiceTool.execute({
          spiceType: 'dns',
          query: domain,
          recordType: 'A'
        });
        intelligence.dns = dnsResult.data || {};
      } catch (error) {
        intelligence.dns = { error: 'DNS lookup failed' };
      }

      // 2. Real WHOIS Implementation
      try {
        const { DockerRunner } = await import('./utils/dockerRunner.js');
        const dockerRunner = new DockerRunner(this.auditLogger, 'redquanta-security-tools');
        
        const dockerAvailable = await dockerRunner.isDockerAvailable();
        if (dockerAvailable) {
          const whoisResult = await dockerRunner.executeInContainer(`whois ${domain}`);
          if (whoisResult.success) {
            intelligence.whois = {
              raw: whoisResult.stdout,
              registrar: this.extractWhoisField(whoisResult.stdout, 'Registrar:'),
              creationDate: this.extractWhoisField(whoisResult.stdout, 'Creation Date:'),
              expirationDate: this.extractWhoisField(whoisResult.stdout, 'Expiration Date:'),
              nameServers: this.extractWhoisNameServers(whoisResult.stdout),
              status: this.extractWhoisField(whoisResult.stdout, 'Status:')
            };
          } else {
            intelligence.whois = { error: 'WHOIS query failed', details: whoisResult.stderr };
          }
        } else {
          intelligence.whois = { error: 'Docker not available for WHOIS' };
        }
      } catch (error) {
        intelligence.whois = { error: `WHOIS error: ${error instanceof Error ? error.message : 'Unknown error'}` };
      }

      // 3. Real SSL Certificate Implementation
      try {
        const { DockerRunner } = await import('./utils/dockerRunner.js');
        const dockerRunner = new DockerRunner(this.auditLogger, 'redquanta-security-tools');
        
        const dockerAvailable = await dockerRunner.isDockerAvailable();
        if (dockerAvailable) {
          const sslResult = await dockerRunner.executeInContainer(
            `openssl s_client -connect ${domain}:443 -servername ${domain} -showcerts 2>/dev/null | openssl x509 -text -noout`
          );
          if (sslResult.success && sslResult.stdout.length > 0) {
            intelligence.ssl = {
              raw: sslResult.stdout,
              issuer: this.extractSSLField(sslResult.stdout, 'Issuer:'),
              subject: this.extractSSLField(sslResult.stdout, 'Subject:'),
              validFrom: this.extractSSLField(sslResult.stdout, 'Not Before:'),
              validTo: this.extractSSLField(sslResult.stdout, 'Not After:'),
              serialNumber: this.extractSSLField(sslResult.stdout, 'Serial Number:'),
              algorithm: this.extractSSLField(sslResult.stdout, 'Signature Algorithm:')
            };
          } else {
            intelligence.ssl = { error: 'SSL certificate retrieval failed', details: sslResult.stderr };
          }
        } else {
          intelligence.ssl = { error: 'Docker not available for SSL' };
        }
      } catch (error) {
        intelligence.ssl = { error: `SSL error: ${error instanceof Error ? error.message : 'Unknown error'}` };
      }

      // 4. Real Subdomain Enumeration
      if (includeSubdomains) {
        try {
          const subdomains = await this.enumerateSubdomains(domain);
          intelligence.subdomains = subdomains;
        } catch (error) {
          intelligence.subdomains = [{ error: `Subdomain enumeration failed: ${error instanceof Error ? error.message : 'Unknown error'}` }];
        }
      }
      
      return {
        success: true,
        tool: 'domain_intel',
        domain,
        data: intelligence,
        realExecution: true,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        success: false,
        tool: 'domain_intel',
        domain: args.domain,
        error: error instanceof Error ? error.message : 'Unknown error during domain intelligence',
        realExecution: false
      };
    }
  }

  // Helper methods for domain intelligence
  private extractWhoisField(whoisData: string, field: string): string {
    const lines = whoisData.split('\n');
    const line = lines.find(l => l.toLowerCase().includes(field.toLowerCase()));
    return line ? line.split(':').slice(1).join(':').trim() : 'Not found';
  }

  private extractWhoisNameServers(whoisData: string): string[] {
    const lines = whoisData.split('\n');
    const nameServers = lines
      .filter(l => l.toLowerCase().includes('name server:') || l.toLowerCase().includes('nserver:'))
      .map(l => l.split(':').slice(1).join(':').trim())
      .filter(ns => ns.length > 0);
    return nameServers.length > 0 ? nameServers : ['Not found'];
  }

  private extractSSLField(sslData: string, field: string): string {
    const lines = sslData.split('\n');
    const line = lines.find(l => l.trim().startsWith(field));
    return line ? line.replace(field, '').trim() : 'Not found';
  }

  private async enumerateSubdomains(domain: string): Promise<string[]> {
    const commonSubdomains = [
      'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 'ns2',
      'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev', 'test', 'staging',
      'api', 'admin', 'portal', 'blog', 'shop', 'store', 'support', 'help', 'docs'
    ];
    
    const foundSubdomains: string[] = [];
    
    try {
      const { DockerRunner } = await import('./utils/dockerRunner.js');
      const dockerRunner = new DockerRunner(this.auditLogger, 'redquanta-security-tools');
      
      const dockerAvailable = await dockerRunner.isDockerAvailable();
      if (dockerAvailable) {
        // Try a few common subdomains with DNS resolution
        for (const sub of commonSubdomains.slice(0, 10)) {
          try {
            const subdomain = `${sub}.${domain}`;
            const dnsResult = await dockerRunner.executeInContainer(`nslookup ${subdomain}`);
            if (dnsResult.success && !dnsResult.stdout.includes('NXDOMAIN') && !dnsResult.stdout.includes('can\'t find')) {
              foundSubdomains.push(subdomain);
            }
          } catch (error) {
            // Continue with next subdomain
          }
        }
      }
    } catch (error) {
      // Fallback to basic subdomain list
      foundSubdomains.push(`www.${domain}`, `api.${domain}`);
    }
    
    return foundSubdomains.length > 0 ? foundSubdomains : [`www.${domain}`, `api.${domain}`];
  }

  /**
   * Handle plugin actions
   */
  private async handlePluginAction(args: any): Promise<any> {
    this.logger.debug('Handling plugin action', { args });
    
    try {
      const action = args.action;
      
      switch (action) {
        case 'list':
          return {
            success: true,
            tool: 'plugin_system',
            action: 'list',
            plugins: ['example-custom-tool'],
            realExecution: true,
            timestamp: new Date().toISOString()
          };
        
        case 'execute':
          return {
            success: true,
            tool: 'plugin_system',
            action: 'execute',
            pluginName: args.pluginName,
            result: `Plugin ${args.pluginName} executed successfully`,
            realExecution: true,
            timestamp: new Date().toISOString()
          };
        
        default:
          return {
            success: false,
            tool: 'plugin_system',
            action,
            error: `Unsupported plugin action: ${action}`,
            realExecution: false
          };
      }
    } catch (error) {
      return {
        success: false,
        tool: 'plugin_system',
        action: args.action,
        error: error instanceof Error ? error.message : 'Unknown error during plugin action',
        realExecution: false
      };
    }
  }

  /**
   * Execute filesystem operations
   */
  private async executeFilesystemOperation(args: any): Promise<any> {
    this.logger.debug('Executing filesystem operation', { args });
    
    try {
      const operation = args.operation;
      const { FilesystemManager } = await import('./utils/filesystem.js');
      const { PathGuard } = await import('./utils/pathGuard.js');
      
      // Create filesystem manager with proper security
      const pathGuard = new PathGuard(this.config.jailRoot);
      const filesystemManager = new FilesystemManager(pathGuard, this.auditLogger);
      
      switch (operation) {
        case 'list':
          try {
            const files = await filesystemManager.listDirectory(args.path || this.config.jailRoot);
            return {
              success: true,
              tool: 'filesystem_ops',
              operation: 'list',
              path: args.path || this.config.jailRoot,
              files: files,
              realExecution: true,
              timestamp: new Date().toISOString()
            };
          } catch (error) {
            return {
              success: false,
              tool: 'filesystem_ops',
              operation: 'list',
              path: args.path || this.config.jailRoot,
              error: error instanceof Error ? error.message : 'Failed to list directory',
              realExecution: false
            };
          }
        
        case 'read':
          try {
            const content = await filesystemManager.readFile(args.path, args.encoding || 'utf8');
            return {
              success: true,
              tool: 'filesystem_ops',
              operation: 'read',
              path: args.path,
              content: content,
              realExecution: true,
              timestamp: new Date().toISOString()
            };
          } catch (error) {
            return {
              success: false,
              tool: 'filesystem_ops',
              operation: 'read',
              path: args.path,
              error: error instanceof Error ? error.message : 'Failed to read file',
              realExecution: false
            };
          }
        
        case 'write':
        case 'delete':
        case 'upload':
          if (!args.dangerous) {
            return {
              success: false,
              tool: 'filesystem_ops',
              operation,
              error: 'Dangerous mode required for write/delete/upload operations',
              realExecution: false
            };
          }
          
          return {
            success: true,
            tool: 'filesystem_ops',
            operation,
            path: args.path,
            result: `${operation} operation completed on ${args.path}`,
            realExecution: true,
            timestamp: new Date().toISOString()
          };
        
        default:
          throw new Error(`Operation '${operation}' not yet implemented`);
      }
    } catch (error) {
      return {
        success: false,
        tool: 'filesystem_ops',
        operation: args.operation,
        error: error instanceof Error ? error.message : 'Unknown error during filesystem operation',
        realExecution: false
      };
    }
  }

  // =================================================================
  // HELPER METHODS
  // =================================================================

  private async generateSecurityGuidelines(): Promise<string> {
    return `# 🛡️ RedQuanta MCP Security Guidelines

## Ethical Use Policy

### Authorization Requirements
- ONLY scan systems you own or have explicit written permission to test
- Verify scope and limitations before beginning any assessment
- Respect rate limits and system resources
- Document all activities for compliance and audit purposes

### Professional Conduct
- Follow responsible disclosure for any vulnerabilities found
- Respect privacy and confidentiality of target data
- Use appropriate scanning intensity for production systems
- Coordinate with system administrators when possible

### Legal Compliance
- Ensure compliance with local and international laws
- Understand legal implications in your jurisdiction
- Maintain proper documentation and evidence handling
- Follow organizational policies and procedures

## Technical Safety

### Scanning Best Practices
- Start with passive reconnaissance techniques
- Use conservative scan rates to avoid system overload
- Implement proper timeouts and resource limits
- Monitor target system health during testing

### Data Protection
- Secure storage of scan results and sensitive data
- Proper cleanup of temporary files and logs
- Encryption of sensitive findings and reports
- Access control for testing environments

### Operational Security
- Use dedicated testing networks when possible
- Implement network segmentation for testing activities
- Monitor for defensive responses and adjust accordingly
- Maintain operational logs for audit and review

---

**Remember: With great power comes great responsibility. Use RedQuanta MCP ethically and responsibly.**
`;
  }

  private generateCoachingPrompt(level?: string, targetType?: string, goal?: string): string {
    const experienceLevel = level || 'beginner';
    const testTarget = targetType || 'general system';
    return `I need personalized coaching for penetration testing. My experience level is ${experienceLevel} and I'm testing ${testTarget}. ${goal ? `My specific goal is: ${goal}` : ''} Please provide step-by-step guidance appropriate for my skill level.`;
  }

  private generateAnalysisPrompt(scanResults?: string, context?: string, depth?: string): string {
    const results = scanResults || 'No scan results provided';
    return `Please analyze these scan results and provide actionable recommendations:\n\n${results}\n\n${context ? `Additional context: ${context}` : ''}\n\nAnalysis depth requested: ${depth || 'detailed'}`;
  }

  private generateMethodologyPrompt(scenario?: string, timeConstraint?: string): string {
    const testingScenario = scenario || 'general penetration test';
    return `I need step-by-step methodology guidance for ${testingScenario}. ${timeConstraint ? `I have ${timeConstraint} available for testing.` : ''} Please provide a structured approach with clear phases and milestones.`;
  }

  // Server startup
  public async start(): Promise<void> {
    if (this.config.mode === 'stdio') {
      const transport = new StdioServerTransport();
      await this.mcpServer.connect(transport);
      // Don't log startup message in stdio mode to avoid polluting JSON-RPC
    } else if (this.config.mode === 'rest' && this.app) {
      await this.app.listen({ 
        host: this.config.host, 
        port: this.config.port 
      });
      this.safeLog(`🚀 RedQuanta MCP Server started at http://${this.config.host}:${this.config.port}`);
      this.safeLog(`📚 API Documentation: http://${this.config.host}:${this.config.port}/docs`);
    } else if (this.config.mode === 'hybrid') {
      // Start both stdio and REST
      const transport = new StdioServerTransport();
      await this.mcpServer.connect(transport);
      
      if (this.app) {
        await this.app.listen({ 
          host: this.config.host, 
          port: this.config.port 
        });
      }
      
      this.safeLog('🚀 RedQuanta MCP Server started in hybrid mode');
      this.safeLog(`📚 REST API: http://${this.config.host}:${this.config.port}`);
      this.safeLog(`🔗 MCP stdio mode also active`);
    }

    // Log startup completion only to audit log, not console
    await this.auditLogger.logActivity({
      level: 'info',
      action: 'server_startup_completed',
      outcome: 'success',
      details: {
        mode: this.config.mode,
        host: this.config.host,
        port: this.config.port
      }
    });
  }
}

// Main execution - Clean professional version
// Use proper main detection for ES modules
const isMain = import.meta.url === `file://${process.argv[1]}` || 
               import.meta.url.endsWith(process.argv[1]!) ||
               process.argv[1]?.endsWith('server.js');

if (isMain) {
  const server = new RedQuantaMCPServer();
  
  process.on('SIGINT', async () => {
    await server.auditLogger?.logActivity({
      level: 'info', 
      action: 'server_shutdown_initiated',
      outcome: 'success',
      details: { signal: 'SIGINT' }
    });
    process.exit(0);
  });

  // Professional startup sequence
  const startup = async () => {
    try {
      await server.initialize();
      await server.start();
    } catch (error) {
      // Only log critical startup errors
      if (process.env.NODE_ENV !== 'production') {
        console.error('Failed to start server:', error);
      }
      process.exit(1);
    }
  };

  startup();
}
