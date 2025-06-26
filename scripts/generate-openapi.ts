#!/usr/bin/env node

/**
 * OpenAPI Specification Generator for RedQuanta MCP Server
 * 
 * Generates comprehensive OpenAPI 3.0 documentation with detailed
 * schemas, examples, and LLM-tailored descriptions.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';

interface ToolSchema {
  name: string;
  description: string;
  category: string;
  dangerLevel: 'safe' | 'caution' | 'dangerous';
  parameters: Record<string, any>;
  examples: any[];
  useCases: string[];
  security: {
    riskLevel: string;
    considerations: string[];
    legalNote: string;
  };
}

const toolSchemas: ToolSchema[] = [
  {
    name: 'nmap_scan',
    description: 'Advanced network discovery and security auditing tool for comprehensive network reconnaissance',
    category: 'Network Scanning',
    dangerLevel: 'caution',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Target specification: IP address, hostname, IP range, or CIDR notation',
        examples: ['192.168.1.1', 'example.com', '192.168.1.0/24', '10.0.0.1-100'],
        pattern: '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:\\/[0-9]{1,2})?$|^[a-zA-Z0-9.-]+$'
      },
      ports: {
        type: 'string',
        required: false,
        default: 'top-1000',
        description: 'Port specification: specific ports, ranges, or presets',
        examples: ['80,443,22', '1-1000', 'top-1000', '1-65535']
      },
      profile: {
        type: 'string',
        required: false,
        default: 'default',
        enum: ['stealth', 'default', 'aggressive'],
        description: 'Scanning profile determining speed vs stealth trade-off'
      },
      dangerous: {
        type: 'boolean',
        required: false,
        default: false,
        description: 'Enable aggressive techniques including OS detection, version scanning, and script execution'
      },
      custom_flags: {
        type: 'array',
        items: { type: 'string' },
        required: false,
        description: 'Additional nmap flags for advanced users',
        examples: [['-sS', '-O'], ['--script', 'vuln'], ['-T4', '--min-rate', '1000']]
      }
    },
    examples: [
      {
        name: 'Basic Host Discovery',
        description: 'Simple ping scan to discover live hosts in a network',
        parameters: { target: '192.168.1.0/24', ports: 'none', profile: 'stealth' },
        expectedOutput: 'List of live hosts with response times'
      },
      {
        name: 'Service Detection',
        description: 'Comprehensive service and version detection on common ports',
        parameters: { target: 'example.com', ports: 'top-1000', profile: 'default', dangerous: true },
        expectedOutput: 'Open ports with service versions and potential vulnerabilities'
      },
      {
        name: 'Vulnerability Assessment',
        description: 'Advanced scanning with NSE scripts for vulnerability detection',
        parameters: { target: '192.168.1.100', custom_flags: ['--script', 'vuln', '--script-args', 'unsafe=1'], dangerous: true },
        expectedOutput: 'Detailed vulnerability report with CVE references'
      }
    ],
    useCases: [
      'Network asset discovery and inventory',
      'Security auditing and vulnerability assessment',
      'Firewall configuration testing',
      'Service enumeration and banner grabbing',
      'Compliance scanning for security standards'
    ],
    security: {
      riskLevel: 'Medium',
      considerations: [
        'Scanning may trigger intrusion detection systems',
        'Aggressive scans can impact network performance',
        'Some techniques may be considered hostile by target organizations',
        'Always respect rate limits to avoid denial of service'
      ],
      legalNote: 'Only scan systems you own or have explicit written permission to test'
    }
  },
  {
    name: 'masscan_scan',
    description: 'Ultra-fast Internet-scale port scanner capable of scanning entire networks in minutes',
    category: 'Network Scanning',
    dangerLevel: 'dangerous',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Target IP range in CIDR notation or single IP address',
        examples: ['192.168.1.0/24', '10.0.0.0/16', '203.0.113.0/24'],
        pattern: '^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:\\/[0-9]{1,2})?$'
      },
      ports: {
        type: 'string',
        required: false,
        default: '1-1000',
        description: 'Port range or specific ports to scan',
        examples: ['80,443', '1-1000', '1-65535', '20-25,53,80,110,443']
      },
      rate: {
        type: 'number',
        required: false,
        default: 1000,
        minimum: 1,
        maximum: 1000000,
        description: 'Transmission rate in packets per second'
      },
      interface: {
        type: 'string',
        required: false,
        description: 'Network interface to use for scanning',
        examples: ['eth0', 'wlan0', 'en0']
      }
    },
    examples: [
      {
        name: 'Fast Network Discovery',
        description: 'High-speed discovery of web services across a subnet',
        parameters: { target: '192.168.1.0/24', ports: '80,443,8080,8443', rate: 10000 },
        expectedOutput: 'List of hosts with open web service ports'
      },
      {
        name: 'Comprehensive Port Scan',
        description: 'Full port range scan with controlled rate limiting',
        parameters: { target: '10.0.0.0/16', ports: '1-65535', rate: 1000 },
        expectedOutput: 'Complete port landscape of the target network'
      }
    ],
    useCases: [
      'Large-scale network reconnaissance',
      'Internet-wide research and scanning',
      'Initial penetration testing reconnaissance',
      'Network asset inventory for large organizations',
      'Security monitoring and threat hunting'
    ],
    security: {
      riskLevel: 'High',
      considerations: [
        'Extremely aggressive scanning that will be detected',
        'Can overwhelm network infrastructure if not rate limited',
        'May violate terms of service for cloud providers',
        'Requires careful configuration to avoid denial of service'
      ],
      legalNote: 'Extremely important to have written authorization - high-speed scanning can appear as attack traffic'
    }
  },
  {
    name: 'ffuf_fuzz',
    description: 'Fast web fuzzer for discovering hidden directories, files, and parameters through intelligent brute forcing',
    category: 'Web Testing',
    dangerLevel: 'caution',
    parameters: {
      url: {
        type: 'string',
        required: true,
        description: 'Target URL with FUZZ keyword placeholder for wordlist substitution',
        examples: ['https://example.com/FUZZ', 'https://api.example.com/v1/FUZZ', 'https://example.com/admin/FUZZ.php'],
        pattern: '^https?://.*FUZZ.*$'
      },
      wordlist: {
        type: 'string',
        required: false,
        default: 'common',
        description: 'Wordlist to use for fuzzing - built-in presets or custom file path',
        examples: ['common', 'directories', 'files', 'api-endpoints', '/path/to/custom.txt']
      },
      extensions: {
        type: 'string',
        required: false,
        description: 'File extensions to append to wordlist entries',
        examples: ['php,html,txt', 'jsp,asp,aspx', 'json,xml,yml']
      },
      threads: {
        type: 'number',
        required: false,
        default: 50,
        minimum: 1,
        maximum: 500,
        description: 'Number of concurrent threads for fuzzing'
      },
      filter_codes: {
        type: 'string',
        required: false,
        default: '403,404',
        description: 'HTTP status codes to filter out from results',
        examples: ['403,404', '400-499', '301,302,403,404']
      },
      headers: {
        type: 'object',
        required: false,
        description: 'Custom HTTP headers to include in requests',
        examples: [{ 'Authorization': 'Bearer token123' }, { 'User-Agent': 'CustomAgent/1.0' }]
      }
    },
    examples: [
      {
        name: 'Directory Discovery',
        description: 'Basic directory enumeration on a web application',
        parameters: { url: 'https://example.com/FUZZ', wordlist: 'directories', threads: 100 },
        expectedOutput: 'List of discovered directories with HTTP status codes'
      },
      {
        name: 'API Endpoint Fuzzing',
        description: 'Discover API endpoints with authentication headers',
        parameters: { 
          url: 'https://api.example.com/v1/FUZZ', 
          wordlist: 'api-endpoints',
          headers: { 'Authorization': 'Bearer token123' },
          filter_codes: '401,403,404'
        },
        expectedOutput: 'Valid API endpoints with response analysis'
      },
      {
        name: 'File Extension Discovery',
        description: 'Find files with multiple extensions',
        parameters: { 
          url: 'https://example.com/backup/FUZZ', 
          wordlist: 'files',
          extensions: 'sql,zip,tar,backup',
          threads: 200
        },
        expectedOutput: 'Backup files and sensitive data files'
      }
    ],
    useCases: [
      'Web application security assessment',
      'Bug bounty hunting and vulnerability research',
      'API security testing and endpoint discovery',
      'Content discovery and hidden resource enumeration',
      'Compliance testing for exposed sensitive files'
    ],
    security: {
      riskLevel: 'Medium',
      considerations: [
        'Can generate significant traffic to target server',
        'May trigger web application firewalls (WAF)',
        'High thread counts can impact server performance',
        'Some discovered content may contain sensitive information'
      ],
      legalNote: 'Ensure proper authorization before testing web applications - fuzzing can be detected as attack behavior'
    }
  },
  {
    name: 'nikto_scan',
    description: 'Comprehensive web server scanner testing for over 6700 dangerous files, outdated software, and security misconfigurations',
    category: 'Web Testing',
    dangerLevel: 'caution',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Target URL including protocol and port if non-standard',
        examples: ['https://example.com', 'http://192.168.1.100:8080', 'https://api.example.com'],
        pattern: '^https?://[^\\s/$.?#].[^\\s]*$'
      },
      port: {
        type: 'number',
        required: false,
        description: 'Specific port to scan if different from URL',
        examples: [80, 443, 8080, 8443]
      },
      ssl: {
        type: 'boolean',
        required: false,
        default: false,
        description: 'Force SSL scanning even for HTTP URLs'
      },
      timeout: {
        type: 'number',
        required: false,
        default: 300,
        minimum: 60,
        maximum: 3600,
        description: 'Maximum scan time in seconds'
      },
      plugins: {
        type: 'string',
        required: false,
        description: 'Specific Nikto plugins to run',
        examples: ['@@ALL', '@@NONE', 'apache,auth,cgi']
      },
      evasion: {
        type: 'string',
        required: false,
        description: 'IDS evasion techniques',
        examples: ['1', '2', '3', '4', '5', '6', '7', '8']
      }
    },
    examples: [
      {
        name: 'Standard Web Security Scan',
        description: 'Comprehensive security assessment of a web application',
        parameters: { target: 'https://example.com', timeout: 600 },
        expectedOutput: 'Detailed vulnerability report with OSVDB references'
      },
      {
        name: 'SSL Security Assessment',
        description: 'Focus on SSL/TLS configuration and certificate issues',
        parameters: { target: 'https://secure.example.com', ssl: true, plugins: 'ssl' },
        expectedOutput: 'SSL/TLS security analysis with cipher recommendations'
      },
      {
        name: 'Evasive Scanning',
        description: 'Stealthy scan with IDS evasion techniques',
        parameters: { target: 'https://example.com', evasion: '2,5,8', timeout: 900 },
        expectedOutput: 'Security findings with reduced detection footprint'
      }
    ],
    useCases: [
      'Web application vulnerability assessment',
      'Penetration testing and security auditing',
      'Compliance scanning for security standards',
      'Pre-deployment security validation',
      'Ongoing security monitoring'
    ],
    security: {
      riskLevel: 'Medium',
      considerations: [
        'May detect real vulnerabilities that could be exploited',
        'Generates significant log entries in target systems',
        'Some tests may impact application performance',
        'Results may contain sensitive path information'
      ],
      legalNote: 'Only scan applications you own or have explicit permission to test'
    }
  },
  {
    name: 'workflow_enum',
    description: 'Automated multi-phase reconnaissance workflow orchestrating multiple tools for comprehensive target enumeration',
    category: 'Workflows',
    dangerLevel: 'caution',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Primary target for comprehensive enumeration',
        examples: ['192.168.1.1', 'example.com', '192.168.1.0/24']
      },
      scope: {
        type: 'string',
        required: false,
        default: 'network',
        enum: ['network', 'web', 'full'],
        description: 'Enumeration scope determining tool selection and focus area'
      },
      depth: {
        type: 'string',
        required: false,
        default: 'normal',
        enum: ['light', 'normal', 'deep'],
        description: 'Scan intensity and comprehensiveness level'
      },
      coaching: {
        type: 'string',
        required: false,
        default: 'beginner',
        enum: ['beginner', 'advanced'],
        description: 'Level of guidance and explanation provided during execution'
      },
      timeout: {
        type: 'number',
        required: false,
        default: 1800,
        description: 'Maximum workflow execution time in seconds'
      }
    },
    examples: [
      {
        name: 'Basic Network Enumeration',
        description: 'Standard reconnaissance of an internal network segment',
        parameters: { target: '192.168.1.0/24', scope: 'network', depth: 'normal', coaching: 'beginner' },
        expectedOutput: 'Comprehensive network map with services and potential entry points'
      },
      {
        name: 'Deep Web Application Assessment',
        description: 'Thorough enumeration of web application infrastructure',
        parameters: { target: 'example.com', scope: 'web', depth: 'deep', coaching: 'advanced' },
        expectedOutput: 'Complete web application security profile with detailed findings'
      }
    ],
    useCases: [
      'Initial penetration testing reconnaissance',
      'Security assessment automation',
      'Bug bounty hunting intelligence gathering',
      'Network asset discovery and mapping',
      'Compliance audit preparation'
    ],
    security: {
      riskLevel: 'Medium',
      considerations: [
        'Combines multiple scanning techniques',
        'May generate significant network traffic',
        'Execution time can be substantial for large targets',
        'Provides comprehensive attack surface analysis'
      ],
      legalNote: 'Comprehensive enumeration requires explicit authorization for all target systems'
    }
  },
  {
    name: 'workflow_scan',
    description: 'Advanced vulnerability assessment workflow for systematic security testing with optional exploitation capabilities',
    category: 'Workflows',
    dangerLevel: 'dangerous',
    parameters: {
      target: {
        type: 'string',
        required: true,
        description: 'Target system or application for vulnerability assessment',
        examples: ['192.168.1.100', 'webapp.example.com', 'api.example.com']
      },
      services: {
        type: 'array',
        items: { type: 'string' },
        required: false,
        description: 'Specific services to focus vulnerability testing on',
        examples: [['http', 'https', 'ssh'], ['smtp', 'ftp', 'telnet']]
      },
      aggressive: {
        type: 'boolean',
        required: false,
        default: false,
        description: 'Enable exploitation attempts and proof-of-concept generation'
      },
      coaching: {
        type: 'string',
        required: false,
        default: 'beginner',
        enum: ['beginner', 'advanced'],
        description: 'Level of guidance provided during assessment'
      }
    },
    examples: [
      {
        name: 'Safe Vulnerability Assessment',
        description: 'Non-invasive security scanning without exploitation',
        parameters: { target: '192.168.1.100', services: ['http', 'ssh'], aggressive: false },
        expectedOutput: 'Vulnerability inventory with remediation recommendations'
      },
      {
        name: 'Penetration Testing with Exploitation',
        description: 'Full security assessment including active exploitation',
        parameters: { target: 'testlab.example.com', aggressive: true, coaching: 'advanced' },
        expectedOutput: 'Complete penetration test report with proof-of-concept exploits'
      }
    ],
    useCases: [
      'Comprehensive vulnerability assessment',
      'Penetration testing with exploitation',
      'Security validation and compliance testing',
      'Red team exercises and attack simulation',
      'Post-deployment security verification'
    ],
    security: {
      riskLevel: 'High',
      considerations: [
        'May perform active exploitation attempts',
        'Can cause service disruption if aggressive mode enabled',
        'Requires careful target selection and timing',
        'Results may include working exploit code'
      ],
      legalNote: 'Aggressive scanning with exploitation requires explicit written authorization and controlled environment'
    }
  }
];

const openApiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'RedQuanta MCP API',
    description: `
# 🛡️ RedQuanta MCP - Enterprise Security Orchestration Platform

## 🎯 Overview

RedQuanta MCP Server provides a comprehensive REST API for executing penetration testing tools, managing security workflows, and gathering threat intelligence. This platform is designed for enterprise security teams, AI assistants, automation systems, and security orchestration platforms.

## ✨ Key Features

### 🛠️ **16+ Professional Security Tools**
- **Network Scanning**: Nmap, Masscan with advanced configuration
- **Web Testing**: FFUF, Nikto, SQLMap with intelligent filtering  
- **Password Security**: John the Ripper, Hydra with ethical controls
- **Intelligence**: Web search, domain analysis, OSINT gathering
- **Automation**: Multi-phase workflows with adaptive coaching

### 🛡️ **Enterprise Security Model**
- **Jailed Execution**: All operations run within secure boundaries
- **Audit Logging**: Comprehensive JSONL audit trail for compliance
- **Command Validation**: Advanced injection prevention and argument sanitization
- **Permission Controls**: Explicit dangerous mode requirements for exploitation
- **Rate Limiting**: Built-in protection against abuse

### 🤖 **LLM-Optimized Design**
- **Rich Schemas**: Detailed parameter descriptions with examples
- **Contextual Guidance**: Adaptive coaching based on user experience level
- **Structured Output**: Consistent JSON responses across all tools
- **Error Handling**: Detailed error messages with remediation suggestions

## 🔐 Authentication & Authorization

This API operates under a security-first model:

1. **Authorization Required**: Always obtain written permission before testing any systems
2. **Dangerous Mode**: Exploitation tools require explicit \`--dangerous\` flag
3. **Scope Validation**: All operations are validated against configured security policies
4. **Audit Trail**: Every operation is logged with user context and outcome

## 📊 Rate Limiting & Performance

- **Default Limits**: 100 requests per minute per client
- **Burst Handling**: Short-term burst allowance for workflow operations
- **Caching**: Intelligent caching for repeated operations (20x performance improvement)
- **Progress Tracking**: Real-time progress updates for long-running operations

## 🔧 Error Handling & Reliability

All endpoints return structured error responses with:
- **HTTP Status Codes**: Standard codes for consistent integration
- **Error Details**: Detailed messages with context and remediation suggestions  
- **Request IDs**: Unique identifiers for debugging and support
- **Retry Guidelines**: Clear guidance on retryable vs permanent failures

## 📋 Compliance & Standards

- **SARIF 2.1.0**: Standardized security finding format
- **OpenAPI 3.0.3**: Full specification compliance
- **NIST Framework**: Aligned with cybersecurity framework principles
- **GDPR Compliance**: Privacy-respecting data handling

## 🚀 Getting Started

1. **Health Check**: \`GET /health\` - Verify system status
2. **Tool Discovery**: \`GET /tools\` - List available capabilities
3. **Tool Information**: \`GET /tools/{toolName}/info\` - Get detailed usage guidance
4. **Execute Tools**: \`POST /tools/{toolName}\` - Run security assessments
5. **View Results**: Structured JSON responses with actionable insights

## 🎓 Examples & Use Cases

### Basic Network Reconnaissance
\`\`\`json
POST /tools/nmap_scan
{
  "target": "192.168.1.0/24",
  "ports": "top-1000",
  "profile": "stealth"
}
\`\`\`

### Web Application Security Testing
\`\`\`json
POST /tools/workflow_enum
{
  "target": "example.com",
  "scope": "web",
  "depth": "deep",
  "coaching": "beginner"
}
\`\`\`

### Automated Vulnerability Assessment
\`\`\`json
POST /tools/workflow_scan
{
  "target": "webapp.example.com",
  "services": ["http", "https"],
  "aggressive": false
}
\`\`\`

## ⚖️ Legal & Ethical Guidelines

**IMPORTANT**: This platform is designed for authorized security testing only.

- ✅ **Authorized Testing**: Only scan systems you own or have written permission to test
- ⚠️ **Responsible Disclosure**: Report vulnerabilities through proper channels
- 🛡️ **No Harm Policy**: Avoid actions that could cause system damage or service disruption
- 📋 **Documentation**: Maintain detailed records of all testing activities
- 🔒 **Data Protection**: Secure handling of any sensitive information discovered

Misuse of this platform for unauthorized activities may violate laws and regulations. Users are responsible for ensuring compliance with all applicable legal requirements.
    `,
    version: '0.3.0',
    contact: {
      name: 'RedQuanta Security Team',
      url: 'https://github.com/sc4rfurry/RedQuanta-MCP',
      email: 'security@redquanta.dev'
    },
    license: {
      name: 'MIT License',
      url: 'https://opensource.org/licenses/MIT'
    },
    termsOfService: 'https://github.com/sc4rfurry/RedQuanta-MCP/blob/main/TERMS.md'
  },
  servers: [
    {
      url: 'http://localhost:5891',
      description: 'Local development server'
    },
    {
      url: 'https://api.redquanta.dev',
      description: 'Production server (when available)'
    }
  ],
  tags: [
    {
      name: 'Health',
      description: '🏥 System health monitoring and status verification endpoints',
      externalDocs: {
        description: 'Health Check Documentation',
        url: 'https://github.com/sc4rfurry/RedQuanta-MCP/blob/main/docs/api/health.md'
      }
    },
    {
      name: 'Tools',
      description: '🛠️ Security tool execution and management endpoints',
      externalDocs: {
        description: 'Tools Documentation',
        url: 'https://github.com/sc4rfurry/RedQuanta-MCP/blob/main/docs/api/tools.md'
      }
    },
    {
      name: 'Workflows',
      description: '🔄 Automated multi-tool security workflows',
      externalDocs: {
        description: 'Workflow Documentation',
        url: 'https://github.com/sc4rfurry/RedQuanta-MCP/blob/main/docs/api/workflows.md'
      }
    },
    {
      name: 'Resources',
      description: '📋 System resources and configuration access',
      externalDocs: {
        description: 'Resources Documentation',
        url: 'https://github.com/sc4rfurry/RedQuanta-MCP/blob/main/docs/api/resources.md'
      }
    },
    {
      name: 'Intelligence',
      description: '🧠 Threat intelligence and OSINT capabilities',
      externalDocs: {
        description: 'Intelligence Documentation',
        url: 'https://github.com/sc4rfurry/RedQuanta-MCP/blob/main/docs/api/intelligence.md'
      }
    }
  ],
  components: {
    schemas: {
      HealthResponse: {
        type: 'object',
        description: 'System health status information',
        required: ['status', 'version', 'uptime', 'timestamp'],
        properties: {
          status: {
            type: 'string',
            enum: ['healthy', 'degraded', 'unhealthy'],
            description: 'Overall system health status',
            example: 'healthy'
          },
          version: {
            type: 'string',
            description: 'Server version string',
            example: '0.3.0',
            pattern: '^\\d+\\.\\d+\\.\\d+$'
          },
          mode: {
            type: 'string',
            enum: ['stdio', 'rest', 'hybrid'],
            description: 'Server operation mode',
            example: 'rest'
          },
          platform: {
            type: 'string',
            description: 'Operating system platform',
            example: 'linux',
            enum: ['linux', 'darwin', 'win32']
          },
          uptime: {
            type: 'number',
            description: 'Server uptime in seconds',
            example: 12345.67,
            minimum: 0
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            description: 'Current server timestamp in ISO 8601 format',
            example: '2025-06-24T18:30:00.000Z'
          },
          jailRoot: {
            type: 'string',
            description: 'Configured filesystem jail root directory',
            example: '/opt/redquanta/vol'
          },
          dangerousMode: {
            type: 'boolean',
            description: 'Whether dangerous operations are enabled',
            example: false
          },
          toolsAvailable: {
            type: 'number',
            description: 'Number of available security tools',
            example: 16,
            minimum: 0
          }
        }
      },
      Error: {
        type: 'object',
        required: ['error', 'message', 'timestamp'],
        properties: {
          error: {
            type: 'string',
            description: 'Error type or code',
            example: 'VALIDATION_ERROR'
          },
          message: {
            type: 'string',
            description: 'Human-readable error message',
            example: 'Invalid target parameter: must be valid IP or hostname'
          },
          details: {
            type: 'object',
            description: 'Additional error context and details',
            additionalProperties: true
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            description: 'Error occurrence timestamp',
            example: '2025-06-24T18:30:00.000Z'
          },
          requestId: {
            type: 'string',
            description: 'Unique request identifier for debugging',
            example: 'req_1234567890abcdef'
          },
          suggestions: {
            type: 'array',
            items: { type: 'string' },
            description: 'Suggested remediation actions',
            example: ['Check target format', 'Ensure proper authorization', 'Verify network connectivity']
          }
        }
      },
      ToolExecutionResponse: {
        type: 'object',
        required: ['success', 'tool', 'timestamp'],
        properties: {
          success: {
            type: 'boolean',
            description: 'Indicates if tool execution completed successfully'
          },
          tool: {
            type: 'string',
            description: 'Name of the executed tool',
            example: 'nmap_scan'
          },
          target: {
            type: 'string',
            description: 'Target that was scanned or tested',
            example: '192.168.1.100'
          },
          timestamp: {
            type: 'string',
            format: 'date-time',
            description: 'Execution start timestamp'
          },
          duration: {
            type: 'number',
            description: 'Execution time in milliseconds',
            example: 15420,
            minimum: 0
          },
          results: {
            type: 'object',
            description: 'Tool-specific results and findings',
            additionalProperties: true
          },
          metadata: {
            type: 'object',
            description: 'Execution metadata and statistics',
            properties: {
              command: { type: 'string', description: 'Actual command executed' },
              args: { type: 'array', items: { type: 'string' }, description: 'Command arguments' },
              exitCode: { type: 'number', description: 'Process exit code' },
              dangerous: { type: 'boolean', description: 'Whether dangerous mode was used' },
              user: { type: 'string', description: 'User context for audit' }
            }
          },
          coaching: {
            type: 'array',
            items: { type: 'string' },
            description: 'Contextual guidance and next steps'
          },
          warnings: {
            type: 'array',
            items: { type: 'string' },
            description: 'Important warnings or considerations'
          }
        }
      }
    },
    responses: {
      Unauthorized: {
        description: 'Authentication required or insufficient permissions',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/Error' },
            example: {
              error: 'UNAUTHORIZED',
              message: 'This operation requires explicit authorization',
              timestamp: '2025-06-24T18:30:00.000Z',
              suggestions: ['Ensure proper authentication', 'Verify permissions', 'Check dangerous mode requirements']
            }
          }
        }
      },
      RateLimited: {
        description: 'Rate limit exceeded',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/Error' },
            example: {
              error: 'RATE_LIMITED',
              message: 'Rate limit exceeded: 100 requests per minute',
              timestamp: '2025-06-24T18:30:00.000Z',
              suggestions: ['Reduce request frequency', 'Implement exponential backoff', 'Contact support for higher limits']
            }
          }
        }
      },
      NotFound: {
        description: 'Resource not found',
        content: {
          'application/json': {
            schema: { $ref: '#/components/schemas/Error' },
            example: {
              error: 'NOT_FOUND',
              message: 'Tool or resource not found',
              timestamp: '2025-06-24T18:30:00.000Z',
              suggestions: ['Check tool name spelling', 'Use GET /tools to list available tools', 'Verify API endpoint']
            }
          }
        }
      }
    },
    securitySchemes: {
      ApiKeyAuth: {
        type: 'apiKey',
        in: 'header',
        name: 'X-API-Key',
        description: 'API key for authentication (when configured)'
      },
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'JWT bearer token authentication (when configured)'
      }
    }
  },
  paths: {
    '/health': {
      get: {
        tags: ['Health'],
        summary: 'System Health Check',
        description: 'Returns comprehensive system health information including uptime, version, operational status, and tool availability. Use this endpoint to verify the server is running and responsive.',
        operationId: 'getHealth',
        responses: {
          '200': {
            description: 'System is healthy and operational',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/HealthResponse' },
                examples: {
                  healthy: {
                    summary: 'Healthy system with all tools available',
                    value: {
                      status: 'healthy',
                      version: '0.3.0',
                      mode: 'rest',
                      platform: 'linux',
                      uptime: 12345.67,
                      timestamp: '2025-06-24T18:30:00.000Z',
                      jailRoot: '/opt/redquanta/vol',
                      dangerousMode: false,
                      toolsAvailable: 16
                    }
                  },
                  degraded: {
                    summary: 'System operational but some tools unavailable',
                    value: {
                      status: 'degraded',
                      version: '0.3.0',
                      mode: 'rest',
                      platform: 'win32',
                      uptime: 5432.10,
                      timestamp: '2025-06-24T18:30:00.000Z',
                      jailRoot: 'C:\\redquanta\\vol',
                      dangerousMode: false,
                      toolsAvailable: 12
                    }
                  }
                }
              }
            }
          }
        }
      }
    },
    '/tools': {
      get: {
        tags: ['Tools'],
        summary: 'List Available Security Tools',
        description: 'Returns a comprehensive list of all available penetration testing tools with their categories, capabilities, and current status. Use this endpoint to discover available functionality before executing specific tools.',
        operationId: 'listTools',
        responses: {
          '200': {
            description: 'List of available security tools with metadata',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['tools', 'totalTools', 'categories'],
                  properties: {
                    tools: {
                      type: 'array',
                      items: {
                        type: 'object',
                        properties: {
                          name: { type: 'string', description: 'Tool identifier' },
                          description: { type: 'string', description: 'Brief tool description' },
                          category: { type: 'string', description: 'Tool category' },
                          dangerLevel: { type: 'string', enum: ['safe', 'caution', 'dangerous'] },
                          available: { type: 'boolean', description: 'Tool availability status' }
                        }
                      }
                    },
                    totalTools: { type: 'number', description: 'Total number of tools' },
                    categories: {
                      type: 'object',
                      additionalProperties: {
                        type: 'array',
                        items: { type: 'string' }
                      },
                      description: 'Tools organized by category'
                    }
                  }
                },
                examples: {
                  fullList: {
                    summary: 'Complete tools inventory',
                    value: {
                      tools: [
                        { name: 'nmap_scan', description: 'Network discovery and port scanning', category: 'Network Scanning', dangerLevel: 'caution', available: true },
                        { name: 'ffuf_fuzz', description: 'Fast web fuzzing', category: 'Web Testing', dangerLevel: 'caution', available: true },
                        { name: 'workflow_enum', description: 'Automated enumeration', category: 'Workflows', dangerLevel: 'caution', available: true }
                      ],
                      totalTools: 16,
                      categories: {
                        'Network Scanning': ['nmap_scan', 'masscan_scan'],
                        'Web Testing': ['ffuf_fuzz', 'nikto_scan'],
                        'Workflows': ['workflow_enum', 'workflow_scan']
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
};

// Generate tool-specific paths
toolSchemas.forEach(tool => {
  const toolPath = `/tools/${tool.name}`;
  const infoPath = `/tools/${tool.name}/info`;

  // Tool execution endpoint
  openApiSpec.paths[toolPath] = {
    post: {
      tags: [tool.category === 'Workflows' ? 'Workflows' : 'Tools'],
      summary: `Execute ${tool.name}`,
      description: `${tool.description}\n\n**Security Level**: ${tool.dangerLevel.toUpperCase()}\n\n**Legal Notice**: ${tool.security.legalNote}`,
      operationId: `execute_${tool.name}`,
      requestBody: {
        description: `Parameters for ${tool.name} execution`,
        required: true,
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: tool.parameters,
              required: Object.entries(tool.parameters)
                .filter(([_, param]) => param.required)
                .map(([name, _]) => name)
            },
            examples: tool.examples.reduce((acc, example, index) => {
              acc[`example_${index + 1}`] = {
                summary: example.name,
                description: example.description,
                value: example.parameters
              };
              return acc;
            }, {} as Record<string, any>)
          }
        }
      },
      responses: {
        '200': {
          description: `${tool.name} execution completed successfully`,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/ToolExecutionResponse' }
            }
          }
        },
        '400': { $ref: '#/components/responses/Unauthorized' },
        '401': { $ref: '#/components/responses/Unauthorized' },
        '404': { $ref: '#/components/responses/NotFound' },
        '429': { $ref: '#/components/responses/RateLimited' }
      }
    }
  };

  // Tool info endpoint
  openApiSpec.paths[infoPath] = {
    get: {
      tags: ['Tools'],
      summary: `Get ${tool.name} Information`,
      description: `Retrieve comprehensive information about ${tool.name} including parameters, examples, use cases, and security considerations.`,
      operationId: `get_${tool.name}_info`,
      responses: {
        '200': {
          description: `Detailed information about ${tool.name}`,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  name: { type: 'string', example: tool.name },
                  description: { type: 'string', example: tool.description },
                  category: { type: 'string', example: tool.category },
                  dangerLevel: { type: 'string', example: tool.dangerLevel },
                  parameters: { type: 'object', description: 'Parameter specifications' },
                  examples: { type: 'array', description: 'Usage examples' },
                  useCases: { type: 'array', items: { type: 'string' }, example: tool.useCases },
                  security: { type: 'object', description: 'Security considerations' }
                }
              }
            }
          }
        },
        '404': { $ref: '#/components/responses/NotFound' }
      }
    }
  };
});

// Ensure docs/api directory exists
const outputDir = 'docs/api';
try {
  mkdirSync(outputDir, { recursive: true });
} catch (error) {
  // Directory might already exist
}

// Write the enhanced OpenAPI specification
const outputPath = `${outputDir}/openapi.json`;
writeFileSync(outputPath, JSON.stringify(openApiSpec, null, 2));

console.log('✅ Enhanced OpenAPI specification generated successfully');
console.log(`📄 File: ${outputPath}`);
console.log(`🔧 Tools documented: ${toolSchemas.length}`);
console.log(`📊 Total endpoints: ${Object.keys(openApiSpec.paths).length}`); 