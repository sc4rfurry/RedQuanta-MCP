#!/usr/bin/env node
/**
 * RedQuanta MCP CLI - Command Line Interface
 * 
 * Provides command-line access to all RedQuanta MCP functionality
 */

import { Command } from 'commander';
import { readFileSync } from 'fs';
import { RedQuantaMCPServer } from './server.js';
import { WorkflowEngine } from './core/workflowEngine.js';
import { AuditLogger } from './utils/auditLogger.js';
import { ArgGuard } from './utils/argGuard.js';
import { PathGuard } from './utils/pathGuard.js';
import pino from 'pino';

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'));

const program = new Command();

program
  .name('redquanta-mcp')
  .description('Cross-platform, security-hardened MCP server for penetration testing')
  .version(pkg.version);

program
  .command('server')
  .description('Start the RedQuanta MCP server')
  .option('-m, --mode <mode>', 'Server mode (stdio|rest)', 'stdio')
  .option('-p, --port <port>', 'REST API port', '5891')
  .option('-h, --host <host>', 'REST API host', 'localhost')
  .option('-l, --log-level <level>', 'Log level (debug|info|warn|error)', 'info')
  .option('--dangerous', 'Enable dangerous operations (required for exploitation)')
  .option('--jail-root <path>', 'Filesystem jail root path')
  .option('--telemetry <endpoint>', 'OpenTelemetry endpoint')
  .action(async (options: any) => {
    // Set environment variables from CLI options
    process.env.MCP_MODE = options.mode;
    process.env.PORT = options.port;
    process.env.HOST = options.host;
    process.env.LOG_LEVEL = options.logLevel;
    
    if (options.dangerous) {
      process.env.DANGEROUS_MODE = 'true';
    }
    
    if (options.jailRoot) {
      process.env.JAIL_ROOT = options.jailRoot;
    }
    
    if (options.telemetry) {
      process.env.TELEMETRY_ENDPOINT = options.telemetry;
    }

    console.log('🛡️ Starting RedQuanta MCP Server...');
    console.log(`Mode: ${options.mode}`);
    console.log(`Log Level: ${options.logLevel}`);
    
    if (options.dangerous) {
      console.log('⚠️  Dangerous mode enabled');
    }

    const server = new RedQuantaMCPServer();
    await server.start();
  });

program
  .command('enum')
  .description('Run enumeration workflow')
  .argument('<target>', 'Target IP, hostname, or CIDR range')
  .option('-s, --scope <scope>', 'Enumeration scope (network|web|full)', 'network')
  .option('-d, --depth <depth>', 'Scan depth (light|normal|deep)', 'normal')
  .option('-c, --coaching <level>', 'Coaching level (beginner|advanced)', 'beginner')
  .option('--dangerous', 'Enable dangerous operations')
  .action(async (target: string, options: any) => {
    console.log('🎯 Starting enumeration workflow...');
    console.log(`Target: ${target}`);
    console.log(`Scope: ${options.scope}`);
    console.log(`Depth: ${options.depth}`);
    console.log(`Coaching: ${options.coaching}`);
    
    if (options.dangerous) {
      console.log('⚠️  Dangerous mode enabled');
      process.env.DANGEROUS_MODE = 'true';
    }

    try {
      // Initialize workflow engine with proper dependencies
      const logger = pino({ level: 'info' });
      const auditLogger = new AuditLogger();
      const argGuard = new ArgGuard();
      const pathGuard = new PathGuard();
      
      console.log('🔧 Initializing workflow engine...');
      const workflowEngine = new WorkflowEngine(logger, auditLogger, argGuard, pathGuard);
      
      console.log('🚀 Executing enumeration workflow...');
      const startTime = Date.now();
      
      const result = await workflowEngine.executeEnumeration(
        target,
        options.scope as 'network' | 'web' | 'full',
        options.depth as 'light' | 'normal' | 'deep',
        options.coaching as 'beginner' | 'advanced'
      );
      
      const duration = Date.now() - startTime;
      
      console.log('\n📊 ENUMERATION RESULTS:');
      console.log('========================');
      console.log(`✅ Success: ${result.success}`);
      console.log(`⏱️  Duration: ${duration}ms (${(duration/1000).toFixed(2)}s)`);
      console.log(`🎯 Target: ${result.target}`);
      console.log(`🔍 Phase: ${result.phase}`);
      
      if (result.results && Object.keys(result.results).length > 0) {
        console.log('\n🔍 DISCOVERED ASSETS:');
        Object.entries(result.results).forEach(([key, value]: [string, any]) => {
          console.log(`  ${key}: ${JSON.stringify(value.success ? 'Completed' : 'Failed')}`);
        });
      }
      
      if (result.errors && result.errors.length > 0) {
        console.log('\n❌ ERRORS ENCOUNTERED:');
        result.errors.forEach(error => console.log(`  • ${error}`));
      }
      
      if (result.coaching && result.coaching.length > 0) {
        console.log('\n💡 COACHING GUIDANCE:');
        result.coaching.forEach(tip => console.log(`  ${tip}`));
      }
      
      if (result.nextSteps && result.nextSteps.length > 0) {
        console.log('\n➡️  NEXT STEPS:');
        result.nextSteps.forEach(step => console.log(`  • ${step}`));
      }
      
      console.log('\n✅ Enumeration workflow completed successfully!');
      
    } catch (error) {
      console.error('\n❌ Enumeration workflow failed:');
      console.error(error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('scan') 
  .description('Run vulnerability scanning workflow')
  .argument('<target>', 'Target from enumeration phase')
  .option('-s, --services <services>', 'Comma-separated list of services to scan')
  .option('-a, --aggressive', 'Enable aggressive scanning')
  .option('-c, --coaching <level>', 'Coaching level (beginner|advanced)', 'beginner')
  .option('--dangerous', 'Enable dangerous operations')
  .action(async (target: string, options: any) => {
    console.log('🔍 Starting vulnerability scanning...');
    console.log(`Target: ${target}`);
    
    if (options.services) {
      console.log(`Services: ${options.services}`);
    }
    
    if (options.aggressive) {
      console.log('⚡ Aggressive scanning enabled');
    }

    if (options.dangerous) {
      console.log('⚠️  Dangerous mode enabled');
      process.env.DANGEROUS_MODE = 'true';
    }

    try {
      // Initialize workflow engine with proper dependencies
      const logger = pino({ level: 'info' });
      const auditLogger = new AuditLogger();
      const argGuard = new ArgGuard();
      const pathGuard = new PathGuard();
      
      console.log('🔧 Initializing workflow engine...');
      const workflowEngine = new WorkflowEngine(logger, auditLogger, argGuard, pathGuard);
      
      // Parse services if provided
      const services = options.services ? options.services.split(',').map((s: string) => s.trim()) : [];
      
      console.log('🚀 Executing vulnerability scanning workflow...');
      const startTime = Date.now();
      
      const result = await workflowEngine.executeScan(
        target,
        services,
        options.aggressive || false,
        options.coaching as 'beginner' | 'advanced'
      );
      
      const duration = Date.now() - startTime;
      
      console.log('\n📊 VULNERABILITY SCAN RESULTS:');
      console.log('===============================');
      console.log(`✅ Success: ${result.success}`);
      console.log(`⏱️  Duration: ${duration}ms (${(duration/1000).toFixed(2)}s)`);
      console.log(`🎯 Target: ${result.target}`);
      console.log(`🔍 Phase: ${result.phase}`);
      
      if (result.results && Object.keys(result.results).length > 0) {
        console.log('\n🛡️ SECURITY ASSESSMENT:');
        Object.entries(result.results).forEach(([key, value]: [string, any]) => {
          if (key === 'vulnerability_scan' && value.summary) {
            console.log(`  Total Tests: ${value.summary.totalTests}`);
            console.log(`  Successful Tests: ${value.summary.successfulTests}`);
            console.log(`  Vulnerabilities Found: ${value.summary.vulnerabilitiesFound}`);
          } else {
            console.log(`  ${key}: ${JSON.stringify(value.success ? 'Completed' : 'Failed')}`);
          }
        });
      }
      
      if (result.errors && result.errors.length > 0) {
        console.log('\n❌ ERRORS ENCOUNTERED:');
        result.errors.forEach(error => console.log(`  • ${error}`));
      }
      
      if (result.coaching && result.coaching.length > 0) {
        console.log('\n💡 COACHING GUIDANCE:');
        result.coaching.forEach(tip => console.log(`  ${tip}`));
      }
      
      if (result.nextSteps && result.nextSteps.length > 0) {
        console.log('\n➡️  NEXT STEPS:');
        result.nextSteps.forEach(step => console.log(`  • ${step}`));
      }
      
      console.log('\n✅ Vulnerability scanning workflow completed successfully!');
      
    } catch (error) {
      console.error('\n❌ Vulnerability scanning workflow failed:');
      console.error(error instanceof Error ? error.message : 'Unknown error');
      process.exit(1);
    }
  });

program
  .command('tools')
  .description('List available pentesting tools')
  .action(() => {
    console.log('🛠️  Available RedQuanta MCP Tools:');
    console.log('');
    
    const tools = [
      { name: 'nmap_scan', desc: 'Network discovery and port scanning' },
      { name: 'masscan_scan', desc: 'High-speed port scanning' },
      { name: 'ffuf_fuzz', desc: 'Web fuzzing and directory discovery' },
      { name: 'gobuster_scan', desc: 'Directory and DNS enumeration' },
      { name: 'nikto_scan', desc: 'Web vulnerability scanning' },
      { name: 'sqlmap_test', desc: 'SQL injection testing' },
      { name: 'john_crack', desc: 'Password cracking' },
      { name: 'hydra_bruteforce', desc: 'Network service brute forcing' },
      { name: 'workflow_enum', desc: 'Automated enumeration workflow' },
      { name: 'workflow_scan', desc: 'Automated vulnerability scanning' },
      { name: 'workflow_report', desc: 'Report generation' },
      { name: 'filesystem_*', desc: 'Secure filesystem operations' },
      { name: 'command_run', desc: 'Secure command execution' },
    ];

    tools.forEach(tool => {
      console.log(`  ${tool.name.padEnd(20)} - ${tool.desc}`);
    });
    
    console.log('');
    console.log('Use --dangerous flag for exploitation tools');
  });

program
  .command('config')
  .description('Show configuration information')
  .action(() => {
    console.log('🔧 RedQuanta MCP Configuration:');
    console.log('');
    console.log(`Version: ${pkg.version}`);
    console.log(`Platform: ${process.platform}`);
    console.log(`Node.js: ${process.version}`);
    console.log(`Architecture: ${process.arch}`);
    console.log('');
    console.log('Configuration files:');
    console.log('  config/allowedCommands.json - Command allowlist');
    console.log('  config/allowedPaths.json - Filesystem allowlist');
    console.log('  config/deniedPatterns.json - Security patterns');
    console.log('');
    console.log('Environment variables:');
    console.log('  JAIL_ROOT - Filesystem jail root');
    console.log('  MCP_MODE - Server mode (stdio|rest)');
    console.log('  MCP_PORT - REST API port');
    console.log('  LOG_LEVEL - Logging level');
    console.log('  TELEMETRY_ENDPOINT - OpenTelemetry endpoint');
  });

program
  .command('doctor')
  .description('Check system requirements and tool availability')
  .action(async () => {
    console.log('🏥 RedQuanta MCP System Check:');
    console.log('');

    // Check Node.js version
    const nodeVersion = process.version;
    const versionPart = nodeVersion.slice(1).split('.')[0];
    const nodeMajor = versionPart ? parseInt(versionPart) : 0;
    
    console.log(`✅ Node.js ${nodeVersion} ${nodeMajor >= 20 ? '(OK)' : '(⚠️  Requires v20+)'}`);
    
    // Check platform
    console.log(`✅ Platform: ${process.platform} ${process.arch}`);
    
    // Check Docker availability (simplified)
    console.log('🐳 Docker availability: Not checked in this version');
    
    // Check config files
    try {
      readFileSync('config/allowedCommands.json');
      console.log('✅ Config: allowedCommands.json found');
    } catch {
      console.log('❌ Config: allowedCommands.json missing');
    }
    
    try {
      readFileSync('config/allowedPaths.json');
      console.log('✅ Config: allowedPaths.json found');
    } catch {
      console.log('❌ Config: allowedPaths.json missing');
    }

    console.log('');
    console.log('🛠️  Tool availability check requires full server startup');
    console.log('💡 Run `redquanta-mcp server` to perform complete tool detection');
  });

// Error handling
program.configureHelp({
  sortSubcommands: true,
});

program.on('command:*', () => {
  console.error('❌ Invalid command: %s\n', program.args.join(' '));
  console.log('💡 See --help for available commands');
  process.exit(1);
});

// Parse command line arguments
if (process.argv.length <= 2) {
  program.help();
}

program.parse(); 