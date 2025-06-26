/**
 * Argument Guard Utility - Prevents command injection attacks
 * 
 * This module provides secure argument handling with the following features:
 * - Command injection pattern detection
 * - Shell metacharacter sanitization  
 * - Argument allowlist validation
 * - Command allowlist enforcement
 * - Docker fallback support
 */

import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { platform } from 'os';

interface CommandConfig {
  allowed: Record<string, {
    path: string;
    script?: string;
    minVersion: string;
    allowedArgs: string[];
    dangerousArgs: string[];
    requiresDangerous: boolean;
  }>;
  denied: {
    patterns: string[];
    commands: string[];
  };
}

interface DeniedPatterns {
  commandInjection: string[];
  pathTraversal: string[];
  shellMetacharacters: string[];
  dangerousCommands: string[];
  sensitiveData: string[];
  networkAccess: string[];
}

export class ArgGuard {
  private commandConfig: CommandConfig;
  private deniedPatterns: DeniedPatterns;

  constructor(
    commandConfigPath?: string,
    deniedPatternsPath?: string
  ) {
    // Get the project root directory (two levels up from this file)
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const projectRoot = resolve(__dirname, '../..');
    
    // Use OS-intelligent configuration file selection
    const configPath = commandConfigPath || this.getOSSpecificConfigPath(projectRoot);
    const patternsPath = deniedPatternsPath || resolve(projectRoot, 'config/deniedPatterns.json');
    
    try {
      this.commandConfig = JSON.parse(readFileSync(configPath, 'utf-8'));
      this.deniedPatterns = JSON.parse(readFileSync(patternsPath, 'utf-8'));
    } catch (error) {
      throw new Error(`Failed to load ArgGuard configuration: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get OS-specific configuration file path
   * 
   * @param projectRoot - Project root directory
   * @returns Path to appropriate configuration file
   */
  private getOSSpecificConfigPath(projectRoot: string): string {
    const currentPlatform = platform();
    
    if (currentPlatform === 'win32') {
      const windowsConfigPath = resolve(projectRoot, 'config/allowedCommands-windows.json');
      try {
        // Check if Windows-specific config exists
        readFileSync(windowsConfigPath, 'utf-8');
        return windowsConfigPath;
      } catch {
        // Fall back to default config if Windows-specific doesn't exist
        return resolve(projectRoot, 'config/allowedCommands.json');
      }
    }
    
    // Use default config for non-Windows platforms
    return resolve(projectRoot, 'config/allowedCommands.json');
  }

  /**
   * Validates and sanitizes command and arguments
   * 
   * @param command - Command to execute
   * @param args - Command arguments
   * @param dangerousEnabled - Whether dangerous operations are enabled
   * @returns Validated command and arguments
   * @throws Error if command or arguments are invalid
   */
  public validateCommand(
    command: string,
    args: string[] = [],
    dangerousEnabled: boolean = false
  ): { command: string; args: string[]; script?: string } {
    // Check if command is in allowlist
    const commandConfig = this.commandConfig.allowed[command];
    if (!commandConfig) {
      throw new Error(`Command not allowed: ${command}`);
    }

    // Check if dangerous flag is required
    if (commandConfig.requiresDangerous && !dangerousEnabled) {
      throw new Error(`Command ${command} requires --dangerous flag`);
    }

    // Validate each argument
    const sanitizedArgs = args.map(arg => this.sanitizeArgument(arg));
    
    // Check arguments against command-specific allowlist
    for (const arg of sanitizedArgs) {
      this.validateArgument(command, arg, dangerousEnabled);
    }

    const result: { command: string; args: string[]; script?: string } = {
      command: commandConfig.path,
      args: sanitizedArgs
    };
    
    if (commandConfig.script) {
      result.script = commandConfig.script;
    }
    
    return result;
  }

  /**
   * Sanitizes a single argument
   * 
   * @param arg - Argument to sanitize
   * @returns Sanitized argument
   * @throws Error if argument contains dangerous patterns
   */
  private sanitizeArgument(arg: string): string {
    // Check for command injection patterns
    for (const pattern of this.deniedPatterns.commandInjection) {
      const regex = new RegExp(pattern, 'g');
      if (regex.test(arg)) {
        throw new Error(`Command injection detected in argument: ${arg}`);
      }
    }

    // Check for path traversal patterns
    for (const pattern of this.deniedPatterns.pathTraversal) {
      const regex = new RegExp(pattern, 'g');
      if (regex.test(arg)) {
        throw new Error(`Path traversal detected in argument: ${arg}`);
      }
    }

    // Check for shell metacharacters
    for (const pattern of this.deniedPatterns.shellMetacharacters) {
      const regex = new RegExp(pattern, 'g');
      if (regex.test(arg)) {
        throw new Error(`Shell metacharacter detected in argument: ${arg}`);
      }
    }

    // Check for dangerous commands
    for (const dangerousCmd of this.deniedPatterns.dangerousCommands) {
      if (arg.toLowerCase().includes(dangerousCmd.toLowerCase())) {
        throw new Error(`Dangerous command detected in argument: ${arg}`);
      }
    }

    return arg;
  }

  /**
   * Validates argument against command-specific allowlist
   * 
   * @param command - Command name
   * @param arg - Argument to validate
   * @param dangerousEnabled - Whether dangerous operations are enabled
   * @throws Error if argument is not allowed
   */
  private validateArgument(
    command: string, 
    arg: string, 
    dangerousEnabled: boolean
  ): void {
    const commandConfig = this.commandConfig.allowed[command];
    if (!commandConfig) return;

    // Skip validation for file paths and values (not flags)
    if (!arg.startsWith('-')) return;

    // Extract flag name (remove values after =)
    const flag = arg.split('=')[0];
    if (!flag) return;

    // Check if it's a dangerous argument
    if (commandConfig.dangerousArgs.includes(flag)) {
      if (!dangerousEnabled) {
        throw new Error(`Dangerous argument ${flag} requires --dangerous flag`);
      }
      return; // Allow dangerous args if flag is set
    }

    // Check if argument is in allowlist
    const isAllowed = commandConfig.allowedArgs.some(allowedArg => {
      // Handle exact matches and prefix matches for complex flags
      return flag === allowedArg || 
             flag.startsWith(allowedArg + '=') ||
             allowedArg.includes('*') && this.matchesPattern(flag, allowedArg);
    });

    if (!isAllowed) {
      throw new Error(`Argument not allowed for ${command}: ${flag}`);
    }
  }

  /**
   * Matches argument against pattern (supports wildcards)
   * 
   * @param arg - Argument to match
   * @param pattern - Pattern to match against
   * @returns true if matches
   */
  private matchesPattern(arg: string, pattern: string): boolean {
    const regex = new RegExp(pattern.replace(/\*/g, '.*'));
    return regex.test(arg);
  }

  /**
   * Scrubs sensitive data from output
   * 
   * @param output - Command output to scrub
   * @returns Scrubbed output
   */
  public scrubSensitiveData(output: string): string {
    let scrubbed = output;

    // Replace sensitive data patterns
    for (const pattern of this.deniedPatterns.sensitiveData) {
      const regex = new RegExp(`${pattern}[=:]\\s*([^\\s]+)`, 'gi');
      scrubbed = scrubbed.replace(regex, `${pattern}=[REDACTED]`);
    }

    // Replace potential IP addresses in private ranges
    for (const pattern of this.deniedPatterns.networkAccess) {
      const regex = new RegExp(pattern, 'g');
      scrubbed = scrubbed.replace(regex, '[REDACTED_IP]');
    }

    return scrubbed;
  }

  /**
   * Creates Docker command arguments for fallback execution
   * 
   * @param command - Original command
   * @param args - Original arguments
   * @param image - Docker image to use
   * @returns Docker command arguments
   */
  public createDockerCommand(
    command: string, 
    args: string[], 
    image: string
  ): { command: string; args: string[] } {
    const dockerArgs = [
      'run',
      '--rm',
      '-i',
      '--network', 'none',
      '--read-only',
      '--tmpfs', '/tmp:noexec,nosuid,size=100m',
      '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--user', '65534:65534', // nobody:nogroup
      image,
      command,
      ...args
    ];

    return {
      command: 'docker',
      args: dockerArgs
    };
  }

  /**
   * Validates if command exists in allowlist
   * 
   * @param command - Command to validate
   * @returns true if command is allowed
   */
  public isCommandAllowed(command: string): boolean {
    return command in this.commandConfig.allowed;
  }

  /**
   * Gets command configuration
   * 
   * @param command - Command name
   * @returns Command configuration or undefined
   */
  public getCommandConfig(command: string) {
    return this.commandConfig.allowed[command];
  }

  /**
   * Checks if command requires dangerous flag
   * 
   * @param command - Command name
   * @returns true if requires dangerous flag
   */
  public requiresDangerous(command: string): boolean {
    const config = this.commandConfig.allowed[command];
    return config?.requiresDangerous ?? false;
  }
} 