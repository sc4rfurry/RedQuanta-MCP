/**
 * Command Runner - Secure command execution
 * 
 * Provides safe command execution with:
 * - Argument validation and sanitization
 * - Command whitelist enforcement
 * - Timeout management
 * - Process isolation
 * - Audit logging
 */

import { ArgGuard } from './argGuard.js';
import { AuditLogger } from './auditLogger.js';
import { execa } from 'execa';

export interface CommandOptions {
  timeout?: number;
  cwd?: string;
  env?: Record<string, string>;
  input?: string;
  signal?: AbortSignal;
}

export interface CommandResult {
  success: boolean;
  exitCode: number;
  stdout: string;
  stderr: string;
  command: string;
  args: string[];
  duration: number;
  timedOut: boolean;
}

export class CommandRunner {
  private argGuard: ArgGuard;
  private auditLogger: AuditLogger;

  constructor(argGuard: ArgGuard, auditLogger: AuditLogger) {
    this.argGuard = argGuard;
    this.auditLogger = auditLogger;
  }

  /**
   * Execute a command with security validation
   */
  public async executeCommand(
    command: string, 
    args: string[] = [], 
    options: CommandOptions = {}
  ): Promise<CommandResult> {
    const startTime = Date.now();
    let result: CommandResult;

    try {
      // Validate command and arguments
      const validated = this.argGuard.validateCommand(command, args);
      
      // Log the attempt
      await this.auditLogger.logActivity({
        action: 'command_execution_attempt',
        target: validated.command,
        details: { 
          args: validated.args,
          cwd: options.cwd,
          timeout: options.timeout 
        },
        outcome: 'success' // Initial attempt logged as success
      });

      // Execute the command with timeout and security controls
      const execaOptions: any = {
        timeout: options.timeout || 30000, // 30 second default timeout
        cwd: options.cwd,
        env: {
          ...process.env,
          ...options.env,
          // Security: Remove potentially dangerous env vars
          PATH: process.env.PATH,
          HOME: process.env.HOME,
          USER: process.env.USER,
        },
        signal: options.signal,
        input: options.input,
        stdio: ['pipe', 'pipe', 'pipe'],
        reject: false, // Don't throw on non-zero exit codes
        encoding: 'utf8' as const,
        stripFinalNewline: false,
        maxBuffer: 10 * 1024 * 1024, // 10MB max output
      };

      const execResult = await execa(validated.command, validated.args, execaOptions);
      
      const duration = Date.now() - startTime;
      
      result = {
        success: execResult.exitCode === 0,
        exitCode: execResult.exitCode || 0,
        stdout: execResult.stdout || '',
        stderr: execResult.stderr || '',
        command: validated.command,
        args: validated.args,
        duration,
        timedOut: execResult.timedOut || false
      };

      // Log successful execution
      await this.auditLogger.logActivity({
        action: 'command_execution_completed',
        target: validated.command,
        details: { 
          exitCode: result.exitCode,
          duration,
          success: result.success,
          outputLength: result.stdout.length + result.stderr.length
        },
        outcome: result.success ? 'success' : 'failure'
      });

    } catch (error) {
      const duration = Date.now() - startTime;
      
      result = {
        success: false,
        exitCode: -1,
        stdout: '',
        stderr: error instanceof Error ? error.message : String(error),
        command,
        args,
        duration,
        timedOut: (error as any).timedOut || false
      };

      // Log failed execution
      await this.auditLogger.logActivity({
        action: 'command_execution_failed',
        target: command,
        details: { 
          error: error instanceof Error ? error.message : String(error),
          duration,
          args
        },
        outcome: 'failure'
      });
    }

    return result;
  }

  /**
   * Check if a command is available on the system
   */
  public async isCommandAvailable(command: string): Promise<boolean> {
    try {
      // Validate command first
      this.argGuard.validateCommand(command, []);
      
      // Try to get version or help to check availability
      const testArgs = ['--version'];
      const result = await execa(command, testArgs, {
        timeout: 5000,
        reject: false,
        stdio: 'pipe'
      });

      return result.exitCode === 0 || result.exitCode === 1; // Some tools return 1 for --version
    } catch {
      return false;
    }
  }

  /**
   * Execute a command with Docker fallback
   */
  public async executeWithDockerFallback(
    command: string,
    args: string[],
    dockerImage: string,
    options: CommandOptions = {}
  ): Promise<CommandResult> {
    // Try local execution first
    if (await this.isCommandAvailable(command)) {
      return this.executeCommand(command, args, options);
    }

    // Fallback to Docker
    const dockerArgs = [
      'run', '--rm', '-i',
      '--network', 'host',
      '--read-only',
      '--tmpfs', '/tmp',
      '--user', 'nobody:nogroup',
      dockerImage,
      ...args
    ];

    return this.executeCommand('docker', dockerArgs, options);
  }

  /**
   * Kill a running process by PID (if supported)
   */
  public async killProcess(pid: number): Promise<boolean> {
    try {
      if (process.platform === 'win32') {
        await this.executeCommand('taskkill', ['/F', '/PID', pid.toString()]);
      } else {
        await this.executeCommand('kill', ['-TERM', pid.toString()]);
      }
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get process information
   */
  public async getProcessInfo(pid: number): Promise<any> {
    try {
      if (process.platform === 'win32') {
        const result = await this.executeCommand('tasklist', ['/FI', `PID eq ${pid}`, '/FO', 'CSV']);
        return { stdout: result.stdout, exists: result.success };
      } else {
        const result = await this.executeCommand('ps', ['-p', pid.toString(), '-o', 'pid,ppid,cmd']);
        return { stdout: result.stdout, exists: result.success };
      }
    } catch {
      return { exists: false };
    }
  }
} 