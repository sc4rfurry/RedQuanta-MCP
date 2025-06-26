/**
 * Audit Logger - Security event logging
 */

import { writeFile, mkdir } from 'fs/promises';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

export interface AuditEvent {
  timestamp: string;
  level: 'info' | 'warn' | 'error';
  action: string;
  user?: string;
  target?: string;
  outcome: 'success' | 'failure';
  details?: Record<string, any>;
}

export class AuditLogger {
  private logDir: string;
  private initialized: boolean = false;

  constructor(logDir?: string) {
    // Determine the project root directory dynamically
    const projectRoot = this.findProjectRoot();
    
    // Use provided logDir or default to logs in project root
    if (logDir) {
      this.logDir = resolve(logDir);
    } else {
      this.logDir = resolve(projectRoot, 'logs');
    }
  }

  private findProjectRoot(): string {
    try {
      // Try to find project root by looking for package.json
      let currentDir = process.cwd();
      const fs = require('fs');
      
      // First check if we're already in the project directory
      if (fs.existsSync(join(currentDir, 'package.json'))) {
        const packageJson = JSON.parse(fs.readFileSync(join(currentDir, 'package.json'), 'utf8'));
        if (packageJson.name === 'redquanta-mcp') {
          return currentDir;
        }
      }
      
      // If not, try to find it by going up directories
      const parts = currentDir.split(/[\/\\]/);
      for (let i = parts.length; i > 0; i--) {
        const testDir = parts.slice(0, i).join('/') || '/';
        if (fs.existsSync(join(testDir, 'package.json'))) {
          try {
            const packageJson = JSON.parse(fs.readFileSync(join(testDir, 'package.json'), 'utf8'));
            if (packageJson.name === 'redquanta-mcp') {
              return testDir;
            }
          } catch {}
        }
      }
      
      // Fallback: use current working directory
      return currentDir;
    } catch (error) {
      // Final fallback: use current working directory
      return process.cwd();
    }
  }

  public async initialize(): Promise<void> {
    if (this.initialized) return;
    
    try {
      await mkdir(this.logDir, { recursive: true });
      this.initialized = true;
      
      // Log successful initialization
      await this.logActivity({
        level: 'info',
        action: 'audit_logger_initialized',
        outcome: 'success',
        details: {
          logDirectory: this.logDir,
          workingDirectory: process.cwd()
        }
      });
    } catch (error) {
      // If we can't create the logs directory, fall back to a temp location
      const tempDir = join(require('os').tmpdir(), 'redquanta-logs');
      try {
        await mkdir(tempDir, { recursive: true });
        this.logDir = tempDir;
        this.initialized = true;
        
        console.error(`Warning: Could not create logs directory, using temp: ${tempDir}`);
      } catch (tempError) {
        console.error('Failed to initialize audit logger:', error);
        console.error('Fallback temp directory also failed:', tempError);
      }
    }
  }

  public async logActivity(event: Partial<AuditEvent>): Promise<void> {
    // Ensure logger is initialized
    if (!this.initialized) {
      await this.initialize();
    }
    
    const auditEvent: AuditEvent = {
      timestamp: new Date().toISOString(),
      level: 'info',
      action: 'unknown',
      outcome: 'success',
      ...event
    };

    const logEntry = JSON.stringify(auditEvent) + '\n';
    const logFile = join(this.logDir, `audit-${new Date().toISOString().split('T')[0]}.jsonl`);
    
    try {
      await writeFile(logFile, logEntry, { flag: 'a' });
    } catch (error) {
      // Silent fallback - don't spam console with errors but try to log to stderr
      if (process.env.NODE_ENV !== 'production') {
        console.error(`Audit log error (${this.logDir}):`, error);
      }
    }
  }

  public getLogDirectory(): string {
    return this.logDir;
  }

  public async shutdown(): Promise<void> {
    if (this.initialized) {
      await this.logActivity({
        level: 'info',
        action: 'audit_logger_shutdown',
        outcome: 'success'
      });
    }
  }
} 