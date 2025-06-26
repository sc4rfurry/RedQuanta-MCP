/**
 * Filesystem Manager - Secure file operations within jail
 */

import { PathGuard } from './pathGuard.js';
import { AuditLogger } from './auditLogger.js';
import { existsSync, statSync, readdirSync, readFileSync } from 'fs';

export class FilesystemManager {
  private pathGuard: PathGuard;
  private auditLogger: AuditLogger;

  constructor(pathGuard: PathGuard, auditLogger: AuditLogger) {
    this.pathGuard = pathGuard;
    this.auditLogger = auditLogger;
  }

  /**
   * List directory contents
   */
  public async listDirectory(path: string): Promise<string[]> {
    const validation = this.pathGuard.validatePath(path, false);
    if (!validation.isValid) {
      throw new Error(`Invalid path for listing: ${validation.reason}`);
    }

    const safePath = validation.canonicalPath;

    if (!existsSync(safePath)) {
      throw new Error(`Directory does not exist: ${path}`);
    }

    const stat = statSync(safePath);
    if (!stat.isDirectory()) {
      throw new Error(`Path is not a directory: ${path}`);
    }

    return readdirSync(safePath);
  }

  /**
   * Read file contents
   */
  public async readFile(path: string, encoding: BufferEncoding = 'utf8'): Promise<string> {
    const validation = this.pathGuard.validatePath(path, false);
    if (!validation.isValid) {
      throw new Error(`Invalid path for reading: ${validation.reason}`);
    }

    const safePath = validation.canonicalPath;

    if (!existsSync(safePath)) {
      throw new Error(`File does not exist: ${path}`);
    }

    const stat = statSync(safePath);
    if (!stat.isFile()) {
      throw new Error(`Path is not a file: ${path}`);
    }

    return readFileSync(safePath, encoding);
  }
} 