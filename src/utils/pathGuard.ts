/**
 * Path Guard - Secure filesystem access control
 * 
 * Provides canonical path resolution and jail root enforcement:
 * - Prevents path traversal attacks (../, \\..\\, etc.)
 * - Enforces access only within designated jail root
 * - Validates file extensions and sizes
 * - Cross-platform path normalization
 * - Windows environment variable expansion
 */

import { resolve, relative, join, extname, dirname, basename } from 'path';
import { existsSync, statSync, mkdirSync, readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { OSConfigManager } from './osConfig.js';

export interface PathGuardConfig {
  jailRoot: string;
  jailRootAlternatives?: string[];
  allowedExtensions: string[];
  deniedExtensions: string[];
  allowedDirectories: string[];
  maxFileSize: string | number;
  maxTotalSize: string | number;
  readOnlyByDefault: boolean;
  enforceCanonicalPaths?: boolean;
  windowsSpecific?: {
    allowedDrives?: string[];
    allowUNCPaths?: boolean;
    allowNetworkDrives?: boolean;
    respectNTFSPermissions?: boolean;
    allowHiddenFiles?: boolean;
    allowSystemFiles?: boolean;
    pathSeparator?: string;
    caseSensitive?: boolean;
    maxPathLength?: number;
    reservedNames?: string[];
  };
  security?: {
    blockPathTraversal?: boolean;
    blockSymlinks?: boolean;
    blockJunctions?: boolean;
    blockHardlinks?: boolean;
    requireDangerousFlag?: string[];
  };
}

export interface PathValidationResult {
  isValid: boolean;
  canonicalPath: string;
  relativePath: string;
  reason?: string;
  isWritable?: boolean;
  size?: number | undefined;
  exists?: boolean;
}

export class PathGuard {
  private config: PathGuardConfig;
  private osConfig: OSConfigManager;
  private actualJailRoot: string;

  constructor(configPath?: string, jailRootOverride?: string) {
    this.osConfig = new OSConfigManager();
    this.config = this.loadConfig(configPath);
    this.actualJailRoot = jailRootOverride || this.determineJailRoot();
    this.ensureJailRootExists();
  }

  /**
   * Load configuration from file or use defaults
   */
  private loadConfig(configPath?: string): PathGuardConfig {
    // Get the project root directory (two levels up from this file)
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const projectRoot = resolve(__dirname, '../..');
    
    const defaultConfigFile = this.osConfig.isWindows() 
      ? 'config/allowedPaths-windows.json'
      : 'config/allowedPaths.json';
    
    const actualConfigPath = configPath || resolve(projectRoot, defaultConfigFile);

    try {
      if (existsSync(actualConfigPath)) {
        const configData = JSON.parse(readFileSync(actualConfigPath, 'utf8'));
        return {
          ...this.getDefaultConfig(),
          ...configData,
        };
      }
    } catch (error) {
      console.error(`Failed to load config from ${actualConfigPath}:`, error);
    }

    return this.getDefaultConfig();
  }

  /**
   * Get default configuration
   */
  private getDefaultConfig(): PathGuardConfig {
    const osConfig = this.osConfig.getConfig();
    
    return {
      jailRoot: osConfig.jailRoot,
      allowedExtensions: ['.txt', '.json', '.xml', '.csv', '.log', '.md'],
      deniedExtensions: ['.exe', '.dll', '.sys', '.msi', '.bat', '.cmd'],
      allowedDirectories: ['tmp', 'reports', 'uploads', 'downloads'],
      maxFileSize: 104857600, // 100MB
      maxTotalSize: 1073741824, // 1GB
      readOnlyByDefault: true,
      enforceCanonicalPaths: true,
    };
  }

  /**
   * Determine the actual jail root to use, with Windows-safe fallbacks
   */
  private determineJailRoot(): string {
    // If we have alternatives (Windows), try them in order
    const alternatives = this.config.jailRootAlternatives || [this.config.jailRoot];
    
    for (const jailRoot of alternatives) {
      const expandedPath = this.expandWindowsEnvironmentVariables(jailRoot);
      const resolvedPath = resolve(expandedPath);
      
      // Test if we can use this path
      if (this.canUseJailRoot(resolvedPath)) {
        return resolvedPath;
      }
    }

    // Fallback to OS config's safe path
    return this.osConfig.getJailRoot();
  }

  /**
   * Expand Windows environment variables in paths
   */
  private expandWindowsEnvironmentVariables(path: string): string {
    if (!this.osConfig.isWindows()) {
      return path;
    }

    return path.replace(/%([^%]+)%/g, (match, varName) => {
      const value = process.env[varName];
      return value || match;
    });
  }

  /**
   * Test if we can use a jail root path (create directories, write files)
   */
  private canUseJailRoot(jailRoot: string): boolean {
    try {
      // Try to create the directory
      if (!existsSync(jailRoot)) {
        mkdirSync(jailRoot, { recursive: true });
      }

      // Test write permissions
      const testFile = join(jailRoot, '.pathguard-test');
      require('fs').writeFileSync(testFile, 'test');
      require('fs').unlinkSync(testFile);
      
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Ensure jail root directory exists and is accessible
   */
  private ensureJailRootExists(): void {
    try {
      if (!existsSync(this.actualJailRoot)) {
        mkdirSync(this.actualJailRoot, { recursive: true, mode: 0o755 });
      }

      // Create standard subdirectories
      for (const dir of this.config.allowedDirectories) {
        const dirPath = join(this.actualJailRoot, dir);
        if (!existsSync(dirPath)) {
          mkdirSync(dirPath, { recursive: true, mode: 0o755 });
        }
      }
    } catch (error) {
      throw new Error(`Failed to initialize jail root at ${this.actualJailRoot}: ${error}`);
    }
  }

  /**
   * Get the actual jail root being used
   */
  public getJailRoot(): string {
    return this.actualJailRoot;
  }

  /**
   * Get the configuration being used
   */
  public getConfig(): PathGuardConfig {
    return { ...this.config };
  }

  /**
   * Validate and resolve a path within the jail
   */
  public validatePath(inputPath: string, allowWrite = false): PathValidationResult {
    try {
      // Handle Windows environment variables
      const expandedPath = this.expandWindowsEnvironmentVariables(inputPath);
      
      // Normalize path separators for the platform
      const normalizedPath = this.osConfig.normalizePath(expandedPath);
      
      // Resolve to canonical path
      const candidatePath = this.osConfig.isAbsolute(normalizedPath)
        ? normalizedPath
        : join(this.actualJailRoot, normalizedPath);
      
      const canonicalPath = resolve(candidatePath);

      // Check if path is within jail root
      const relativePath = relative(this.actualJailRoot, canonicalPath);
      if (relativePath.startsWith('..') || this.osConfig.isAbsolute(relativePath)) {
        return {
          isValid: false,
          canonicalPath,
          relativePath,
          reason: 'Path escapes jail root',
        };
      }

      // Check for path traversal patterns
      if (this.config.security?.blockPathTraversal !== false) {
        if (this.containsPathTraversal(inputPath)) {
          return {
            isValid: false,
            canonicalPath,
            relativePath,
            reason: 'Path contains traversal patterns',
          };
        }
      }

      // Windows-specific validations
      if (this.osConfig.isWindows()) {
        const windowsValidation = this.validateWindowsPath(canonicalPath, relativePath);
        if (!windowsValidation.isValid) {
          return windowsValidation;
        }
      }

      // Check file extension
      const ext = extname(canonicalPath).toLowerCase();
      if (ext && this.config.deniedExtensions.includes(ext)) {
        return {
          isValid: false,
          canonicalPath,
          relativePath,
          reason: `File extension '${ext}' is denied`,
        };
      }

      if (ext && this.config.allowedExtensions.length > 0 && !this.config.allowedExtensions.includes(ext)) {
        return {
          isValid: false,
          canonicalPath,
          relativePath,
          reason: `File extension '${ext}' is not in allowed list`,
        };
      }

      // Check directory allowlist
      const topLevelDir = relativePath.split(this.osConfig.isWindows() ? '\\' : '/')[0];
      if (topLevelDir && this.config.allowedDirectories.length > 0 && !this.config.allowedDirectories.includes(topLevelDir)) {
        return {
          isValid: false,
          canonicalPath,
          relativePath,
          reason: `Directory '${topLevelDir}' is not in allowed list`,
        };
      }

      // Check if file exists and get metadata
      let size: number | undefined;
      let exists = false;
      try {
        if (existsSync(canonicalPath)) {
          exists = true;
          const stat = statSync(canonicalPath);
          size = stat.isFile() ? stat.size : undefined;

          // Check file size
          if (size !== undefined) {
            const maxSize = typeof this.config.maxFileSize === 'string' 
              ? this.parseSize(this.config.maxFileSize)
              : this.config.maxFileSize;
            
            if (size > maxSize) {
              return {
                isValid: false,
                canonicalPath,
                relativePath,
                reason: `File size ${size} exceeds limit ${maxSize}`,
                size,
                exists,
              };
            }
          }
        }
      } catch (error) {
        // Path might not exist yet, which is okay for write operations
      }

      return {
        isValid: true,
        canonicalPath,
        relativePath,
        isWritable: allowWrite && !this.config.readOnlyByDefault,
        size: size,
        exists,
      };

    } catch (error) {
      return {
        isValid: false,
        canonicalPath: '',
        relativePath: '',
        reason: `Path validation error: ${error}`,
      };
    }
  }

  /**
   * Windows-specific path validation
   */
  private validateWindowsPath(canonicalPath: string, relativePath: string): PathValidationResult {
    const windowsConfig = this.config.windowsSpecific;
    if (!windowsConfig) {
      return { isValid: true, canonicalPath, relativePath };
    }

    // Check drive restrictions
    if (windowsConfig.allowedDrives) {
      const match = canonicalPath.match(/^([A-Za-z]:)/);
      if (match && match[1]) {
        const drive = match[1].toUpperCase() + ':';
        if (!windowsConfig.allowedDrives.includes(drive)) {
          return {
            isValid: false,
            canonicalPath,
            relativePath,
            reason: `Drive '${drive}' is not allowed`,
          };
        }
      }
    }

    // Check UNC paths
    if (!windowsConfig.allowUNCPaths && canonicalPath.startsWith('\\\\')) {
      return {
        isValid: false,
        canonicalPath,
        relativePath,
        reason: 'UNC paths are not allowed',
      };
    }

    // Check path length (Windows limitation)
    if (windowsConfig.maxPathLength && canonicalPath.length > windowsConfig.maxPathLength) {
      return {
        isValid: false,
        canonicalPath,
        relativePath,
        reason: `Path length ${canonicalPath.length} exceeds Windows limit ${windowsConfig.maxPathLength}`,
      };
    }

    // Check reserved names
    if (windowsConfig.reservedNames) {
      const fileName = basename(canonicalPath, extname(canonicalPath)).toUpperCase();
      if (windowsConfig.reservedNames.includes(fileName)) {
        return {
          isValid: false,
          canonicalPath,
          relativePath,
          reason: `'${fileName}' is a reserved Windows name`,
        };
      }
    }

    return { isValid: true, canonicalPath, relativePath };
  }

  /**
   * Check for path traversal patterns
   */
  private containsPathTraversal(path: string): boolean {
    const traversalPatterns = [
      /\.\./,           // Basic traversal
      /%2e%2e/i,        // URL encoded ..
      /%252e%252e/i,    // Double URL encoded ..
      /\.\\\./,         // Windows traversal
      /\.\/\.\//,       // Unix traversal
      /%5c/i,           // URL encoded backslash
      /%2f/i,           // URL encoded forward slash
    ];

    return traversalPatterns.some(pattern => pattern.test(path));
  }

  /**
   * Parse size string to bytes
   */
  private parseSize(sizeStr: string): number {
    const units = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
    const match = sizeStr.match(/^(\d+(?:\.\d+)?)\s*([A-Z]{1,2})?$/i);
    
    if (!match || !match[1]) {
      throw new Error(`Invalid size format: ${sizeStr}`);
    }

    const value = parseFloat(match[1]);
    const unit = (match[2] || 'B').toUpperCase() as keyof typeof units;
    
    if (!(unit in units)) {
      throw new Error(`Unknown size unit: ${unit}`);
    }

    return Math.floor(value * units[unit]);
  }

  /**
   * Get safe paths for common operations
   */
  public getSafePath(operation: 'tmp' | 'reports' | 'uploads' | 'downloads' | 'wordlists', filename?: string): string {
    const basePath = join(this.actualJailRoot, operation);
    return filename ? join(basePath, filename) : basePath;
  }

  /**
   * Check if path is within jail root (without full validation)
   */
  public isWithinJail(path: string): boolean {
    try {
      const canonicalPath = resolve(path);
      const relativePath = relative(this.actualJailRoot, canonicalPath);
      return !relativePath.startsWith('..') && !this.osConfig.isAbsolute(relativePath);
    } catch {
      return false;
    }
  }

  /**
   * Get jail root statistics
   */
  public getJailStats(): { totalSize: number; fileCount: number; dirCount: number } {
    const stats = { totalSize: 0, fileCount: 0, dirCount: 0 };

    const walkDir = (dir: string): void => {
      try {
        const entries = require('fs').readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const fullPath = join(dir, entry.name);
          if (entry.isDirectory()) {
            stats.dirCount++;
            walkDir(fullPath);
          } else if (entry.isFile()) {
            stats.fileCount++;
            try {
              stats.totalSize += statSync(fullPath).size;
            } catch {
              // Skip files we can't stat
            }
          }
        }
      } catch {
        // Skip directories we can't read
      }
    };

    if (existsSync(this.actualJailRoot)) {
      walkDir(this.actualJailRoot);
    }

    return stats;
  }
} 