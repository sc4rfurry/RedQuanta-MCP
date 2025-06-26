/**
 * OS Configuration Utility - Cross-platform path and binary resolution
 * 
 * Provides OS-aware configuration for Windows, macOS, and Linux:
 * - Platform-specific jail root paths (user-accessible)
 * - Binary name resolution with extensions
 * - Package manager integration
 * - Temp directory handling
 */

import { platform, homedir, tmpdir } from 'os';
import { join, resolve } from 'path';

export type Platform = 'windows' | 'linux' | 'darwin';
export type PackageManager = 'winget' | 'chocolatey' | 'brew' | 'apt' | 'snap' | 'flatpak';

export interface OSConfig {
  platform: Platform;
  jailRoot: string;
  tempDir: string;
  packageManagers: PackageManager[];
  binaryExtension: string;
  scriptExtension: string;
  pathSeparator: string;
  homeDir: string;
}

export interface BinaryLocation {
  name: string;
  path?: string;
  packageManager?: PackageManager;
  dockerImage?: string;
  installCommand?: string;
}

export class OSConfigManager {
  private config: OSConfig;
  private platformName: Platform;

  constructor() {
    this.platformName = this.detectPlatform();
    this.config = this.createPlatformConfig();
  }

  /**
   * Detect the current platform
   */
  private detectPlatform(): Platform {
    const platformStr = platform();
    switch (platformStr) {
      case 'win32':
        return 'windows';
      case 'darwin':
        return 'darwin';
      case 'linux':
        return 'linux';
      default:
        // Default to linux for unknown platforms
        console.error(`Unknown platform ${platformStr}, defaulting to linux`);
        return 'linux';
    }
  }

  /**
   * Create platform-specific configuration with safe, user-accessible paths
   */
  private createPlatformConfig(): OSConfig {
    const base = {
      platform: this.platformName,
      homeDir: homedir(),
    };

    switch (this.platformName) {
      case 'windows':
        return {
          ...base,
          // Use AppData\Local for Windows - always user-accessible
          jailRoot: join(process.env.LOCALAPPDATA || join(homedir(), 'AppData', 'Local'), 'RedQuanta', 'vol'),
          tempDir: tmpdir(),
          packageManagers: ['winget', 'chocolatey'],
          binaryExtension: '.exe',
          scriptExtension: '.bat',
          pathSeparator: ';',
        };

      case 'darwin':
        return {
          ...base,
          // Use user's home directory on macOS
          jailRoot: join(homedir(), '.redquanta', 'vol'),
          tempDir: '/tmp',
          packageManagers: ['brew'],
          binaryExtension: '',
          scriptExtension: '.sh',
          pathSeparator: ':',
        };

      case 'linux':
      default:
        return {
          ...base,
          // Use user's home directory on Linux, fallback to /opt if available
          jailRoot: process.getuid && process.getuid() === 0 
            ? '/opt/redquanta/vol' 
            : join(homedir(), '.redquanta', 'vol'),
          tempDir: '/tmp',
          packageManagers: ['apt', 'snap', 'flatpak'],
          binaryExtension: '',
          scriptExtension: '.sh',
          pathSeparator: ':',
        };
    }
  }

  /**
   * Get safe jail root path with fallback options
   */
  public getJailRoot(customPath?: string): string {
    if (customPath) {
      return resolve(customPath);
    }

    // Platform-specific safe paths
    if (this.platformName === 'windows') {
      const options = [
        // Primary: LocalAppData (always writable)
        join(process.env.LOCALAPPDATA || join(this.config.homeDir, 'AppData', 'Local'), 'RedQuanta', 'vol'),
        // Fallback: User profile
        join(this.config.homeDir, 'RedQuanta', 'vol'),
        // Last resort: Temp directory
        join(tmpdir(), 'RedQuanta', 'vol'),
      ];
      
      return options[0]!; // Return the safest option (we know array has items)
    }

    return this.config.jailRoot;
  }

  /**
   * Get multiple jail root options for Windows (in order of preference)
   */
  public getJailRootOptions(): string[] {
    if (this.platformName === 'windows') {
      return [
        // Most preferred: LocalAppData (guaranteed writable for current user)
        join(process.env.LOCALAPPDATA || join(this.config.homeDir, 'AppData', 'Local'), 'RedQuanta', 'vol'),
        // Alternative: User Documents folder
        join(this.config.homeDir, 'Documents', 'RedQuanta', 'vol'),
        // Alternative: User profile root
        join(this.config.homeDir, 'RedQuanta', 'vol'),
        // Last resort: Temp directory (will work but not persistent)
        join(tmpdir(), 'RedQuanta', 'vol'),
      ];
    }

    return [this.config.jailRoot];
  }

  /**
   * Get the current OS configuration
   */
  public getConfig(): OSConfig {
    return { ...this.config };
  }

  /**
   * Get platform-specific binary name with extension
   */
  public getBinaryName(baseName: string): string {
    return baseName + this.config.binaryExtension;
  }

  /**
   * Get platform-specific script name with extension
   */
  public getScriptName(baseName: string): string {
    return baseName + this.config.scriptExtension;
  }

  /**
   * Resolve tool binary location based on platform
   */
  public resolveBinary(toolName: string, toolProfile: any): BinaryLocation {
    const platformBinary = toolProfile.binary[this.platformName] || toolProfile.binary.linux;
    
    return {
      name: platformBinary,
      packageManager: this.getPrimaryPackageManager(),
      dockerImage: this.getDockerFallback(toolName),
      installCommand: this.getInstallCommand(toolName),
    };
  }

  /**
   * Get the primary package manager for the platform
   */
  public getPrimaryPackageManager(): PackageManager {
    return this.config.packageManagers[0]!;
  }

  /**
   * Get all available package managers for the platform
   */
  public getPackageManagers(): PackageManager[] {
    return [...this.config.packageManagers];
  }

  /**
   * Get Docker fallback image for a tool
   */
  private getDockerFallback(toolName: string): string {
    const dockerImages: Record<string, string> = {
      nmap: 'instrumentisto/nmap:latest',
      masscan: 'ivre/masscan:latest',
      ffuf: 'ghcr.io/ffuf/ffuf:latest',
      gobuster: 'opsxcq/docker-gobuster:latest',
      nikto: 'secfigo/nikto:latest',
      sqlmap: 'paoloo/sqlmap:latest',
      john: 'ghcr.io/openwall/john:latest',
      hydra: 'vanhauser/hydra:latest',
      zap: 'owasp/zap2docker-stable:latest',
    };

    return dockerImages[toolName] || 'alpine:latest';
  }

  /**
   * Get installation command for a tool on the current platform
   */
  public getInstallCommand(toolName: string): string {
    const commands: Record<Platform, Record<string, string>> = {
      windows: {
        nmap: 'winget install Nmap.Nmap',
        masscan: 'winget install masscan',
        ffuf: 'winget install ffuf',
        gobuster: 'go install github.com/OJ/gobuster/v3@latest',
        nikto: 'git clone https://github.com/sullo/nikto.git',
        sqlmap: 'git clone https://github.com/sqlmapproject/sqlmap.git',
        john: 'winget install openwall.john',
        hydra: 'winget install hydra',
      },
      darwin: {
        nmap: 'brew install nmap',
        masscan: 'brew install masscan',
        ffuf: 'brew install ffuf',
        gobuster: 'brew install gobuster',
        nikto: 'brew install nikto',
        sqlmap: 'brew install sqlmap',
        john: 'brew install john',
        hydra: 'brew install hydra',
      },
      linux: {
        nmap: 'sudo apt update && sudo apt install -y nmap',
        masscan: 'sudo apt update && sudo apt install -y masscan',
        ffuf: 'sudo apt update && sudo apt install -y ffuf',
        gobuster: 'sudo apt update && sudo apt install -y gobuster',
        nikto: 'sudo apt update && sudo apt install -y nikto',
        sqlmap: 'sudo apt update && sudo apt install -y sqlmap',
        john: 'sudo apt update && sudo apt install -y john',
        hydra: 'sudo apt update && sudo apt install -y hydra',
      },
    };

    const platformCommands = commands[this.platformName];
    const command = platformCommands?.[toolName];
    
    if (command) {
      return command;
    }
    
    return `echo "No install command for ${toolName} on ${this.platformName}"`;
  }

  /**
   * Create platform-appropriate path
   */
  public createPath(...segments: string[]): string {
    return resolve(...segments);
  }

  /**
   * Check if a path is absolute
   */
  public isAbsolute(path: string): boolean {
    if (this.platformName === 'windows') {
      // Windows absolute paths: C:\, D:\, \\server\share
      return /^[A-Za-z]:\\|^\\\\/.test(path);
    }
    return path.startsWith('/');
  }

  /**
   * Normalize path separators for the current platform
   */
  public normalizePath(path: string): string {
    if (this.platformName === 'windows') {
      return path.replace(/\//g, '\\');
    }
    return path.replace(/\\/g, '/');
  }

  /**
   * Get environment variable path separator
   */
  public getPathSeparator(): string {
    return this.config.pathSeparator;
  }

  /**
   * Get platform-specific temp directory
   */
  public getTempDir(): string {
    return this.config.tempDir;
  }

  /**
   * Check if current platform is Windows
   */
  public isWindows(): boolean {
    return this.platformName === 'windows';
  }

  /**
   * Check if current platform is macOS
   */
  public isMacOS(): boolean {
    return this.platformName === 'darwin';
  }

  /**
   * Check if current platform is Linux
   */
  public isLinux(): boolean {
    return this.platformName === 'linux';
  }

  /**
   * Get current platform name
   */
  public getPlatform(): Platform {
    return this.platformName;
  }
} 