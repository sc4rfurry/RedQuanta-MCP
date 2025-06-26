import { execa } from 'execa';
import { AuditLogger } from './auditLogger.js';

export interface DockerExecutionResult {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  command: string;
  executionTime: number;
  containerUsed: string;
}

export class DockerRunner {
  private auditLogger: AuditLogger;
  private containerName: string;

  constructor(auditLogger: AuditLogger, containerName: string = 'redquanta-security-tools') {
    this.auditLogger = auditLogger;
    this.containerName = containerName;
  }

  async isDockerAvailable(): Promise<boolean> {
    try {
      const result = await execa('docker', ['--version'], { timeout: 5000 });
      return result.exitCode === 0;
    } catch (error) {
      return false;
    }
  }

  async isContainerRunning(): Promise<boolean> {
    try {
      const result = await execa('docker', ['ps', '--filter', `name=${this.containerName}`, '--format', '{{.Names}}']);
      return result.stdout.includes(this.containerName);
    } catch (error) {
      return false;
    }
  }

  async executeInContainer(command: string, timeout: number = 30000): Promise<DockerExecutionResult> {
    const startTime = Date.now();
    
    try {
      const result = await execa('docker', [
        'exec',
        this.containerName,
        'bash',
        '-c',
        command
      ], {
        timeout,
        encoding: 'utf8'
      });

      return {
        success: true,
        stdout: result.stdout || '',
        stderr: result.stderr || '',
        exitCode: result.exitCode || 0,
        command: command,
        executionTime: Date.now() - startTime,
        containerUsed: this.containerName
      };

    } catch (error: any) {
      return {
        success: false,
        stdout: error.stdout || '',
        stderr: error.stderr || error.message || '',
        exitCode: error.exitCode || 1,
        command: command,
        executionTime: Date.now() - startTime,
        containerUsed: this.containerName
      };
    }
  }

  // Tool-specific execution methods
  async executeMasscan(target: string, ports: string, rate: number = 1000): Promise<DockerExecutionResult> {
    const command = `masscan ${target} -p${ports} --rate=${rate} --open-only`;
    return await this.executeInContainer(command);
  }

  async executeFFUF(url: string, wordlist: string = 'common'): Promise<DockerExecutionResult> {
    let wordlistPath = '/usr/share/wordlists/dirb/common.txt';
    
    switch (wordlist) {
      case 'directories':
        wordlistPath = '/usr/share/wordlists/dirb/common.txt';
        break;
      case 'files':
        wordlistPath = '/usr/share/wordlists/dirb/small.txt';
        break;
    }

    const command = `ffuf -w ${wordlistPath} -u ${url} -fc 403,404 -t 50`;
    return await this.executeInContainer(command);
  }

  async executeNikto(target: string, timeout: number = 300): Promise<DockerExecutionResult> {
    const command = `nikto -h ${target} -maxtime ${timeout} -ask no`;
    return await this.executeInContainer(command, (timeout + 60) * 1000);
  }

  async executeNmap(target: string, scanType: string = 'tcp', ports?: string, timing: string = '4'): Promise<DockerExecutionResult> {
    let scanArg = '-sT'; // Default TCP connect scan
    
    switch (scanType) {
      case 'syn':
        scanArg = '-sS';
        break;
      case 'udp':
        scanArg = '-sU';
        break;
      case 'ping':
        scanArg = '-sn';
        break;
      case 'version':
        scanArg = '-sV';
        break;
      case 'script':
        scanArg = '-sC';
        break;
    }

    let command = `nmap ${scanArg} -T${timing}`;
    
    if (ports) {
      command += ` -p ${ports}`;
    }
    
    command += ` ${target}`;
    
    return await this.executeInContainer(command, 120000); // 2 minute timeout
  }

  async executeGobuster(mode: string, target: string, wordlist: string, extensions?: string, threads: number = 50): Promise<DockerExecutionResult> {
    let command = `gobuster ${mode} -u ${target} -w ${wordlist} -t ${threads}`;
    
    if (extensions) {
      command += ` -x ${extensions}`;
    }
    
    return await this.executeInContainer(command);
  }

  /**
   * Get Linux binary name for Docker containers (removes Windows .exe extension)
   */
  private getLinuxBinaryName(toolName: string): string {
    // Docker containers are Linux-based, so no .exe extension
    return toolName.replace(/\.exe$/, '');
  }
}
