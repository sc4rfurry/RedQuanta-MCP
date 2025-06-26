/**
 * SARIF (Static Analysis Results Interchange Format) Reporter for RedQuanta MCP
 * 
 * Features:
 * - SARIF 2.1.0 compliance
 * - CI/CD pipeline integration
 * - Multi-tool result aggregation
 * - Vulnerability scoring and classification
 * - Security baseline comparisons
 * - Automated issue tracking integration
 */

import { AuditLogger } from './auditLogger.js';
import { promises as fs } from 'fs';
import { join } from 'path';

export interface SarifVulnerability {
  id: string;
  tool: string;
  target: string;
  title: string;
  description: string;
  severity: 'error' | 'warning' | 'note' | 'info';
  confidence: 'high' | 'medium' | 'low';
  category: string;
  cwe?: string;
  cvss?: number;
  location: {
    uri: string;
    startLine?: number;
    endLine?: number;
    startColumn?: number;
    endColumn?: number;
  };
  evidence?: string;
  remediation?: string;
  references?: string[];
  tags: string[];
  discoveredAt: string;
  toolVersion?: string;
  ruleId: string;
}

export interface SarifReport {
  version: string;
  $schema: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  invocations: SarifInvocation[];
  taxonomies?: SarifTaxonomy[];
  properties?: Record<string, any>;
}

export interface SarifTool {
  driver: SarifDriver;
}

export interface SarifDriver {
  name: string;
  version: string;
  informationUri?: string;
  organization?: string;
  rules: SarifRule[];
  notifications?: SarifNotification[];
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: SarifMessage;
  fullDescription?: SarifMessage;
  help?: SarifMessage;
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note' | 'none';
  };
  properties?: {
    precision?: 'very-high' | 'high' | 'medium' | 'low';
    'security-severity'?: string;
    tags?: string[];
  };
}

export interface SarifResult {
  ruleId: string;
  message: SarifMessage;
  level: 'error' | 'warning' | 'note' | 'info';
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
  properties?: Record<string, any>;
  codeFlows?: SarifCodeFlow[];
  relatedLocations?: SarifLocation[];
}

export interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine?: number;
      endLine?: number;
      startColumn?: number;
      endColumn?: number;
    };
  };
  message?: SarifMessage;
}

export interface SarifMessage {
  text: string;
  markdown?: string | undefined;
}

export interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc: string;
  endTimeUtc: string;
  commandLine?: string;
  arguments?: string[];
  workingDirectory?: SarifArtifactLocation;
  exitCode?: number;
  exitCodeDescription?: string;
  toolExecutionNotifications?: SarifNotification[];
}

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifNotification {
  level: 'error' | 'warning' | 'note' | 'info';
  message: SarifMessage;
  timeUtc?: string;
}

export interface SarifTaxonomy {
  name: string;
  version?: string;
  organization?: string;
  shortDescription?: SarifMessage;
  taxa: SarifTaxon[];
}

export interface SarifTaxon {
  id: string;
  name: string;
  shortDescription?: SarifMessage;
  fullDescription?: SarifMessage;
}

export interface SarifCodeFlow {
  message?: SarifMessage;
  threadFlows: SarifThreadFlow[];
}

export interface SarifThreadFlow {
  id?: string;
  message?: SarifMessage;
  locations: SarifThreadFlowLocation[];
}

export interface SarifThreadFlowLocation {
  step?: number;
  location: SarifLocation;
  state?: Record<string, any>;
  nestingLevel?: number;
  executionOrder?: number;
}

export interface SarifReportOptions {
  includeBaseline?: boolean;
  baselineFile?: string;
  outputPath?: string;
  mergeRuns?: boolean;
  includeCoverage?: boolean;
  securitySeverityThreshold?: number;
  excludeRules?: string[];
  includeOnlyRules?: string[];
  addGitHubAnnotations?: boolean;
  addJunitOutput?: boolean;
}

export class SarifReporter {
  private auditLogger: AuditLogger;
  private vulnerabilities: Map<string, SarifVulnerability> = new Map();
  private toolInvocations: Map<string, any> = new Map();
  private reportMetadata: Record<string, any> = {};

  constructor(auditLogger: AuditLogger) {
    this.auditLogger = auditLogger;
  }

  /**
   * Add vulnerability finding to the report
   */
  public addVulnerability(vulnerability: SarifVulnerability): void {
    const key = this.generateVulnerabilityKey(vulnerability);
    this.vulnerabilities.set(key, vulnerability);

    this.auditLogger.logActivity({
      action: 'vulnerability_added',
      target: vulnerability.target,
      details: {
        tool: vulnerability.tool,
        severity: vulnerability.severity,
        category: vulnerability.category,
        ruleId: vulnerability.ruleId
      },
      outcome: 'success'
    });
  }

  /**
   * Add multiple vulnerabilities from tool output
   */
  public addToolFindings(tool: string, target: string, findings: any[]): void {
    for (const finding of findings) {
      const vulnerability = this.convertToolFindingToVulnerability(tool, target, finding);
      if (vulnerability) {
        this.addVulnerability(vulnerability);
      }
    }
  }

  /**
   * Record tool invocation details
   */
  public recordToolInvocation(tool: string, invocation: {
    startTime: Date;
    endTime: Date;
    commandLine?: string;
    arguments?: string[];
    exitCode?: number;
    successful: boolean;
    target?: string;
  }): void {
    this.toolInvocations.set(tool, {
      ...invocation,
      startTimeUtc: invocation.startTime.toISOString(),
      endTimeUtc: invocation.endTime.toISOString()
    });
  }

  /**
   * Generate comprehensive SARIF report
   */
  public async generateReport(options: SarifReportOptions = {}): Promise<SarifReport> {
    const runs: SarifRun[] = [];

    // Group vulnerabilities by tool
    const toolVulnerabilities = this.groupVulnerabilitiesByTool();

    for (const [toolName, vulnerabilities] of toolVulnerabilities.entries()) {
      const run = await this.createToolRun(toolName, vulnerabilities, options);
      runs.push(run);
    }

    const report: SarifReport = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: options.mergeRuns ? [this.mergeRuns(runs)] : runs
    };

    // Apply baseline filtering if specified
    if (options.includeBaseline && options.baselineFile) {
      await this.applyBaseline(report, options.baselineFile);
    }

    // Generate additional outputs
    if (options.addGitHubAnnotations) {
      await this.generateGitHubAnnotations(report, options);
    }

    if (options.addJunitOutput) {
      await this.generateJunitReport(report, options);
    }

    return report;
  }

  /**
   * Save SARIF report to file
   */
  public async saveReport(report: SarifReport, filePath: string): Promise<void> {
    const reportJson = JSON.stringify(report, null, 2);
    await fs.writeFile(filePath, reportJson, 'utf8');

    const stats = this.getReportStatistics(report);
    
    await this.auditLogger.logActivity({
      action: 'sarif_report_saved',
      target: filePath,
      details: {
        ...stats,
        fileSize: Buffer.byteLength(reportJson, 'utf8')
      },
      outcome: 'success'
    });
  }

  /**
   * Get report statistics
   */
  public getReportStatistics(report: SarifReport): any {
    const stats = {
      totalRuns: report.runs.length,
      totalResults: 0,
      errorCount: 0,
      warningCount: 0,
      noteCount: 0,
      infoCount: 0,
      toolsUsed: [] as string[],
      categoryCounts: {} as Record<string, number>,
      severityCounts: {} as Record<string, number>
    };

    for (const run of report.runs) {
      stats.totalResults += run.results.length;
      stats.toolsUsed.push(run.tool.driver.name);

      for (const result of run.results) {
        switch (result.level) {
          case 'error':
            stats.errorCount++;
            break;
          case 'warning':
            stats.warningCount++;
            break;
          case 'note':
            stats.noteCount++;
            break;
          case 'info':
            stats.infoCount++;
            break;
        }

        // Count by security severity if available
        const securitySeverity = result.properties?.['security-severity'];
        if (securitySeverity) {
          stats.severityCounts[securitySeverity] = (stats.severityCounts[securitySeverity] || 0) + 1;
        }
      }
    }

    return stats;
  }

  /**
   * Filter vulnerabilities by security threshold
   */
  public filterBySeverity(report: SarifReport, threshold: number): SarifReport {
    const filteredReport = JSON.parse(JSON.stringify(report)) as SarifReport;

    for (const run of filteredReport.runs) {
      run.results = run.results.filter(result => {
        const securitySeverity = result.properties?.['security-severity'];
        return !securitySeverity || parseFloat(securitySeverity) >= threshold;
      });
    }

    return filteredReport;
  }

  /**
   * Generate diff report between two SARIF reports
   */
  public async generateDiffReport(baselineReport: SarifReport, currentReport: SarifReport): Promise<{
    newIssues: SarifResult[];
    resolvedIssues: SarifResult[];
    unchangedIssues: SarifResult[];
  }> {
    const baselineFingerprints = new Set<string>();
    const currentFingerprints = new Map<string, SarifResult>();

    // Extract fingerprints from baseline
    for (const run of baselineReport.runs) {
      for (const result of run.results) {
        const fingerprint = this.generateResultFingerprint(result);
        baselineFingerprints.add(fingerprint);
      }
    }

    // Extract fingerprints from current report
    for (const run of currentReport.runs) {
      for (const result of run.results) {
        const fingerprint = this.generateResultFingerprint(result);
        currentFingerprints.set(fingerprint, result);
      }
    }

    const newIssues: SarifResult[] = [];
    const unchangedIssues: SarifResult[] = [];
    const resolvedIssues: SarifResult[] = [];

    // Find new and unchanged issues
    for (const [fingerprint, result] of currentFingerprints.entries()) {
      if (baselineFingerprints.has(fingerprint)) {
        unchangedIssues.push(result);
      } else {
        newIssues.push(result);
      }
    }

    // Find resolved issues (in baseline but not in current)
    for (const run of baselineReport.runs) {
      for (const result of run.results) {
        const fingerprint = this.generateResultFingerprint(result);
        if (!currentFingerprints.has(fingerprint)) {
          resolvedIssues.push(result);
        }
      }
    }

    return { newIssues, resolvedIssues, unchangedIssues };
  }

  // Private helper methods
  private generateVulnerabilityKey(vulnerability: SarifVulnerability): string {
    return `${vulnerability.tool}-${vulnerability.target}-${vulnerability.ruleId}-${vulnerability.location.uri}`;
  }

  private convertToolFindingToVulnerability(tool: string, target: string, finding: any): SarifVulnerability | null {
    try {
      const vulnerability: SarifVulnerability = {
        id: finding.id || `${tool}-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
        tool,
        target,
        title: finding.title || finding.name || finding.description || 'Unknown vulnerability',
        description: finding.description || finding.details || finding.message || '',
        severity: this.mapSeverity(finding.severity || finding.level || 'medium'),
        confidence: this.mapConfidence(finding.confidence || 'medium'),
        category: finding.category || this.inferCategory(tool),
        cwe: finding.cwe,
        cvss: finding.cvss || finding.score,
        location: {
          uri: finding.location?.uri || finding.url || target,
          startLine: finding.location?.line,
          endLine: finding.location?.endLine,
          startColumn: finding.location?.column,
          endColumn: finding.location?.endColumn
        },
        evidence: finding.evidence || finding.proof,
        remediation: finding.remediation || finding.solution || finding.fix,
        references: finding.references || finding.links || [],
        tags: finding.tags || [tool, this.inferCategory(tool)],
        discoveredAt: new Date().toISOString(),
        toolVersion: finding.toolVersion,
        ruleId: finding.ruleId || finding.id || `${tool}-default-rule`
      };

      return vulnerability;
    } catch (error) {
      this.auditLogger.logActivity({
        action: 'vulnerability_conversion_failed',
        target,
        details: { tool, error: (error as Error).message },
        outcome: 'failure'
      });
      return null;
    }
  }

  private mapSeverity(severity: string): 'error' | 'warning' | 'note' | 'info' {
    const severityMap: Record<string, 'error' | 'warning' | 'note' | 'info'> = {
      'critical': 'error',
      'high': 'error',
      'medium': 'warning',
      'low': 'note',
      'info': 'info',
      'informational': 'info'
    };

    return severityMap[severity.toLowerCase()] || 'warning';
  }

  private mapConfidence(confidence: string): 'high' | 'medium' | 'low' {
    const confidenceMap: Record<string, 'high' | 'medium' | 'low'> = {
      'certain': 'high',
      'firm': 'high',
      'tentative': 'medium',
      'uncertain': 'low'
    };

    return confidenceMap[confidence.toLowerCase()] || 'medium';
  }

  private inferCategory(tool: string): string {
    const categoryMap: Record<string, string> = {
      'nmap': 'network-security',
      'masscan': 'network-security',
      'ffuf': 'web-security',
      'gobuster': 'web-security',
      'nikto': 'web-security',
      'sqlmap': 'injection',
      'hydra': 'authentication',
      'john': 'password-security',
      'zap': 'web-security',
      'metasploit': 'exploitation'
    };

    return categoryMap[tool.toLowerCase()] || 'security';
  }

  private groupVulnerabilitiesByTool(): Map<string, SarifVulnerability[]> {
    const grouped = new Map<string, SarifVulnerability[]>();

    for (const vulnerability of this.vulnerabilities.values()) {
      if (!grouped.has(vulnerability.tool)) {
        grouped.set(vulnerability.tool, []);
      }
      grouped.get(vulnerability.tool)!.push(vulnerability);
    }

    return grouped;
  }

  private async createToolRun(toolName: string, vulnerabilities: SarifVulnerability[], options: SarifReportOptions): Promise<SarifRun> {
    const rules = this.createRulesFromVulnerabilities(vulnerabilities);
    const results = vulnerabilities.map(v => this.convertVulnerabilityToResult(v));
    const invocation = this.toolInvocations.get(toolName);

    const run: SarifRun = {
      tool: {
        driver: {
          name: toolName,
          version: vulnerabilities[0]?.toolVersion || '1.0.0',
          informationUri: this.getToolInformationUri(toolName),
          organization: 'RedQuanta MCP',
          rules
        }
      },
      results: results.filter(result => !this.shouldExcludeResult(result, options)),
      invocations: invocation ? [this.convertToSarifInvocation(invocation)] : []
    };

    return run;
  }

  private createRulesFromVulnerabilities(vulnerabilities: SarifVulnerability[]): SarifRule[] {
    const rulesMap = new Map<string, SarifRule>();

    for (const vulnerability of vulnerabilities) {
      if (!rulesMap.has(vulnerability.ruleId)) {
        const rule: SarifRule = {
          id: vulnerability.ruleId,
          name: vulnerability.title,
          shortDescription: {
            text: vulnerability.title
          },
          fullDescription: {
            text: vulnerability.description
          },
          defaultConfiguration: {
            level: vulnerability.severity === 'info' ? 'none' : vulnerability.severity
          },
          properties: {
            precision: vulnerability.confidence === 'high' ? 'high' : vulnerability.confidence === 'medium' ? 'medium' : 'low',
            'security-severity': vulnerability.cvss?.toString() || this.getDefaultSecuritySeverity(vulnerability.severity),
            tags: vulnerability.tags
          }
        };

        if (vulnerability.cwe) {
          rule.properties!.tags = [...(rule.properties!.tags || []), `CWE-${vulnerability.cwe}`];
        }

        rulesMap.set(vulnerability.ruleId, rule);
      }
    }

    return Array.from(rulesMap.values());
  }

  private convertVulnerabilityToResult(vulnerability: SarifVulnerability): SarifResult {
    return {
      ruleId: vulnerability.ruleId,
      message: {
        text: vulnerability.description,
        markdown: vulnerability.evidence ? `${vulnerability.description}\n\n**Evidence:**\n\`\`\`\n${vulnerability.evidence}\n\`\`\`` : undefined
      },
      level: vulnerability.severity,
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: vulnerability.location.uri
          },
          ...(vulnerability.location.startLine && {
            region: {
              startLine: vulnerability.location.startLine,
              ...(vulnerability.location.endLine !== undefined && { endLine: vulnerability.location.endLine }),
              ...(vulnerability.location.startColumn !== undefined && { startColumn: vulnerability.location.startColumn }),
              ...(vulnerability.location.endColumn !== undefined && { endColumn: vulnerability.location.endColumn })
            }
          })
        }
      }],
      fingerprints: {
        redquanta: this.generateVulnerabilityKey(vulnerability)
      },
      properties: {
        'security-severity': vulnerability.cvss?.toString() || this.getDefaultSecuritySeverity(vulnerability.severity),
        category: vulnerability.category,
        confidence: vulnerability.confidence,
        discoveredAt: vulnerability.discoveredAt,
        remediation: vulnerability.remediation,
        references: vulnerability.references
      }
    };
  }

  private convertToSarifInvocation(invocation: any): SarifInvocation {
    return {
      executionSuccessful: invocation.successful,
      startTimeUtc: invocation.startTimeUtc,
      endTimeUtc: invocation.endTimeUtc,
      commandLine: invocation.commandLine,
      arguments: invocation.arguments,
      exitCode: invocation.exitCode
    };
  }

  private shouldExcludeResult(result: SarifResult, options: SarifReportOptions): boolean {
    if (options.excludeRules && options.excludeRules.includes(result.ruleId)) {
      return true;
    }

    if (options.includeOnlyRules && !options.includeOnlyRules.includes(result.ruleId)) {
      return true;
    }

    if (options.securitySeverityThreshold) {
      const severity = parseFloat(result.properties?.['security-severity'] || '0');
      if (severity < options.securitySeverityThreshold) {
        return true;
      }
    }

    return false;
  }

  private mergeRuns(runs: SarifRun[]): SarifRun {
    const mergedRun: SarifRun = {
      tool: {
        driver: {
          name: 'RedQuanta MCP',
          version: '0.3.0',
          informationUri: 'https://github.com/redquanta/mcp',
          organization: 'RedQuanta',
          rules: []
        }
      },
      results: [],
      invocations: []
    };

    for (const run of runs) {
      mergedRun.tool.driver.rules.push(...run.tool.driver.rules);
      mergedRun.results.push(...run.results);
      mergedRun.invocations.push(...run.invocations);
    }

    return mergedRun;
  }

  private async applyBaseline(report: SarifReport, baselineFile: string): Promise<void> {
    try {
      const baselineContent = await fs.readFile(baselineFile, 'utf8');
      const baselineReport: SarifReport = JSON.parse(baselineContent);
      
      const diff = await this.generateDiffReport(baselineReport, report);
      
      // Add metadata about baseline comparison
      for (const run of report.runs) {
        run.properties = {
          ...run.properties,
          baseline: {
            file: baselineFile,
            newIssues: diff.newIssues.length,
            resolvedIssues: diff.resolvedIssues.length,
            unchangedIssues: diff.unchangedIssues.length
          }
        };
      }
    } catch (error) {
      this.auditLogger.logActivity({
        action: 'baseline_application_failed',
        target: baselineFile,
        details: { error: (error as Error).message },
        outcome: 'failure'
      });
    }
  }

  private async generateGitHubAnnotations(report: SarifReport, options: SarifReportOptions): Promise<void> {
    const annotations: any[] = [];

    for (const run of report.runs) {
      for (const result of run.results) {
        const location = result.locations[0]?.physicalLocation;
        if (location) {
          annotations.push({
            path: location.artifactLocation.uri,
            start_line: location.region?.startLine || 1,
            end_line: location.region?.endLine || location.region?.startLine || 1,
            annotation_level: this.mapSarifLevelToGitHub(result.level),
            message: result.message.text,
            title: `${run.tool.driver.name}: ${result.ruleId}`,
            raw_details: result.message.markdown || result.message.text
          });
        }
      }
    }

    const outputPath = options.outputPath || '.';
    const annotationsPath = join(outputPath, 'github-annotations.json');
    await fs.writeFile(annotationsPath, JSON.stringify(annotations, null, 2));
  }

  private async generateJunitReport(report: SarifReport, options: SarifReportOptions): Promise<void> {
    const stats = this.getReportStatistics(report);
    
    const junitXml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="RedQuanta Security Scan" tests="${stats.totalResults}" failures="${stats.errorCount}" errors="${stats.warningCount}" time="0">
  <testsuite name="Security Vulnerabilities" tests="${stats.totalResults}" failures="${stats.errorCount}" errors="${stats.warningCount}">
    ${report.runs.map(run => 
      run.results.map(result => 
        `<testcase name="${result.ruleId}" classname="${run.tool.driver.name}">
          ${result.level === 'error' ? `<failure message="${this.escapeXml(result.message.text)}"/>` : ''}
          ${result.level === 'warning' ? `<error message="${this.escapeXml(result.message.text)}"/>` : ''}
        </testcase>`
      ).join('\n')
    ).join('\n')}
  </testsuite>
</testsuites>`;

    const outputPath = options.outputPath || '.';
    const junitPath = join(outputPath, 'junit-report.xml');
    await fs.writeFile(junitPath, junitXml);
  }

  private generateResultFingerprint(result: SarifResult): string {
    const location = result.locations[0]?.physicalLocation;
    const uri = location?.artifactLocation.uri || '';
    const line = location?.region?.startLine || 0;
    
    return `${result.ruleId}-${uri}-${line}`;
  }

  private getToolInformationUri(toolName: string): string {
    const uriMap: Record<string, string> = {
      'nmap': 'https://nmap.org/',
      'masscan': 'https://github.com/robertdavidgraham/masscan',
      'ffuf': 'https://github.com/ffuf/ffuf',
      'gobuster': 'https://github.com/OJ/gobuster',
      'nikto': 'https://github.com/sullo/nikto',
      'sqlmap': 'https://github.com/sqlmapproject/sqlmap',
      'hydra': 'https://github.com/vanhauser-thc/thc-hydra',
      'john': 'https://github.com/openwall/john'
    };

    return uriMap[toolName.toLowerCase()] || 'https://redquanta.com/';
  }

  private getDefaultSecuritySeverity(level: string): string {
    const severityMap: Record<string, string> = {
      'error': '8.5',
      'warning': '5.0',
      'note': '2.0',
      'info': '1.0'
    };

    return severityMap[level] || '5.0';
  }

  private mapSarifLevelToGitHub(level: string): string {
    const levelMap: Record<string, string> = {
      'error': 'failure',
      'warning': 'warning',
      'note': 'notice',
      'info': 'notice'
    };

    return levelMap[level] || 'notice';
  }

  private escapeXml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&apos;');
  }
}
