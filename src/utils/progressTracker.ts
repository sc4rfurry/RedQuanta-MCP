/**
 * Real-time Progress Tracking System for RedQuanta MCP
 */

import { EventEmitter } from 'events';
import { AuditLogger } from './auditLogger.js';

export interface ProgressEvent {
  id: string;
  type: 'start' | 'progress' | 'complete' | 'error' | 'phase';
  timestamp: number;
  toolName: string;
  target?: string | undefined;
  phase?: string | undefined;
  progress?: number | undefined; // 0-100
  message?: string | undefined;
  data?: any;
  error?: string | undefined;
}

export interface ToolExecutionContext {
  id: string;
  toolName: string;
  parameters: any;
  startTime: number;
  progress: number;
  status: 'running' | 'completed' | 'failed';
  phases: string[];
  currentPhase?: string;
  results?: any;
  error?: string;
}

export class ProgressTracker extends EventEmitter {
  private executions: Map<string, ToolExecutionContext> = new Map();
  private auditLogger: AuditLogger;
  private eventHistory: Map<string, ProgressEvent[]> = new Map();

  constructor(auditLogger: AuditLogger) {
    super();
    this.auditLogger = auditLogger;
  }

  /**
   * Start tracking a new tool execution
   */
  public startExecution(toolName: string, parameters: any, phases: string[] = []): string {
    const executionId = this.generateExecutionId();
    const context: ToolExecutionContext = {
      id: executionId,
      toolName,
      parameters,
      startTime: Date.now(),
      progress: 0,
      status: 'running',
      phases: phases.length > 0 ? phases : this.getDefaultPhases(toolName)
    };

    this.executions.set(executionId, context);
    this.eventHistory.set(executionId, []);

    const event: ProgressEvent = {
      id: executionId,
      type: 'start',
      timestamp: Date.now(),
      toolName,
      target: parameters.target,
      progress: 0,
      message: `Started ${toolName} execution`
    };

    this.addEvent(executionId, event);
    this.emit('progress', event);

    return executionId;
  }

  /**
   * Update execution progress
   */
  public updateProgress(executionId: string, progress: number, message?: string, data?: any): void {
    const execution = this.executions.get(executionId);
    if (!execution || execution.status !== 'running') return;

    execution.progress = Math.min(100, Math.max(0, progress));

    const event: ProgressEvent = {
      id: executionId,
      type: 'progress',
      timestamp: Date.now(),
      toolName: execution.toolName,
      target: execution.parameters.target,
      progress: execution.progress,
      message,
      data
    };

    this.addEvent(executionId, event);
    this.emit('progress', event);
  }

  /**
   * Start a new phase
   */
  public startPhase(executionId: string, phaseName: string, message?: string): void {
    const execution = this.executions.get(executionId);
    if (!execution || execution.status !== 'running') return;

    execution.currentPhase = phaseName;

    const event: ProgressEvent = {
      id: executionId,
      type: 'phase',
      timestamp: Date.now(),
      toolName: execution.toolName,
      target: execution.parameters.target,
      phase: phaseName,
      message: message || `Started phase: ${phaseName}`
    };

    this.addEvent(executionId, event);
    this.emit('progress', event);
  }

  /**
   * Complete execution
   */
  public completeExecution(executionId: string, results?: any): void {
    const execution = this.executions.get(executionId);
    if (!execution) return;

    execution.status = 'completed';
    execution.progress = 100;
    execution.results = results;

    const event: ProgressEvent = {
      id: executionId,
      type: 'complete',
      timestamp: Date.now(),
      toolName: execution.toolName,
      target: execution.parameters.target,
      progress: 100,
      message: `${execution.toolName} execution completed successfully`,
      data: results
    };

    this.addEvent(executionId, event);
    this.emit('progress', event);

    this.auditLogger.logActivity({
      action: 'tool_execution_completed',
      target: executionId,
      details: {
        toolName: execution.toolName,
        duration: Date.now() - execution.startTime,
        success: true
      },
      outcome: 'success'
    });
  }

  /**
   * Fail execution
   */
  public failExecution(executionId: string, error: string): void {
    const execution = this.executions.get(executionId);
    if (!execution) return;

    execution.status = 'failed';
    execution.error = error;

    const event: ProgressEvent = {
      id: executionId,
      type: 'error',
      timestamp: Date.now(),
      toolName: execution.toolName,
      target: execution.parameters.target,
      error,
      message: `${execution.toolName} execution failed: ${error}`
    };

    this.addEvent(executionId, event);
    this.emit('progress', event);

    this.auditLogger.logActivity({
      action: 'tool_execution_failed',
      target: executionId,
      details: {
        toolName: execution.toolName,
        error,
        duration: Date.now() - execution.startTime
      },
      outcome: 'failure'
    });
  }

  /**
   * Get execution status
   */
  public getExecutionStatus(executionId: string): ToolExecutionContext | null {
    return this.executions.get(executionId) || null;
  }

  /**
   * Get active executions
   */
  public getActiveExecutions(): ToolExecutionContext[] {
    return Array.from(this.executions.values())
      .filter(exec => exec.status === 'running');
  }

  /**
   * Get execution statistics
   */
  public getStats(): any {
    const executions = Array.from(this.executions.values());
    const activeExecutions = executions.filter(e => e.status === 'running');

    return {
      totalExecutions: executions.length,
      activeExecutions: activeExecutions.length,
      completedExecutions: executions.filter(e => e.status === 'completed').length,
      failedExecutions: executions.filter(e => e.status === 'failed').length,
      toolUsage: this.getToolUsageStats(executions)
    };
  }

  // Private helper methods
  private generateExecutionId(): string {
    return `exec_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }

  private addEvent(executionId: string, event: ProgressEvent): void {
    if (!this.eventHistory.has(executionId)) {
      this.eventHistory.set(executionId, []);
    }

    const history = this.eventHistory.get(executionId)!;
    history.push(event);

    // Limit history size
    if (history.length > 100) {
      history.splice(0, history.length - 100);
    }
  }

  private getDefaultPhases(toolName: string): string[] {
    const phaseDefinitions: Record<string, string[]> = {
      'nmap_scan': ['discovery', 'port_scan', 'service_enum'],
      'ffuf_fuzz': ['wordlist_load', 'fuzzing', 'analysis'],
      'gobuster_scan': ['setup', 'enumeration', 'filtering'],
      'nikto_scan': ['initialization', 'vulnerability_scan', 'report_generation']
    };

    return phaseDefinitions[toolName] || ['execution'];
  }

  private getToolUsageStats(executions: ToolExecutionContext[]): Record<string, number> {
    const usage: Record<string, number> = {};
    for (const exec of executions) {
      usage[exec.toolName] = (usage[exec.toolName] || 0) + 1;
    }
    return usage;
  }
}
