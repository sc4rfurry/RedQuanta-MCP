/**
 * Enhanced Caching System for RedQuanta MCP
 * 
 * Features:
 * - Time-based TTL expiration
 * - LRU (Least Recently Used) eviction
 * - Size-based limits
 * - Intelligent cache key generation
 * - Cache statistics and monitoring
 * - Selective invalidation
 */

import { AuditLogger } from './auditLogger.js';
import { createHash } from 'crypto';

export interface CacheEntry<T> {
  key: string;
  value: T;
  timestamp: number;
  lastAccessed: number;
  ttl: number;
  size: number;
  tags: string[];
  metadata: Record<string, any>;
}

export interface CacheOptions {
  ttl?: number;
  maxSize?: number;
  maxEntries?: number;
  tags?: string[];
  metadata?: Record<string, any>;
}

export interface CacheStats {
  hits: number;
  misses: number;
  entries: number;
  totalSize: number;
  hitRate: number;
  oldestEntry?: number;
  newestEntry?: number;
  averageSize: number;
  topKeys: Array<{ key: string; hits: number; size: number }>;
}

export class CacheManager {
  private cache: Map<string, CacheEntry<any>> = new Map();
  private accessOrder: string[] = []; // For LRU tracking
  private stats: CacheStats;
  private auditLogger: AuditLogger;
  
  // Configuration
  private readonly defaultTTL = 300000; // 5 minutes
  private readonly maxSize = 100 * 1024 * 1024; // 100MB
  private readonly maxEntries = 1000;
  
  // Hit counters for individual keys
  private hitCounters: Map<string, number> = new Map();

  constructor(auditLogger: AuditLogger) {
    this.auditLogger = auditLogger;
    this.stats = {
      hits: 0,
      misses: 0,
      entries: 0,
      totalSize: 0,
      hitRate: 0,
      averageSize: 0,
      topKeys: []
    };
    
    // Start cleanup interval
    setInterval(() => this.cleanup(), 60000); // Cleanup every minute
  }

  /**
   * Generate intelligent cache key for tool execution
   */
  public generateToolKey(toolName: string, parameters: any, target?: string): string {
    const keyData = {
      tool: toolName,
      params: this.normalizeParameters(parameters),
      target: target || parameters.target || 'unknown',
      timestamp: Math.floor(Date.now() / 60000) // Round to minute for short-term caching
    };
    
    const keyString = JSON.stringify(keyData, Object.keys(keyData).sort());
    return createHash('sha256').update(keyString).digest('hex').substring(0, 16);
  }

  /**
   * Normalize parameters for consistent caching
   */
  private normalizeParameters(params: any): any {
    if (!params || typeof params !== 'object') return params;
    
    const normalized: any = {};
    
    // Sort keys and exclude time-sensitive parameters
    const excludeKeys = ['timestamp', 'requestId', 'sessionId', 'nonce'];
    
    Object.keys(params)
      .filter(key => !excludeKeys.includes(key))
      .sort()
      .forEach(key => {
        const value = params[key];
        
        // Normalize arrays and objects recursively
        if (Array.isArray(value)) {
          normalized[key] = value.sort();
        } else if (typeof value === 'object' && value !== null) {
          normalized[key] = this.normalizeParameters(value);
        } else {
          normalized[key] = value;
        }
      });
    
    return normalized;
  }

  /**
   * Store value in cache with intelligent sizing
   */
  public async set<T>(
    key: string, 
    value: T, 
    options: CacheOptions = {}
  ): Promise<void> {
    const now = Date.now();
    const ttl = options.ttl || this.defaultTTL;
    const tags = options.tags || [];
    const metadata = options.metadata || {};
    
    // Calculate size estimate
    const size = this.estimateSize(value);
    
    // Check if we need to make space
    await this.ensureSpace(size);
    
    const entry: CacheEntry<T> = {
      key,
      value,
      timestamp: now,
      lastAccessed: now,
      ttl,
      size,
      tags,
      metadata
    };
    
    // Remove existing entry if present
    if (this.cache.has(key)) {
      this.removeFromAccessOrder(key);
      const oldEntry = this.cache.get(key)!;
      this.stats.totalSize -= oldEntry.size;
    }
    
    // Add new entry
    this.cache.set(key, entry);
    this.accessOrder.push(key);
    this.hitCounters.set(key, 0);
    
    // Update stats
    this.stats.entries = this.cache.size;
    this.stats.totalSize += size;
    this.updateStats();
    
    // Log cache operation
    await this.auditLogger.logActivity({
      action: 'cache_set',
      target: key,
      details: {
        size,
        ttl,
        tags: tags.length,
        totalEntries: this.stats.entries,
        totalSize: this.stats.totalSize
      },
      outcome: 'success'
    });
  }

  /**
   * Retrieve value from cache with access tracking
   */
  public async get<T>(key: string): Promise<T | null> {
    const entry = this.cache.get(key) as CacheEntry<T> | undefined;
    
    if (!entry) {
      this.stats.misses++;
      this.updateStats();
      return null;
    }
    
    const now = Date.now();
    
    // Check if expired
    if (now - entry.timestamp > entry.ttl) {
      await this.delete(key);
      this.stats.misses++;
      this.updateStats();
      return null;
    }
    
    // Update access tracking
    entry.lastAccessed = now;
    this.updateAccessOrder(key);
    
    // Update hit stats
    this.stats.hits++;
    const hitCount = (this.hitCounters.get(key) || 0) + 1;
    this.hitCounters.set(key, hitCount);
    
    this.updateStats();
    
    return entry.value;
  }

  /**
   * Delete specific cache entry
   */
  public async delete(key: string): Promise<boolean> {
    const entry = this.cache.get(key);
    if (!entry) return false;
    
    this.cache.delete(key);
    this.removeFromAccessOrder(key);
    this.hitCounters.delete(key);
    
    // Update stats
    this.stats.entries = this.cache.size;
    this.stats.totalSize -= entry.size;
    this.updateStats();
    
    await this.auditLogger.logActivity({
      action: 'cache_delete',
      target: key,
      details: {
        sizeFreed: entry.size,
        reason: 'manual_deletion'
      },
      outcome: 'success'
    });
    
    return true;
  }

  /**
   * Clear cache entries by tags
   */
  public async invalidateByTags(tags: string[]): Promise<number> {
    let deletedCount = 0;
    const tagsSet = new Set(tags);
    
    for (const [key, entry] of this.cache.entries()) {
      if (entry.tags.some(tag => tagsSet.has(tag))) {
        await this.delete(key);
        deletedCount++;
      }
    }
    
    await this.auditLogger.logActivity({
      action: 'cache_invalidate_tags',
      details: {
        tags,
        deletedEntries: deletedCount
      },
      outcome: 'success'
    });
    
    return deletedCount;
  }

  /**
   * Get cache statistics
   */
  public getStats(): CacheStats {
    this.updateStats();
    return { ...this.stats };
  }

  /**
   * Update access order for LRU tracking
   */
  private updateAccessOrder(key: string): void {
    this.removeFromAccessOrder(key);
    this.accessOrder.push(key);
  }

  /**
   * Remove key from access order tracking
   */
  private removeFromAccessOrder(key: string): void {
    const index = this.accessOrder.indexOf(key);
    if (index > -1) {
      this.accessOrder.splice(index, 1);
    }
  }

  /**
   * Ensure we have space for new entry
   */
  private async ensureSpace(newEntrySize: number): Promise<void> {
    // Check entry count limit
    while (this.cache.size >= this.maxEntries && this.accessOrder.length > 0) {
      const oldestKey = this.accessOrder[0];
      if (oldestKey) {
        await this.delete(oldestKey);
      }
    }
    
    // Check size limit
    while (this.stats.totalSize + newEntrySize > this.maxSize && this.accessOrder.length > 0) {
      const oldestKey = this.accessOrder[0];
      if (oldestKey) {
        await this.delete(oldestKey);
      }
    }
  }

  /**
   * Estimate object size in bytes
   */
  private estimateSize(obj: any): number {
    const jsonString = JSON.stringify(obj);
    return Buffer.byteLength(jsonString, 'utf8');
  }

  /**
   * Cleanup expired entries
   */
  private async cleanup(): Promise<void> {
    const now = Date.now();
    let expiredCount = 0;
    
    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > entry.ttl) {
        await this.delete(key);
        expiredCount++;
      }
    }
    
    if (expiredCount > 0) {
      await this.auditLogger.logActivity({
        action: 'cache_cleanup',
        details: {
          expiredEntries: expiredCount,
          remainingEntries: this.cache.size
        },
        outcome: 'success'
      });
    }
  }

  /**
   * Update cache statistics
   */
  private updateStats(): void {
    const totalRequests = this.stats.hits + this.stats.misses;
    this.stats.hitRate = totalRequests > 0 ? this.stats.hits / totalRequests : 0;
    this.stats.entries = this.cache.size;
    this.stats.averageSize = this.stats.entries > 0 ? this.stats.totalSize / this.stats.entries : 0;
    
    // Find oldest and newest entries
    if (this.cache.size > 0) {
      const timestamps = Array.from(this.cache.values()).map(e => e.timestamp);
      this.stats.oldestEntry = Math.min(...timestamps);
      this.stats.newestEntry = Math.max(...timestamps);
    }
    
    // Generate top keys by hits and size
    this.stats.topKeys = Array.from(this.cache.entries())
      .map(([key, entry]) => ({
        key,
        hits: this.hitCounters.get(key) || 0,
        size: entry.size
      }))
      .sort((a, b) => b.hits - a.hits)
      .slice(0, 10);
  }

  /**
   * Clear all cache entries
   */
  public async clear(): Promise<void> {
    const entriesCleared = this.cache.size;
    
    this.cache.clear();
    this.accessOrder = [];
    this.hitCounters.clear();
    this.stats = {
      hits: 0,
      misses: 0,
      entries: 0,
      totalSize: 0,
      hitRate: 0,
      averageSize: 0,
      topKeys: []
    };
    
    await this.auditLogger.logActivity({
      action: 'cache_clear',
      details: {
        entriesCleared
      },
      outcome: 'success'
    });
  }
}

/**
 * Cached tool execution wrapper
 */
export class CachedToolExecutor {
  private cacheManager: CacheManager;
  
  constructor(cacheManager: CacheManager) {
    this.cacheManager = cacheManager;
  }
  
  /**
   * Execute tool with intelligent caching
   */
  public async executeWithCache<T>(
    toolName: string,
    parameters: any,
    executor: () => Promise<T>,
    options: CacheOptions = {}
  ): Promise<{ result: T; cached: boolean; cacheKey: string }> {
    const cacheKey = this.cacheManager.generateToolKey(toolName, parameters);
    
    // Try to get from cache first
    const cachedResult = await this.cacheManager.get<T>(cacheKey);
    if (cachedResult !== null) {
      return {
        result: cachedResult,
        cached: true,
        cacheKey
      };
    }
    
    // Execute tool and cache result
    const result = await executor();
    
    // Determine caching strategy based on tool type
    const cacheOptions = this.getCacheOptionsForTool(toolName, parameters, options);
    
    await this.cacheManager.set(cacheKey, result, cacheOptions);
    
    return {
      result,
      cached: false,
      cacheKey
    };
  }
  
  /**
   * Get cache options based on tool characteristics
   */
  private getCacheOptionsForTool(toolName: string, parameters: any, userOptions: CacheOptions): CacheOptions {
    const baseOptions: CacheOptions = {
      tags: [toolName, 'tool_execution'],
      metadata: {
        toolName,
        target: parameters.target || 'unknown',
        executedAt: new Date().toISOString()
      }
    };
    
    // Tool-specific caching strategies
    switch (toolName) {
      case 'nmap_scan':
        return {
          ...baseOptions,
          ttl: 600000, // 10 minutes for network scans
          tags: [...(baseOptions.tags || []), 'network', 'discovery'],
          ...userOptions
        };
        
      case 'ffuf_fuzz':
      case 'gobuster_scan':
        return {
          ...baseOptions,
          ttl: 1800000, // 30 minutes for web fuzzing
          tags: [...(baseOptions.tags || []), 'web', 'enumeration'],
          ...userOptions
        };
        
      case 'nikto_scan':
        return {
          ...baseOptions,
          ttl: 3600000, // 1 hour for vulnerability scans
          tags: [...(baseOptions.tags || []), 'web', 'vulnerability'],
          ...userOptions
        };
        
      default:
        return {
          ...baseOptions,
          ttl: 300000, // 5 minutes default
          ...userOptions
        };
    }
  }
}
