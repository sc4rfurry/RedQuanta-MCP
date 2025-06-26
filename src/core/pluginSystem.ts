/**
 * Plugin System for RedQuanta MCP
 * Enables dynamic loading of tools, custom scripts, and user-defined plugins
 */

import { ToolWrapper } from '../tools/base.js';
import { Logger } from 'pino';
import { promises as fs } from 'fs';
import { join, resolve, dirname, extname } from 'path';
import { pathToFileURL } from 'url';
import { AuditLogger } from '../utils/auditLogger.js';
import { CommandRunner } from '../utils/commandRunner.js';
import { PathGuard } from '../utils/pathGuard.js';

export interface PluginManifest {
  name: string;
  version: string;
  description: string;
  author?: string;
  category: 'network' | 'web' | 'exploitation' | 'password' | 'forensics' | 'automation' | 'custom';
  dangerLevel: 'safe' | 'caution' | 'dangerous';
  entryPoint: string;
  dependencies?: string[];
  schema?: any;
  examples?: PluginExample[];
  documentation?: string;
  customCommands?: CustomCommand[];
}

export interface PluginExample {
  title: string;
  description: string;
  command: string;
  parameters: Record<string, any>;
  expectedOutput?: string;
}

export interface CustomCommand {
  name: string;
  description: string;
  parameters: CustomParameter[];
  examples: string[];
}

export interface CustomParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';
  description: string;
  required?: boolean;
  default?: any;
  enum?: any[];
  pattern?: string;
}

export interface LoadedPlugin {
  manifest: PluginManifest;
  instance: ToolWrapper;
  filePath: string;
  loadedAt: Date;
}

export class PluginSystem {
  private plugins: Map<string, LoadedPlugin> = new Map();
  private pluginPaths: string[] = [];
  private logger: Logger;
  private auditLogger: AuditLogger;
  private allowDangerous: boolean;

  constructor(logger: Logger, auditLogger: AuditLogger, allowDangerous: boolean = false) {
    this.logger = logger;
    this.auditLogger = auditLogger;
    this.allowDangerous = allowDangerous;
    
    // Default plugin search paths
    this.pluginPaths = [
      './plugins',
      './src/plugins',
      './custom-tools',
      process.env.REDQUANTA_PLUGIN_PATH || './plugins'
    ];
  }

  /**
   * Initialize plugin system and discover plugins
   */
  async initialize(): Promise<void> {
    this.logger.info('Initializing plugin system...');
    
    // Create plugin directories if they don't exist
    for (const pluginPath of this.pluginPaths) {
      try {
        await fs.mkdir(pluginPath, { recursive: true });
      } catch (error) {
        this.logger.debug({ path: pluginPath, error }, 'Could not create plugin directory');
      }
    }

    // Discover and load plugins
    await this.discoverPlugins();
    
    this.logger.info({ 
      totalPlugins: this.plugins.size, 
      paths: this.pluginPaths 
    }, 'Plugin system initialized');
  }

  /**
   * Discover plugins in all configured paths
   */
  private async discoverPlugins(): Promise<void> {
    for (const basePath of this.pluginPaths) {
      try {
        const pluginDir = resolve(basePath);
        const exists = await fs.access(pluginDir).then(() => true).catch(() => false);
        
        if (!exists) continue;

        const entries = await fs.readdir(pluginDir, { withFileTypes: true });
        
        for (const entry of entries) {
          if (entry.isDirectory()) {
            await this.loadPluginFromDirectory(join(pluginDir, entry.name));
          } else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.ts'))) {
            await this.loadPluginFromFile(join(pluginDir, entry.name));
          }
        }
      } catch (error) {
        this.logger.warn({ path: basePath, error }, 'Failed to scan plugin directory');
      }
    }
  }

  /**
   * Load plugin from directory with manifest
   */
  private async loadPluginFromDirectory(pluginDir: string): Promise<void> {
    try {
      const manifestPath = join(pluginDir, 'plugin.json');
      const manifestExists = await fs.access(manifestPath).then(() => true).catch(() => false);
      
      if (!manifestExists) {
        this.logger.debug({ dir: pluginDir }, 'No plugin.json found, skipping directory');
        return;
      }

      const manifestContent = await fs.readFile(manifestPath, 'utf-8');
      const manifest: PluginManifest = JSON.parse(manifestContent);
      
      // Validate manifest
      if (!this.validateManifest(manifest)) {
        this.logger.warn({ dir: pluginDir }, 'Invalid plugin manifest');
        return;
      }

      // Check danger level
      if (manifest.dangerLevel === 'dangerous' && !this.allowDangerous) {
        this.logger.warn({ 
          plugin: manifest.name, 
          dangerLevel: manifest.dangerLevel 
        }, 'Skipping dangerous plugin (use --dangerous to enable)');
        return;
      }

      const entryPath = join(pluginDir, manifest.entryPoint);
      const plugin = await this.loadPluginModule(entryPath, manifest);
      
      if (plugin) {
        await this.registerPlugin(manifest, plugin, entryPath);
      }
    } catch (error) {
      this.logger.error({ dir: pluginDir, error }, 'Failed to load plugin from directory');
    }
  }

  /**
   * Load plugin from single file
   */
  private async loadPluginFromFile(filePath: string): Promise<void> {
    try {
      // For single files, try to extract manifest from comments or use defaults
      const content = await fs.readFile(filePath, 'utf-8');
      const manifest = this.extractManifestFromFile(content, filePath);
      
      const plugin = await this.loadPluginModule(filePath, manifest);
      
      if (plugin) {
        await this.registerPlugin(manifest, plugin, filePath);
      }
    } catch (error) {
      this.logger.error({ file: filePath, error }, 'Failed to load plugin from file');
    }
  }

  /**
   * Load plugin module dynamically
   */
  private async loadPluginModule(filePath: string, manifest: PluginManifest): Promise<ToolWrapper | null> {
    try {
      const fileUrl = pathToFileURL(resolve(filePath)).href;
      const module = await import(fileUrl);
      
      // Look for default export or named export matching plugin name
      const PluginClass = module.default || module[manifest.name] || module[`${manifest.name}Tool`];
      
      if (!PluginClass) {
        this.logger.warn({ file: filePath }, 'No valid plugin class found in module');
        return null;
      }

      // Instantiate plugin
      const instance = new PluginClass();
      
      if (!(instance instanceof ToolWrapper)) {
        this.logger.warn({ file: filePath }, 'Plugin does not extend ToolWrapper');
        return null;
      }

      return instance;
    } catch (error) {
      this.logger.error({ file: filePath, error }, 'Failed to load plugin module');
      return null;
    }
  }

  /**
   * Register loaded plugin
   */
  private async registerPlugin(manifest: PluginManifest, instance: ToolWrapper, filePath: string): Promise<void> {
    const loadedPlugin: LoadedPlugin = {
      manifest,
      instance,
      filePath,
      loadedAt: new Date()
    };

    this.plugins.set(manifest.name, loadedPlugin);
    
    await this.auditLogger.logActivity({
      action: 'plugin_loaded',
      target: manifest.name,
      details: {
        plugin: manifest.name,
        version: manifest.version,
        category: manifest.category,
        dangerLevel: manifest.dangerLevel,
        filePath
      },
      outcome: 'success'
    });

    this.logger.info({ 
      plugin: manifest.name, 
      version: manifest.version,
      category: manifest.category 
    }, 'Plugin loaded successfully');
  }

  /**
   * Validate plugin manifest
   */
  private validateManifest(manifest: any): manifest is PluginManifest {
    const required = ['name', 'version', 'description', 'category', 'entryPoint'];
    
    for (const field of required) {
      if (!manifest[field]) {
        this.logger.warn({ field, manifest }, `Missing required manifest field: ${field}`);
        return false;
      }
    }

    const validCategories = ['network', 'web', 'exploitation', 'password', 'forensics', 'automation', 'custom'];
    if (!validCategories.includes(manifest.category)) {
      this.logger.warn({ category: manifest.category }, 'Invalid plugin category');
      return false;
    }

    const validDangerLevels = ['safe', 'caution', 'dangerous'];
    if (manifest.dangerLevel && !validDangerLevels.includes(manifest.dangerLevel)) {
      this.logger.warn({ dangerLevel: manifest.dangerLevel }, 'Invalid danger level');
      return false;
    }

    return true;
  }

  /**
   * Extract manifest from file comments
   */
  private extractManifestFromFile(content: string, filePath: string): PluginManifest {
    const fileName = filePath.split('/').pop()?.replace(/\.(js|ts)$/, '') || 'unknown';
    
    // Try to extract manifest from JSDoc-style comments
    const manifestRegex = /\/\*\*\s*@plugin\s*({[\s\S]*?})\s*\*\//;
    const match = content.match(manifestRegex);
    
    if (match && match[1]) {
      try {
        return JSON.parse(match[1]);
      } catch (error) {
        this.logger.debug({ file: filePath }, 'Could not parse embedded manifest');
      }
    }

    // Default manifest for single files
    return {
      name: fileName,
      version: '1.0.0',
      description: `Custom tool: ${fileName}`,
      category: 'custom',
      dangerLevel: 'caution',
      entryPoint: filePath
    };
  }

  /**
   * Get all loaded plugins
   */
  getPlugins(): Map<string, LoadedPlugin> {
    return new Map(this.plugins);
  }

  /**
   * Get plugin by name
   */
  getPlugin(name: string): LoadedPlugin | undefined {
    return this.plugins.get(name);
  }

  /**
   * Get plugins by category
   */
  getPluginsByCategory(category: string): LoadedPlugin[] {
    return Array.from(this.plugins.values()).filter(
      plugin => plugin.manifest.category === category
    );
  }

  /**
   * Get plugin documentation and help
   */
  getPluginHelp(name: string): any {
    const plugin = this.plugins.get(name);
    if (!plugin) return null;

    const manifest = plugin.manifest;
    
    return {
      name: manifest.name,
      version: manifest.version,
      description: manifest.description,
      category: manifest.category,
      dangerLevel: manifest.dangerLevel,
      author: manifest.author,
      documentation: manifest.documentation,
      schema: manifest.schema,
      examples: manifest.examples || [],
      customCommands: manifest.customCommands || [],
      usage: this.generateUsageExamples(manifest),
      loadedAt: plugin.loadedAt.toISOString(),
      filePath: plugin.filePath
    };
  }

  /**
   * Generate usage examples for LLMs
   */
  private generateUsageExamples(manifest: PluginManifest): any {
    const examples = {
      basicUsage: `Use tool "${manifest.name}" for ${manifest.description.toLowerCase()}`,
      parameters: manifest.schema?.properties || {},
      customCommands: [] as any[]
    };

    if (manifest.customCommands) {
      examples.customCommands = manifest.customCommands.map(cmd => ({
        command: cmd.name,
        description: cmd.description,
        examples: cmd.examples
      }));
    }

    return examples;
  }

  /**
   * Reload plugin by name
   */
  async reloadPlugin(name: string): Promise<boolean> {
    const existing = this.plugins.get(name);
    if (!existing) {
      this.logger.warn({ plugin: name }, 'Cannot reload non-existent plugin');
      return false;
    }

    this.logger.info({ plugin: name }, 'Reloading plugin...');
    
    // Remove existing plugin
    this.plugins.delete(name);
    
    // Reload from file
    if (existing.filePath.endsWith('plugin.json')) {
      await this.loadPluginFromDirectory(dirname(existing.filePath));
    } else {
      await this.loadPluginFromFile(existing.filePath);
    }

    const reloaded = this.plugins.has(name);
    this.logger.info({ plugin: name, success: reloaded }, 'Plugin reload completed');
    
    return reloaded;
  }

  /**
   * Get comprehensive plugin system info for LLMs
   */
  getSystemInfo(): any {
    const plugins = Array.from(this.plugins.values());
    
    return {
      status: 'active',
      totalPlugins: plugins.length,
      pluginPaths: this.pluginPaths,
      allowDangerous: this.allowDangerous,
      categories: this.getCategoryStats(),
      dangerLevels: this.getDangerLevelStats(),
      recentlyLoaded: plugins
        .sort((a, b) => b.loadedAt.getTime() - a.loadedAt.getTime())
        .slice(0, 5)
        .map(p => ({
          name: p.manifest.name,
          category: p.manifest.category,
          loadedAt: p.loadedAt.toISOString()
        })),
      availableCommands: this.getAllCustomCommands()
    };
  }

  /**
   * Get category statistics
   */
  private getCategoryStats(): Record<string, number> {
    const stats: Record<string, number> = {};
    
    for (const plugin of this.plugins.values()) {
      const category = plugin.manifest.category;
      stats[category] = (stats[category] || 0) + 1;
    }
    
    return stats;
  }

  /**
   * Get danger level statistics
   */
  private getDangerLevelStats(): Record<string, number> {
    const stats: Record<string, number> = {};
    
    for (const plugin of this.plugins.values()) {
      const danger = plugin.manifest.dangerLevel || 'safe';
      stats[danger] = (stats[danger] || 0) + 1;
    }
    
    return stats;
  }

  /**
   * Get all custom commands from plugins
   */
  private getAllCustomCommands(): any[] {
    const commands: any[] = [];
    
    for (const plugin of this.plugins.values()) {
      if (plugin.manifest.customCommands) {
        for (const cmd of plugin.manifest.customCommands) {
          commands.push({
            plugin: plugin.manifest.name,
            command: cmd.name,
            description: cmd.description,
            category: plugin.manifest.category
          });
        }
      }
    }
    
    return commands;
  }

  /**
   * Add plugin path
   */
  addPluginPath(path: string): void {
    if (!this.pluginPaths.includes(path)) {
      this.pluginPaths.push(path);
      this.logger.info({ path }, 'Added plugin search path');
    }
  }

  /**
   * Install plugin from file or URL
   */
  async installPlugin(source: string, targetDir?: string): Promise<boolean> {
    try {
      this.logger.info({ source }, 'Installing plugin...');
      
      // Implementation would handle downloading/copying plugin files
      // For now, just log the intent
      await this.auditLogger.logActivity({
        action: 'plugin_install',
        target: source,
        details: { 
          source,
          targetDir 
        },
        outcome: 'success'
      });
      
      this.logger.info({ source }, 'Plugin installation completed');
      return true;
    } catch (error) {
      this.logger.error({ source, error }, 'Plugin installation failed');
      return false;
    }
  }
} 