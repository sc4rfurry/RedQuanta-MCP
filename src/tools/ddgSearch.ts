/**
 * DuckDuckGo Search Tool - Advanced OSINT and Intelligence Gathering
 */

import * as DDG from 'duck-duck-scrape';
import fetch from 'node-fetch';
import { ToolWrapper, ToolResult } from './base.js';

interface DDGSearchArgs {
  query: string;
  searchType?: 'web' | 'images' | 'videos' | 'news' | 'autocomplete';
  maxResults?: number;
  safeSearch?: boolean;
  region?: string;
  timeRange?: 'day' | 'week' | 'month' | 'year';
}

interface DDGSpiceArgs {
  spiceType: 'stocks' | 'currency' | 'weather' | 'dictionary' | 'dns' | 'time' | 'thesaurus' | 'expandUrl';
  query?: string;
  fromCurrency?: string;
  toCurrency?: string;
  amount?: number;
  recordType?: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'NS' | 'PTR' | 'SOA' | 'TXT';
  location?: string;
  locale?: string;
  url?: string;
}

export class DDGSearchTool extends ToolWrapper {
  constructor() {
    super('ddg_search');
  }

  // Safe logging method that respects MCP stdio mode
  private safeLog(message: string): void {
    const mcpMode = process.env.MCP_MODE;
    if (mcpMode === 'stdio') {
      // In stdio mode, send to stderr to avoid interfering with MCP JSON-RPC on stdout
      // Remove emojis for MCP compatibility
      const cleanMessage = message
        .replace(/[🔧✅🚀📚🛑🔗🎯🕷️🏃‍♂️🌐🐳📖🛡️⚠️❌🔍🌶️]/g, '') // Remove common emojis
        .replace(/[\u{1F600}-\u{1F64F}]|[\u{1F300}-\u{1F5FF}]|[\u{1F680}-\u{1F6FF}]|[\u{1F1E0}-\u{1F1FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu, '') // Remove all emojis
        .replace(/\s+/g, ' ') // Normalize whitespace
        .trim();
      console.error(`[DDGSearch] ${cleanMessage}`);
    } else {
      // In other modes, normal console output is fine with emojis
      console.log(message);
    }
  }

  public override async execute(args: DDGSearchArgs): Promise<ToolResult> {
    try {
      const { query, searchType = 'web', maxResults = 10, safeSearch = true, region, timeRange } = args;
      
      // Input validation
      if (!query || query.trim().length === 0) {
        return {
          success: false,
          tool: 'ddg_search',
          error: 'Query parameter is required and cannot be empty',
          data: { query, searchType }
        };
      }

      if (maxResults < 1 || maxResults > 50) {
        return {
          success: false,
          tool: 'ddg_search',
          error: 'maxResults must be between 1 and 50',
          data: { query, searchType, maxResults }
        };
      }
      
      this.safeLog(`🔍 DuckDuckGo ${searchType} search: "${query}"`);
      
      const startTime = Date.now();
      let results: any;

      const options: any = {
        safeSearch: safeSearch ? DDG.SafeSearchType.STRICT : DDG.SafeSearchType.OFF,
        region: region || 'wt-wt'
      };

      // Add time range filtering if specified
      if (timeRange && searchType !== 'autocomplete') {
        const timeMap: Record<string, any> = {
          'day': DDG.SearchTimeType.DAY,
          'week': DDG.SearchTimeType.WEEK,
          'month': DDG.SearchTimeType.MONTH,
          'year': DDG.SearchTimeType.YEAR
        };
        options.time = timeMap[timeRange];
      }

      try {
        switch (searchType) {
          case 'web':
            try {
              results = await DDG.search(query, options);
            } catch (ddgLibError) {
              this.safeLog('⚠️ Duck-duck-scrape library failed, using fallback search');
              // Fallback to simple HTTP search when library fails
              const fallbackResults = await this.performFallbackWebSearch(query, maxResults, safeSearch);
              results = { results: fallbackResults, vqd: null };
            }
            break;
          case 'images':
            results = await DDG.searchImages(query, options);
            break;
          case 'videos':
            results = await DDG.searchVideos(query, options);
            break;
          case 'news':
            results = await DDG.searchNews(query, options);
            break;
          case 'autocomplete':
            results = await DDG.autocomplete(query, region);
            break;
          default:
            return {
              success: false,
              tool: 'ddg_search',
              error: `Unsupported search type: ${searchType}. Supported types: web, images, videos, news, autocomplete`,
              data: { query, searchType }
            };
        }
      } catch (ddgError) {
        this.safeLog('DDG API Error:');
        this.safeLog(ddgError instanceof Error ? ddgError.message : 'DDG API call failed');
        
        return {
          success: false,
          tool: 'ddg_search',
          error: `DDG API Error: ${ddgError instanceof Error ? ddgError.message : 'DDG API call failed'}`,
          data: { query, searchType, apiError: ddgError instanceof Error ? ddgError.message : 'DDG API call failed' }
        };
      }

      // Validate results
      if (!results) {
        return {
          success: false,
          tool: 'ddg_search',
          error: 'DDG API returned no results',
          data: { query, searchType }
        };
      }

      // Limit results if needed
      if (results.results && results.results.length > maxResults) {
        results.results = results.results.slice(0, maxResults);
      }

      const duration = Date.now() - startTime;
      const resultsCount = Array.isArray(results.results) ? results.results.length : (Array.isArray(results) ? results.length : 0);

      return {
        success: true,
        tool: 'ddg_search',
        duration,
        data: {
          searchType,
          query,
          resultsCount,
          results: results.results || results,
          metadata: {
            safeSearch,
            region,
            timeRange,
            vqd: results.vqd,
            noResults: results.noResults || false
          }
        }
      };

    } catch (error) {
      this.safeLog('DDG Search execution error:');
      this.safeLog(error instanceof Error ? error.message : 'Unknown execution error');
      
      return {
        success: false,
        tool: 'ddg_search',
        error: `Execution error: ${error instanceof Error ? error.message : 'Unknown execution error'}`,
        data: { 
          query: args.query, 
          searchType: args.searchType || 'web',
          executionError: error instanceof Error ? error.message : 'Unknown execution error'
        }
      };
    }
  }

  private async performFallbackWebSearch(query: string, maxResults: number, safeSearch: boolean): Promise<any[]> {
    const results: any[] = [];
    
    try {
      this.safeLog('🔄 Using fallback DuckDuckGo HTML search...');
      const searchUrl = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}${safeSearch ? '&safe_search=1' : ''}`;
      
      const response = await fetch(searchUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'DNT': '1',
          'Connection': 'keep-alive'
        }
      });

      if (response.ok) {
        const html = await response.text();
        const parsedResults = this.parseDuckDuckGoHTML(html, maxResults);
        this.safeLog(`✅ Fallback search found ${parsedResults.length} results`);
        results.push(...parsedResults);
      } else {
        console.warn(`⚠️ Fallback search failed with status ${response.status}`);
      }
    } catch (error) {
      console.error('❌ Fallback search failed:', error);
    }

    // If fallback also fails, provide some basic security-focused results
    if (results.length === 0 && this.isSecurityQuery(query)) {
      this.safeLog('📚 Using security knowledge base as final fallback');
      results.push(...this.getSecurityKnowledgeResults(query, maxResults));
    }

    return results.slice(0, maxResults);
  }

  private parseDuckDuckGoHTML(html: string, maxResults: number): any[] {
    const results: any[] = [];
    
    try {
      // Multiple regex patterns to handle different DuckDuckGo HTML structures
      const patterns = [
        // Pattern 1: Standard result links
        /<a[^>]+class="[^"]*result[^"]*"[^>]+href="([^"]+)"[^>]*>([^<]+)<\/a>/g,
        // Pattern 2: Alternative structure
        /<h3[^>]*><a[^>]+href="([^"]+)"[^>]*>([^<]+)<\/a><\/h3>/g,
        // Pattern 3: Simple link structure
        /<a[^>]+href="(https?:\/\/[^"]+)"[^>]*>([^<]+)<\/a>/g
      ];

      for (const pattern of patterns) {
        let match;
        let count = 0;
        
        while ((match = pattern.exec(html)) !== null && count < maxResults) {
          const url = match[1];
          const title = match[2];
          
          // Skip internal DuckDuckGo links and invalid URLs
          if (!url || !title || url.startsWith('/') || url.includes('duckduckgo.com') || url.length < 10) {
            continue;
          }
          
          // Clean up title and URL
          const cleanTitle = title.replace(/<[^>]*>/g, '').trim();
          const cleanUrl = url.startsWith('http') ? url : `https://${url}`;
          
          if (cleanTitle && cleanUrl && !results.some(r => r.url === cleanUrl)) {
            results.push({
              title: cleanTitle,
              url: cleanUrl,
              snippet: `Search result for "${cleanTitle.substring(0, 100)}..."`,
              source: 'duckduckgo-fallback',
              type: 'web_result'
            });
            count++;
          }
        }
        
        if (results.length >= maxResults) break;
      }
    } catch (error) {
      console.error('❌ Error parsing DuckDuckGo HTML:', error);
    }
    
    return results;
  }

  private isSecurityQuery(query: string): boolean {
    const securityKeywords = [
      'vulnerability', 'exploit', 'cve', 'security', 'penetration', 'pentest',
      'nmap', 'masscan', 'nikto', 'burp', 'metasploit', 'owasp', 'nist',
      'cybersecurity', 'infosec', 'hacking', 'malware', 'forensics'
    ];
    
    const lowerQuery = query.toLowerCase();
    return securityKeywords.some(keyword => lowerQuery.includes(keyword));
  }

  private getSecurityKnowledgeResults(query: string, maxResults: number): any[] {
    const lowerQuery = query.toLowerCase();
    const results: any[] = [];
    
    // CVE and vulnerability resources
    if (lowerQuery.includes('cve') || lowerQuery.includes('vulnerability')) {
      results.push({
        title: 'CVE Details - Vulnerability Database',
        url: `https://cvedetails.com/cve-search.php?search=${encodeURIComponent(query)}`,
        snippet: 'Comprehensive CVE database with vulnerability details and CVSS scores',
        source: 'security-knowledge',
        type: 'vulnerability_database'
      });
    }
    
    // Security frameworks
    if (lowerQuery.includes('owasp') || lowerQuery.includes('framework')) {
      results.push({
        title: 'OWASP Security Resources',
        url: 'https://owasp.org/www-project-top-ten/',
        snippet: 'OWASP Top 10 and security testing methodologies',
        source: 'security-knowledge',
        type: 'methodology'
      });
    }
    
    // Penetration testing resources
    if (lowerQuery.includes('pentest') || lowerQuery.includes('penetration')) {
      results.push({
        title: 'Penetration Testing Execution Standard',
        url: 'http://www.pentest-standard.org/',
        snippet: 'Comprehensive penetration testing methodology and guidelines',
        source: 'security-knowledge',
        type: 'methodology'
      });
    }
    
    return results.slice(0, maxResults);
  }
}

export class DDGSpiceTool extends ToolWrapper {
  constructor() {
    super('ddg_spice');
  }

  // Safe logging method that respects MCP stdio mode
  private safeLog(message: string): void {
    const mcpMode = process.env.MCP_MODE;
    if (mcpMode === 'stdio') {
      // In stdio mode, send to stderr to avoid interfering with MCP JSON-RPC on stdout
      // Remove emojis for MCP compatibility
      const cleanMessage = message
        .replace(/[🔧✅🚀📚🛑🔗🎯🕷️🏃‍♂️🌐🐳📖🛡️⚠️❌🔍🌶️]/g, '') // Remove common emojis
        .replace(/[\u{1F600}-\u{1F64F}]|[\u{1F300}-\u{1F5FF}]|[\u{1F680}-\u{1F6FF}]|[\u{1F1E0}-\u{1F1FF}]|[\u{2600}-\u{26FF}]|[\u{2700}-\u{27BF}]/gu, '') // Remove all emojis
        .replace(/\s+/g, ' ') // Normalize whitespace
        .trim();
      console.error(`[DDGSpice] ${cleanMessage}`);
    } else {
      // In other modes, normal console output is fine with emojis
      console.log(message);
    }
  }

  public override async execute(args: DDGSpiceArgs): Promise<ToolResult> {
    try {
      // Input validation
      if (!args.spiceType) {
        return {
          success: false,
          tool: 'ddg_spice',
          error: 'spiceType parameter is required',
          data: args
        };
      }

      const startTime = Date.now();
      let results: any;

      this.safeLog(`🌶️ DuckDuckGo Spice API: ${args.spiceType}`);

      try {
        switch (args.spiceType) {
          case 'stocks':
            if (!args.query) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'Stock symbol (query) required for stocks API',
                data: { spiceType: args.spiceType }
              };
            }
            results = await DDG.stocks(args.query);
            break;
            
          case 'currency':
            if (!args.fromCurrency || !args.toCurrency) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'fromCurrency and toCurrency are required for currency conversion',
                data: { spiceType: args.spiceType, fromCurrency: args.fromCurrency, toCurrency: args.toCurrency }
              };
            }
            results = await DDG.currency(args.fromCurrency, args.toCurrency, args.amount || 1);
            break;
            
          case 'weather':
            const weatherLocation = args.location || args.query;
            if (!weatherLocation) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'Location or query required for weather forecast',
                data: { spiceType: args.spiceType }
              };
            }
            results = await DDG.forecast(weatherLocation, args.locale);
            break;
            
          case 'dictionary':
            if (!args.query) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'Word (query) required for dictionary lookup',
                data: { spiceType: args.spiceType }
              };
            }
            results = await DDG.dictionaryDefinition(args.query);
            break;
            
          case 'dns':
            if (!args.query) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'Domain (query) required for DNS lookup',
                data: { spiceType: args.spiceType }
              };
            }
            const recordType = args.recordType || 'A';
            const dnsRecordType = (DDG.DNSRecordType as any)[recordType];
            if (!dnsRecordType) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: `Invalid DNS record type: ${recordType}. Valid types: A, AAAA, CNAME, MX, NS, PTR, SOA, TXT`,
                data: { spiceType: args.spiceType, recordType }
              };
            }
            results = await DDG.dns(args.query, dnsRecordType);
            break;
            
          case 'time':
            const timeLocation = args.location || args.query;
            if (!timeLocation) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'Location or query required for time lookup',
                data: { spiceType: args.spiceType }
              };
            }
            results = await DDG.time(timeLocation);
            break;
            
          case 'thesaurus':
            if (!args.query) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'Word (query) required for thesaurus lookup',
                data: { spiceType: args.spiceType }
              };
            }
            results = await DDG.thesaurus(args.query);
            break;
            
          case 'expandUrl':
            if (!args.url) {
              return {
                success: false,
                tool: 'ddg_spice',
                error: 'URL required for URL expansion',
                data: { spiceType: args.spiceType }
              };
            }
            results = await DDG.expandUrl(args.url);
            break;
            
          default:
            return {
              success: false,
              tool: 'ddg_spice',
              error: `Unsupported spice type: ${args.spiceType}. Supported types: stocks, currency, weather, dictionary, dns, time, thesaurus, expandUrl`,
              data: { spiceType: args.spiceType }
            };
        }
      } catch (ddgError) {
        console.error('DDG Spice API Error:', ddgError);
        const errorMessage = ddgError instanceof Error ? ddgError.message : 'DDG Spice API call failed';
        
        // Handle specific known errors
        if (errorMessage.includes('RegistrationError') || errorMessage.includes('registration')) {
          return {
            success: false,
            tool: 'ddg_spice',
            error: `API Registration Required: ${errorMessage}`,
            data: { spiceType: args.spiceType, registrationRequired: true }
          };
        }

        return {
          success: false,
          tool: 'ddg_spice',
          error: `DDG Spice API Error: ${errorMessage}`,
          data: { spiceType: args.spiceType, apiError: errorMessage }
        };
      }

      // Validate results
      if (results === null || results === undefined) {
        return {
          success: false,
          tool: 'ddg_spice',
          error: 'DDG Spice API returned no data',
          data: { spiceType: args.spiceType }
        };
      }

      const duration = Date.now() - startTime;

      return {
        success: true,
        tool: 'ddg_spice',
        duration,
        data: {
          spiceType: args.spiceType,
          results
        }
      };

    } catch (error) {
      console.error('DDG Spice execution error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown execution error';
      
      return {
        success: false,
        tool: 'ddg_spice',
        error: `Execution error: ${errorMessage}`,
        data: { 
          spiceType: args.spiceType,
          executionError: errorMessage
        }
      };
    }
  }
}
