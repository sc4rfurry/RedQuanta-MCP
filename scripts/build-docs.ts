#!/usr/bin/env node
/**
 * Documentation Builder for RedQuanta MCP
 * Generates enhanced API documentation with custom styling and comprehensive content
 */

import { writeFileSync, readFileSync, mkdirSync } from 'fs';
import { join } from 'path';

function generateEnhancedRedocs(): void {
  const customCSS = `
    /* RedQuanta MCP Custom Styling */
    :root {
      --redquanta-primary: #e74c3c;
      --redquanta-secondary: #3498db;
      --redquanta-accent: #27ae60;
      --redquanta-dark: #2c3e50;
      --redquanta-light: #ecf0f1;
    }

    /* Header Customization */
    .api-logo {
      background: linear-gradient(135deg, var(--redquanta-primary), var(--redquanta-secondary));
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      font-weight: bold;
      font-size: 1.5em;
    }

    /* Navigation Enhancements */
    .menu-content {
      background: linear-gradient(145deg, #f8f9fa, #e9ecef) !important;
      border-right: 3px solid var(--redquanta-primary);
    }

    .menu-item-title {
      color: var(--redquanta-dark) !important;
      font-weight: 600;
    }

    .menu-item-title:hover {
      color: var(--redquanta-primary) !important;
      background: rgba(231, 76, 60, 0.1);
      border-radius: 4px;
      padding: 4px 8px;
      margin: -4px -8px;
      transition: all 0.3s ease;
    }

    /* Method Badges */
    .http-verb.get { 
      background: linear-gradient(135deg, #27ae60, #2ecc71) !important;
      box-shadow: 0 2px 4px rgba(39, 174, 96, 0.3);
    }
    .http-verb.post { 
      background: linear-gradient(135deg, #3498db, #5dade2) !important;
      box-shadow: 0 2px 4px rgba(52, 152, 219, 0.3);
    }
    .http-verb.put { 
      background: linear-gradient(135deg, #f39c12, #f7dc6f) !important;
      box-shadow: 0 2px 4px rgba(243, 156, 18, 0.3);
    }
    .http-verb.delete { 
      background: linear-gradient(135deg, #e74c3c, #ec7063) !important;
      box-shadow: 0 2px 4px rgba(231, 76, 60, 0.3);
    }

    /* Content Area Enhancements */
    .redoc-content {
      background: linear-gradient(145deg, #ffffff, #f8f9fa);
    }

    /* Schema Improvements */
    .schema-type {
      background: var(--redquanta-accent) !important;
      color: white !important;
      padding: 2px 6px;
      border-radius: 3px;
      font-weight: 500;
    }

    /* Security Indicators */
    .security-requirement {
      background: linear-gradient(135deg, #e74c3c, #c0392b);
      color: white;
      padding: 8px 12px;
      border-radius: 6px;
      margin: 10px 0;
      box-shadow: 0 2px 4px rgba(231, 76, 60, 0.3);
    }

    /* Code Samples */
    .redoc-json {
      background: var(--redquanta-dark) !important;
      border-left: 4px solid var(--redquanta-primary);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    }

    /* Response Codes */
    .response-code-200 { border-left: 4px solid #27ae60; }
    .response-code-400 { border-left: 4px solid #f39c12; }
    .response-code-401 { border-left: 4px solid #e67e22; }
    .response-code-404 { border-left: 4px solid #e74c3c; }
    .response-code-500 { border-left: 4px solid #8e44ad; }

    /* Animation Enhancements */
    @keyframes pulseGlow {
      0% { box-shadow: 0 0 5px rgba(231, 76, 60, 0.5); }
      50% { box-shadow: 0 0 20px rgba(231, 76, 60, 0.8); }
      100% { box-shadow: 0 0 5px rgba(231, 76, 60, 0.5); }
    }

    .security-endpoint {
      animation: pulseGlow 3s infinite;
    }

    /* Custom Tags */
    .tag-security { 
      background: linear-gradient(135deg, #e74c3c, #c0392b) !important;
      color: white !important;
    }
    .tag-tools { 
      background: linear-gradient(135deg, #3498db, #2980b9) !important;
      color: white !important;
    }
    .tag-workflows { 
      background: linear-gradient(135deg, #9b59b6, #8e44ad) !important;
      color: white !important;
    }

    /* Responsive Enhancements */
    @media (max-width: 768px) {
      .menu-content {
        transform: translateX(-100%);
        transition: transform 0.3s ease;
      }
      .menu-content.open {
        transform: translateX(0);
      }
    }

    /* Print Styles */
    @media print {
      .menu-content { display: none; }
      .redoc-content { margin-left: 0 !important; }
    }
  `;

  const redocHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf8" />
    <title>🛡️ RedQuanta MCP API Documentation</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Enterprise-Grade Penetration Testing Orchestration Platform - Comprehensive API Documentation">
    <meta name="keywords" content="RedQuanta, MCP, API, penetration testing, security, cybersecurity, nmap, ffuf, nikto">
    <meta name="author" content="RedQuanta Security Team">
    
    <!-- Open Graph Meta Tags -->
    <meta property="og:title" content="RedQuanta MCP API Documentation">
    <meta property="og:description" content="Enterprise-Grade Security Orchestration Platform with 16+ Professional Tools">
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://github.com/sc4rfurry/RedQuanta-MCP">
    
    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="../assets/redquanta-logo.svg">
    
    <!-- Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    
    <style>
        body { 
            padding: 0; 
            margin: 0; 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(145deg, #f8f9fa, #e9ecef);
        }
        
        /* Loading Animation */
        .loading-container {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            transition: opacity 0.5s ease;
        }
        
        .loading-spinner {
            width: 60px;
            height: 60px;
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: #fff;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .loading-text {
            color: white;
            margin-top: 20px;
            font-size: 18px;
            font-weight: 500;
        }
        
        ${customCSS}
    </style>
    
    <!-- ReDoc -->
    <script src="https://cdn.redocly.com/redoc/v2.1.3/bundles/redoc.standalone.js"></script>
</head>
<body>
    <!-- Loading Screen -->
    <div id="loading" class="loading-container">
        <div style="text-align: center;">
            <div class="loading-spinner"></div>
            <div class="loading-text">Loading RedQuanta MCP API Documentation...</div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div id="redoc-container"></div>
    
    <!-- Custom Header -->
    <script>
        // Enhanced ReDoc options
        const redocOptions = {
            theme: {
                colors: {
                    primary: {
                        main: '#e74c3c'
                    },
                    secondary: {
                        main: '#3498db'
                    },
                    success: {
                        main: '#27ae60'
                    },
                    warning: {
                        main: '#f39c12'
                    },
                    error: {
                        main: '#e74c3c'
                    },
                    text: {
                        primary: '#2c3e50',
                        secondary: '#7f8c8d'
                    },
                    border: {
                        dark: '#bdc3c7',
                        light: '#ecf0f1'
                    }
                },
                typography: {
                    fontSize: '14px',
                    lineHeight: '1.6',
                    code: {
                        fontSize: '13px',
                        fontFamily: 'JetBrains Mono, Consolas, monospace'
                    },
                    headings: {
                        fontFamily: 'Inter, sans-serif',
                        fontWeight: '600'
                    }
                },
                sidebar: {
                    backgroundColor: '#f8f9fa',
                    textColor: '#2c3e50',
                    activeTextColor: '#e74c3c'
                },
                rightPanel: {
                    backgroundColor: '#2c3e50',
                    textColor: '#ecf0f1'
                }
            },
            scrollYOffset: 60,
            hideDownloadButton: false,
            disableSearch: false,
            expandResponses: '200,201',
            requiredPropsFirst: true,
            sortPropsAlphabetically: true,
            showExtensions: true,
            hideSchemaPattern: false,
            expandSingleSchemaField: true,
            menuToggle: true,
            nativeScrollbars: false,
            pathInMiddlePanel: true,
            untrustedSpec: false,
            hideHostname: false,
            hideLoading: false,
            customCSS: \`
                .api-info-wrapper {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px;
                    margin: -40px -40px 40px -40px;
                    border-radius: 0 0 20px 20px;
                }
                
                .api-info h1 {
                    color: white !important;
                    font-size: 2.5em;
                    margin-bottom: 10px;
                    text-shadow: 0 2px 4px rgba(0,0,0,0.3);
                }
                
                .api-info .api-info-description {
                    color: rgba(255,255,255,0.9) !important;
                    font-size: 1.1em;
                    line-height: 1.6;
                }
                
                .tag {
                    margin: 5px 0;
                    padding: 10px 15px;
                    border-radius: 8px;
                    background: white;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    transition: transform 0.2s ease;
                }
                
                .tag:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                }
                
                .operation-path {
                    font-family: 'JetBrains Mono', monospace !important;
                    background: rgba(231, 76, 60, 0.1);
                    padding: 4px 8px;
                    border-radius: 4px;
                    border-left: 3px solid #e74c3c;
                }
                
                .security-definitions {
                    background: linear-gradient(135deg, #e74c3c, #c0392b);
                    color: white;
                    padding: 20px;
                    border-radius: 10px;
                    margin: 20px 0;
                    box-shadow: 0 4px 12px rgba(231, 76, 60, 0.3);
                }
            \`
        };
        
        // Initialize ReDoc with enhanced options
        function initializeRedoc() {
            Redoc.init('./openapi.json', redocOptions, document.getElementById('redoc-container'), function(errors) {
                if (errors) {
                    console.error('ReDoc initialization errors:', errors);
                    document.getElementById('redoc-container').innerHTML = 
                        '<div style="padding: 40px; text-align: center; color: #e74c3c;">' +
                        '<h2>⚠️ Documentation Loading Error</h2>' +
                        '<p>Please ensure the OpenAPI specification is properly generated.</p>' +
                        '<p>Run: <code>npm run docs:api</code></p>' +
                        '</div>';
                }
                
                // Hide loading screen
                setTimeout(() => {
                    const loading = document.getElementById('loading');
                    if (loading) {
                        loading.style.opacity = '0';
                        setTimeout(() => loading.remove(), 500);
                    }
                }, 1000);
                
                // Add custom enhancements
                enhanceDocumentation();
            });
        }
        
        function enhanceDocumentation() {
            // Add security indicators
            setTimeout(() => {
                const dangerousEndpoints = document.querySelectorAll('[data-section-id*="dangerous"], [data-section-id*="exploit"], [data-section-id*="attack"]');
                dangerousEndpoints.forEach(endpoint => {
                    endpoint.classList.add('security-endpoint');
                });
                
                // Add tool category indicators
                const networkTools = document.querySelectorAll('[data-section-id*="nmap"], [data-section-id*="masscan"]');
                networkTools.forEach(tool => tool.classList.add('network-tool'));
                
                const webTools = document.querySelectorAll('[data-section-id*="ffuf"], [data-section-id*="nikto"]');
                webTools.forEach(tool => tool.classList.add('web-tool'));
                
                // Add interactive features
                addInteractiveFeatures();
            }, 2000);
        }
        
        function addInteractiveFeatures() {
            // Add copy buttons to code samples
            const codeBlocks = document.querySelectorAll('pre code');
            codeBlocks.forEach(block => {
                const wrapper = block.parentElement;
                const copyBtn = document.createElement('button');
                copyBtn.innerHTML = '📋 Copy';
                copyBtn.style.cssText = 'position: absolute; top: 10px; right: 10px; background: #3498db; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; font-size: 12px;';
                wrapper.style.position = 'relative';
                wrapper.appendChild(copyBtn);
                
                copyBtn.addEventListener('click', () => {
                    navigator.clipboard.writeText(block.textContent);
                    copyBtn.innerHTML = '✅ Copied!';
                    setTimeout(() => copyBtn.innerHTML = '📋 Copy', 2000);
                });
            });
            
            // Add progress indicator for long content
            const progressBar = document.createElement('div');
            progressBar.style.cssText = 'position: fixed; top: 0; left: 0; height: 3px; background: linear-gradient(90deg, #e74c3c, #3498db); z-index: 1000; transition: width 0.3s ease;';
            document.body.appendChild(progressBar);
            
            window.addEventListener('scroll', () => {
                const scrollPercent = (window.scrollY / (document.documentElement.scrollHeight - window.innerHeight)) * 100;
                progressBar.style.width = scrollPercent + '%';
            });
        }
        
        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeRedoc);
        } else {
            initializeRedoc();
        }
        
        // Add keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 'k':
                        e.preventDefault();
                        const searchInput = document.querySelector('input[placeholder*="Search"]');
                        if (searchInput) searchInput.focus();
                        break;
                    case '/':
                        e.preventDefault();
                        const searchInput2 = document.querySelector('input[placeholder*="Search"]');
                        if (searchInput2) searchInput2.focus();
                        break;
                }
            }
        });
    </script>
    
    <!-- Analytics and Error Tracking -->
    <script>
        window.addEventListener('error', (e) => {
            console.error('Documentation Error:', e.error);
        });
        
        // Performance monitoring
        window.addEventListener('load', () => {
            const loadTime = performance.now();
            console.log(\`Documentation loaded in \${Math.round(loadTime)}ms\`);
        });
    </script>
</body>
</html>`;

  // Ensure output directory exists
  const outputDir = join(process.cwd(), 'docs', 'api');
  mkdirSync(outputDir, { recursive: true });

  // Write enhanced HTML
  const outputPath = join(outputDir, 'index.html');
  writeFileSync(outputPath, redocHTML);

  console.log('✅ Enhanced ReDoc documentation generated');
  console.log(`📄 File: ${outputPath}`);
  console.log('🎨 Custom styling and enhancements applied');
}

// Update comprehensive documentation files
function updateDocumentationFiles(): void {
  const docsDir = join(process.cwd(), 'docs');
  
  // Update main README
  const mainReadme = `# 📚 RedQuanta MCP Documentation

## 🎯 Quick Navigation

### 📖 [API Documentation](./api/index.html)
Interactive API documentation with live examples and comprehensive schemas.

### 🔧 [Installation Guide](./installation/)
Step-by-step setup instructions for all supported platforms.

### 🛡️ [Security Model](./security/)
Comprehensive security architecture and safety guidelines.

### 💡 [Usage Examples](./examples/)
Real-world usage scenarios and best practices.

### 🔬 [Development Guide](./development/)
Information for contributors and plugin developers.

## 📊 Documentation Stats

- **16+ Security Tools** fully documented
- **100+ API Endpoints** with examples
- **Multi-platform Support** (Windows, Linux, macOS)
- **SARIF 2.1.0 Compliant** output format
- **Enterprise-Grade** security controls

## 🚀 Getting Started

1. **[Quick Setup](./SETUP_WINDOWS.md)** - Get running in 5 minutes
2. **[API Overview](./api/REST_API.md)** - Understand the endpoints
3. **[First Security Scan](./usage/BEGINNER_GUIDE.md)** - Run your first assessment
4. **[Advanced Workflows](./examples/LLM_USAGE_GUIDE.md)** - Automate with AI

## 🔍 Find What You Need

| Topic | Documentation |
|-------|---------------|
| Installation | [Setup Guide](./SETUP_WINDOWS.md) |
| API Reference | [Interactive Docs](./api/index.html) |
| Security | [Security Model](./security/SECURITY_MODEL.md) |
| Examples | [Usage Guide](./usage/BEGINNER_GUIDE.md) |
| Development | [Plugin Development](./development/PLUGIN_DEVELOPMENT.md) |

## 📈 Recent Updates

- **Enhanced API Documentation** with custom styling
- **Comprehensive OpenAPI 3.0.3** specification
- **Custom SVG Assets** for professional appearance
- **Interactive Examples** with copy-to-clipboard
- **Performance Optimizations** for faster loading

---

**Need Help?** Check our [GitHub Issues](https://github.com/sc4rfurry/RedQuanta-MCP/issues) or [Discussion Forum](https://github.com/sc4rfurry/RedQuanta-MCP/discussions).
`;

  writeFileSync(join(docsDir, 'README.md'), mainReadme);

  console.log('✅ Documentation files updated');
  console.log('📁 Main documentation index created');
}

// Main execution
function buildDocumentation(): void {
  console.log('🔨 Building comprehensive documentation...');
  
  generateEnhancedRedocs();
  updateDocumentationFiles();
  
  console.log('✅ Documentation build completed successfully');
  console.log('🌐 Open docs/api/index.html to view enhanced API documentation');
}

buildDocumentation();
