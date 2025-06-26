# RedQuanta MCP

**Enterprise-Grade Penetration Testing Orchestration Platform**

## Overview

RedQuanta MCP is a production-ready security testing platform that provides secure, orchestrated access to penetration testing tools through the Model Context Protocol (MCP). It enables AI assistants and security professionals to conduct comprehensive security assessments with enterprise-grade safety and compliance controls.

## Key Features

- **Security First**: Jailed execution, command validation, audit logging
- **Enterprise Ready**: REST API, MCP protocol, scalable architecture  
- **Comprehensive Toolset**: Network, web, and intelligence testing tools
- **Professional Reporting**: SARIF format, executive summaries, compliance mapping

## Quick Start

### Installation
````bash
npm install -g redquanta-mcp
redquanta-mcp --version
```

### Basic Usage
````bash
# Network scan
redquanta-mcp nmap_scan 192.168.1.1 --ports 80,443,22

# Web vulnerability scan  
redquanta-mcp nikto_scan https://example.com

# Automated workflow
redquanta-mcp workflow_enum 192.168.1.0/24 --scope basic
```

## Getting Started Paths

| User Type | Recommended Path |
|-----------|------------------|
| **Beginners** | [Beginner's Guide](USAGE_beginner.md) ? [Basic Examples](examples/basic-scanning.md) |
| **Security Professionals** | [Quick Start](getting-started/quick-start.md) ? [Tool Overview](tools/overview.md) |
| **Developers** | [API Documentation](api/REST_API.md) ? [Plugin Development](development/plugin-development.md) |
| **Enterprise** | [Enterprise Setup](tutorials/enterprise-setup.md) ? [Deployment Guide](deployment/docker.md) |

## Next Steps

- [Getting Started](getting-started/quick-start.md) - Quick setup and first scan
- [Tool Overview](tools/overview.md) - Available security testing tools
- [API Documentation](api/REST_API.md) - REST API and integration guides
- [Security Model](security/model.md) - Safety and compliance features
