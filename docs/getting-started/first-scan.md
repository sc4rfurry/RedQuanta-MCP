# Your First Security Scan

Learn how to perform your first security assessment with RedQuanta MCP.

## Prerequisites

!!! warning "Legal Authorization Required"
    Only scan systems you own or have explicit written permission to test.

## Quick Start

### 1. Start the Server
```bash
npm run start:prod
```

### 2. Run Your First Scan
```bash
# Basic network discovery
node dist/cli.js enum 192.168.1.0/24 --scope network --depth light

# Web application scan
node dist/cli.js scan httpbin.org --services http
```

### 3. Review Results
Results are saved in JSON and SARIF formats in the `reports/` directory.

## Understanding Output

### Network Scan Results
- **Open Ports**: Services accessible from external networks
- **Service Versions**: Software versions that may have vulnerabilities
- **OS Detection**: Operating system identification

### Web Scan Results
- **Directory Discovery**: Hidden files and directories
- **Vulnerability Findings**: Security issues found
- **Configuration Issues**: Misconfigurations detected

## Next Steps

- [Configuration Guide](configuration.md)
- [Basic Scanning Examples](../examples/basic-scanning.md)
- [Security Best Practices](../security/legal-ethics.md) 