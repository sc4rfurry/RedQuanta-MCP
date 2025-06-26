# 🎯 Claude Desktop App Integration Guide for RedQuanta MCP

This comprehensive guide will help you integrate RedQuanta MCP with Claude Desktop App for intelligent penetration testing workflows through natural language interactions.

## 📋 Table of Contents

- [Prerequisites](#-prerequisites)
- [Quick Setup](#-quick-setup)
- [Configuration](#-configuration)
- [Verification](#-verification)
- [Usage Examples](#-usage-examples)
- [Advanced Configuration](#-advanced-configuration)
- [Troubleshooting](#-troubleshooting)
- [Best Practices](#-best-practices)
- [Available Tools](#-available-tools)

## 🎯 Prerequisites

### Required Software
- **Claude Desktop App** - Download from [Anthropic](https://claude.ai/download)
- **Node.js 20 LTS** - [Download here](https://nodejs.org/en/download/)
- **Git** - For cloning the repository

### System Requirements
- **Windows**: 10 (1903+) or 11
- **macOS**: 10.15+ 
- **Linux**: Ubuntu 18.04+, CentOS 7+
- **RAM**: 2GB+ available
- **Storage**: 500MB+ available

## 🚀 Quick Setup

### Step 1: Install RedQuanta MCP

```bash
# Clone the repository
git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
cd RedQuanta-MCP

# Install dependencies
npm install

# Build the project
npm run build

# Create jail directory
mkdir -p vol
```

### Step 2: Locate Claude Desktop Configuration

The configuration file location varies by operating system:

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/claude_desktop_config.json`

### Step 3: Configure Claude Desktop

Add RedQuanta MCP to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "redquanta-mcp": {
      "command": "node",
      "args": ["./dist/server.js"],
      "cwd": "/path/to/RedQuanta-MCP",
      "env": {
        "NODE_ENV": "production",
        "MCP_MODE": "stdio",
        "MCP_LOG_LEVEL": "info",
        "LOG_LEVEL": "info",
        "WEB_SEARCH_ENABLED": "true",
        "CACHE_ENABLED": "true",
        "CACHE_TTL": "600",
        "DANGEROUS_MODE": "false",
        "DOCKER_ENABLED": "true",
        "JAIL_ROOT": "/path/to/RedQuanta-MCP/vol",
        "REAL_EXECUTION": "true",
        "SIMULATION_MODE": "false",
        "NODE_OPTIONS": "--max-old-space-size=2048",
        "UV_THREADPOOL_SIZE": "4"
      }
    }
  }
}
```

**⚠️ Important**: Replace `/path/to/RedQuanta-MCP` with your actual project path.

### Step 4: Restart Claude Desktop

1. **Close Claude Desktop** completely
2. **Wait 5 seconds** for processes to terminate
3. **Start Claude Desktop** again
4. **Wait for initialization** (look for MCP status indicators)

## ⚙️ Configuration

### Windows Configuration Example

```json
{
  "mcpServers": {
    "redquanta-mcp": {
      "command": "node",
      "args": ["D:\\Projects\\RedQuanta-MCP\\dist\\server.js"],
      "cwd": "D:\\Projects\\RedQuanta-MCP",
      "env": {
        "NODE_ENV": "production",
        "MCP_MODE": "stdio",
        "MCP_LOG_LEVEL": "info",
        "LOG_LEVEL": "info",
        "WEB_SEARCH_ENABLED": "true",
        "CACHE_ENABLED": "true",
        "CACHE_TTL": "600",
        "DANGEROUS_MODE": "false",
        "DOCKER_ENABLED": "true",
        "JAIL_ROOT": "D:\\Projects\\RedQuanta-MCP\\vol",
        "REAL_EXECUTION": "true",
        "SIMULATION_MODE": "false",
        "NODE_OPTIONS": "--max-old-space-size=2048",
        "UV_THREADPOOL_SIZE": "4"
      }
    }
  }
}
```

### macOS/Linux Configuration Example

```json
{
  "mcpServers": {
    "redquanta-mcp": {
      "command": "node",
      "args": ["/Users/username/RedQuanta-MCP/dist/server.js"],
      "cwd": "/Users/username/RedQuanta-MCP",
      "env": {
        "NODE_ENV": "production",
        "MCP_MODE": "stdio",
        "MCP_LOG_LEVEL": "info",
        "LOG_LEVEL": "info",
        "WEB_SEARCH_ENABLED": "true",
        "CACHE_ENABLED": "true",
        "CACHE_TTL": "600",
        "DANGEROUS_MODE": "false",
        "DOCKER_ENABLED": "true",
        "JAIL_ROOT": "/Users/username/RedQuanta-MCP/vol",
        "REAL_EXECUTION": "true",
        "SIMULATION_MODE": "false",
        "NODE_OPTIONS": "--max-old-space-size=2048",
        "UV_THREADPOOL_SIZE": "4"
      }
    }
  }
}
```

### Environment Variables Explained

| Variable | Description | Default | Values |
|----------|-------------|---------|---------|
| `NODE_ENV` | Environment mode | `production` | `development`, `production` |
| `MCP_MODE` | Communication mode | `stdio` | `stdio`, `rest` |
| `MCP_LOG_LEVEL` | MCP logging level | `info` | `error`, `warn`, `info`, `debug` |
| `LOG_LEVEL` | General logging level | `info` | `error`, `warn`, `info`, `debug` |
| `WEB_SEARCH_ENABLED` | Enable web search tools | `true` | `true`, `false` |
| `CACHE_ENABLED` | Enable result caching | `true` | `true`, `false` |
| `CACHE_TTL` | Cache time-to-live (seconds) | `600` | Any number |
| `DANGEROUS_MODE` | Enable dangerous operations | `false` | `true`, `false` |
| `DOCKER_ENABLED` | Enable Docker fallback | `true` | `true`, `false` |
| `JAIL_ROOT` | Filesystem jail directory | `./vol` | Any valid path |
| `REAL_EXECUTION` | Execute real commands | `true` | `true`, `false` |
| `SIMULATION_MODE` | Enable simulation mode | `false` | `true`, `false` |

## ✅ Verification

### Check MCP Server Status

1. **Open Claude Desktop**
2. **Start a new conversation**
3. **Type**: "Can you list the available security tools?"
4. **Expected Response**: Claude should mention RedQuanta MCP tools

### Test Basic Functionality

```
User: "What security tools are available through RedQuanta MCP?"

Expected Response: Claude should list tools like:
- nmap_scan (Network discovery and port scanning)
- ffuf_fuzz (Web directory fuzzing)
- nikto_scan (Web vulnerability scanning)
- workflow_enum (Automated enumeration)
- And more...
```

### Verify Tool Execution

```
User: "Can you help me scan 8.8.8.8 for open ports using nmap?"

Expected Response: Claude should:
1. Acknowledge the request
2. Execute the nmap_scan tool
3. Return structured results
4. Provide security recommendations
```

## 🎭 Usage Examples

### Example 1: Network Discovery

```
User: Hi! I need to scan my home network 192.168.1.0/24 to see what devices are connected. Can you help me discover live hosts and their open ports?

Claude Response: I'll help you discover devices on your home network using nmap. Let me scan the 192.168.1.0/24 range to find live hosts and their open ports.

[Tool execution: nmap_scan with target 192.168.1.0/24]

Results: I found 5 live hosts on your network:
1. 192.168.1.1 (Router) - Ports: 80/tcp, 443/tcp, 22/tcp
2. 192.168.1.10 (Computer) - Ports: 135/tcp, 445/tcp, 3389/tcp
3. 192.168.1.20 (Printer) - Ports: 80/tcp, 515/tcp, 9100/tcp
[Additional results...]

Security Recommendations:
- Review open RDP (3389) on 192.168.1.10
- Ensure printer web interface is secured
- Consider disabling unused services
```

### Example 2: Web Application Security Assessment

```
User: I need to test the security of my website example.com. Can you perform a comprehensive security scan?

Claude Response: I'll perform a comprehensive web security assessment of example.com. This will include directory enumeration, vulnerability scanning, and SSL analysis.

[Tool execution: workflow_scan with target example.com]

Assessment Results:
1. Directory Enumeration: Found /admin, /backup, /api endpoints
2. Vulnerability Scan: Detected outdated software versions
3. SSL Analysis: Certificate expires in 30 days
4. Security Headers: Missing CSP and HSTS headers

Recommendations:
- Secure or remove exposed administrative interfaces
- Update server software to latest versions
- Renew SSL certificate
- Implement security headers
```

### Example 3: Incident Response

```
User: I suspect someone is trying to brute force our SSH server at 10.0.0.50. Can you help me investigate?

Claude Response: I'll help investigate potential brute force activity on your SSH server. Let me gather information about the target system and check for security issues.

[Tool execution: nmap_scan with scripts for SSH analysis]

Investigation Results:
- SSH service confirmed on port 22
- Server allows password authentication
- No rate limiting detected
- Multiple failed authentication logs (if accessible)

Immediate Actions Recommended:
1. Enable SSH key-only authentication
2. Implement fail2ban or similar protection
3. Change default SSH port if possible
4. Enable SSH login logging and monitoring
```

## 🔧 Advanced Configuration

### Enabling Dangerous Operations

For advanced penetration testing (password cracking, SQL injection testing):

```json
{
  "env": {
    "DANGEROUS_MODE": "true"
  }
}
```

**⚠️ Warning**: Only enable dangerous mode in authorized testing environments with proper legal authorization.

### Custom Jail Root Directory

To use a custom filesystem jail location:

```json
{
  "env": {
    "JAIL_ROOT": "C:/PentestJail"
  }
}
```

### Performance Tuning

For large-scale assessments:

```json
{
  "env": {
    "NODE_OPTIONS": "--max-old-space-size=4096",
    "UV_THREADPOOL_SIZE": "8",
    "CACHE_TTL": "1800"
  }
}
```

## 🔍 Troubleshooting

### Common Issues

#### 1. Claude Desktop Can't Find MCP Server

**Symptoms**: No RedQuanta tools available, MCP server not listed

**Solutions**:
```bash
# Verify Node.js installation
node --version  # Should be 20.x or higher

# Check if server starts manually
cd /path/to/RedQuanta-MCP
node dist/server.js --mode stdio

# Verify configuration file syntax
cat ~/.config/claude/claude_desktop_config.json | jq .
```

#### 2. Tools Not Executing

**Symptoms**: Tools listed but execution fails

**Solutions**:
```bash
# Check jail directory permissions
ls -la /path/to/RedQuanta-MCP/vol

# Verify environment variables
env | grep -E "(JAIL_ROOT|DANGEROUS_MODE)"

# Test manual tool execution
node dist/cli.js nmap_scan 8.8.8.8
```

## 🛠️ Available Tools

### 🌐 Network Security Tools

| Tool | Description | Danger Level |
|------|-------------|--------------|
| `nmap_scan` | Network discovery and port scanning | Safe |
| `masscan_scan` | High-speed port scanning | Safe |
| `workflow_enum` | Automated network enumeration | Safe |

### 🌐 Web Security Tools

| Tool | Description | Danger Level |
|------|-------------|--------------|
| `ffuf_fuzz` | Fast web directory/file fuzzing | Safe |
| `nikto_scan` | Web vulnerability scanning | Safe |
| `workflow_scan` | Comprehensive web security assessment | Safe |

### 🔐 Exploitation Tools (Dangerous Mode)

| Tool | Description | Danger Level |
|------|-------------|--------------|
| `hydra_bruteforce` | Network service brute forcing | Dangerous |

### 🤖 Automation Tools

| Tool | Description | Danger Level |
|------|-------------|--------------|
| `workflow_report` | Professional report generation | Safe |
| `help_system` | Interactive documentation | Safe |

### 💾 System Tools

| Tool | Description | Danger Level |
|------|-------------|--------------|
| `filesystem_ops` | Secure file management | Safe |
| `ddg_search` | Intelligence gathering via web search | Safe |

## 🚀 Next Steps

### Getting Started
1. **Complete the setup** following this guide
2. **Test basic functionality** with simple scans
3. **Explore different tool combinations**
4. **Practice with authorized targets only**

### Advanced Usage
1. **Enable dangerous mode** for comprehensive testing
2. **Develop custom workflows** for specific scenarios
3. **Integrate with CI/CD** pipelines for automated security
4. **Create custom plugins** for specialized tools

---

**🎯 Ready to start intelligent security testing with Claude Desktop!**

Remember: Always ensure you have proper authorization before testing any systems. RedQuanta MCP is designed for authorized security assessments only.

**Legal Notice**: This tool is for authorized security testing only. Users are responsible for compliance with applicable laws and regulations. 