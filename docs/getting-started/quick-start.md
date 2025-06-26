# Quick Start Guide

Get RedQuanta MCP up and running in under 5 minutes with this comprehensive quick start guide.

## Prerequisites

!!! info "System Requirements"
    
    === "Minimum Requirements"
        
        - **OS**: Windows 10+, Linux (Ubuntu 18.04+), macOS 10.14+
        - **CPU**: 2 cores, 2.0 GHz
        - **RAM**: 4 GB
        - **Storage**: 2 GB free space
        - **Network**: Internet connection for tool downloads
        
    === "Recommended Requirements"
        
        - **OS**: Windows 11, Linux (Ubuntu 22.04+), macOS 12+
        - **CPU**: 4+ cores, 3.0 GHz
        - **RAM**: 8+ GB
        - **Storage**: 10+ GB free space (for logs and reports)
        - **Network**: High-bandwidth connection for large scans

### Required Software

=== "Windows"

    ```powershell
    # Install Node.js 20 LTS
    winget install OpenJS.NodeJS.LTS
    
    # Install Git
    winget install Git.Git
    
    # Install Docker Desktop (optional)
    winget install Docker.DockerDesktop
    
    # Verify installations
    node --version  # Should be v20.x.x
    npm --version   # Should be 10.x.x
    git --version   # Should be 2.x.x
    ```

=== "Linux (Ubuntu/Debian)"

    ```bash
    # Update package list
    sudo apt update
    
    # Install Node.js 20 LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    
    # Install Git
    sudo apt install git
    
    # Install Docker (optional)
    sudo apt install docker.io docker-compose
    sudo usermod -aG docker $USER
    
    # Verify installations
    node --version  # Should be v20.x.x
    npm --version   # Should be 10.x.x
    git --version   # Should be 2.x.x
    ```

=== "macOS"

    ```bash
    # Install Homebrew (if not installed)
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Install Node.js 20 LTS
    brew install node@20
    
    # Install Git
    brew install git
    
    # Install Docker Desktop (optional)
    brew install --cask docker
    
    # Verify installations
    node --version  # Should be v20.x.x
    npm --version   # Should be 10.x.x
    git --version   # Should be 2.x.x
    ```

---

## Installation Methods

### Method 1: NPM Installation (Recommended)

=== "Development Installation"

    ```bash
    # Clone the repository
    git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
    cd RedQuanta-MCP
    
    # Install dependencies
    npm install
    
    # Build the project
    npm run build
    
    # Run tests to verify installation
    npm test
    
    # Start in development mode
    npm run start:dev
    ```

=== "Production Installation"

    ```bash
    # Clone and setup for production
    git clone --depth 1 --branch main https://github.com/sc4rfurry/RedQuanta-MCP.git
    cd RedQuanta-MCP
    
    # Install production dependencies only
    npm ci --only=production
    
    # Build optimized version
    npm run build:prod
    
    # Start in production mode
    npm run start:prod
    ```

### Method 2: Docker Installation

=== "Quick Docker Run"

    ```bash
    # Pull and run the latest image
    docker run -d \
      --name redquanta-mcp \
      -p 5891:5891 \
      -e LOG_LEVEL=info \
      redquanta/mcp:latest
    
    # Check container status
    docker ps
    
    # View logs
    docker logs redquanta-mcp
    ```

=== "Docker Compose"

    ```yaml
    # docker-compose.yml
    version: '3.8'
    
    services:
      redquanta-mcp:
        image: redquanta/mcp:latest
        container_name: redquanta-mcp
        ports:
          - "5891:5891"
        environment:
          - NODE_ENV=production
          - LOG_LEVEL=info
          - JAIL_ROOT=/app/vol
        volumes:
          - ./config:/app/config:ro
          - ./logs:/app/logs
          - ./reports:/app/reports
        restart: unless-stopped
        healthcheck:
          test: ["CMD", "curl", "-f", "http://localhost:5891/health"]
          interval: 30s
          timeout: 10s
          retries: 3
          start_period: 40s
    
    volumes:
      logs:
      reports:
    ```
    
    ```bash
    # Start with Docker Compose
    docker-compose up -d
    
    # Check status
    docker-compose ps
    
    # View logs
    docker-compose logs -f
    ```

### Method 3: Pre-built Binaries

=== "Linux"

    ```bash
    # Download the latest release
    curl -L https://github.com/sc4rfurry/RedQuanta-MCP/releases/latest/download/redquanta-mcp-linux-x64 \
         -o redquanta-mcp
    
    # Make executable
    chmod +x redquanta-mcp
    
    # Run directly
    ./redquanta-mcp --help
    ```

=== "Windows"

    ```powershell
    # Download the latest release
    Invoke-WebRequest -Uri "https://github.com/sc4rfurry/RedQuanta-MCP/releases/latest/download/redquanta-mcp-win-x64.exe" `
                      -OutFile "redquanta-mcp.exe"
    
    # Run directly
    .\redquanta-mcp.exe --help
    ```

=== "macOS"

    ```bash
    # Download the latest release
    curl -L https://github.com/sc4rfurry/RedQuanta-MCP/releases/latest/download/redquanta-mcp-macos-x64 \
         -o redquanta-mcp
    
    # Make executable
    chmod +x redquanta-mcp
    
    # Run directly (may require security approval)
    ./redquanta-mcp --help
    ```

---

## Initial Configuration

### 1. Environment Setup

Create a `.env` file in the project root:

```bash
# .env
NODE_ENV=development
LOG_LEVEL=info
MCP_MODE=rest
PORT=5891
HOST=localhost
JAIL_ROOT=/opt/redquanta/vol
DANGEROUS_MODE=false
CACHE_ENABLED=true
CACHE_TTL=3600
WEB_SEARCH_ENABLED=true
```

### 2. Security Configuration

The default configuration is secure by default. For custom setups:

=== "Security Policies"

    ```json
    // config/allowedCommands.json
    {
      "nmap": {
        "binary": "nmap",
        "allowedArgs": ["-A", "-T4", "-sV", "-sC", "--reason"],
        "dangerousArgs": ["--script", "vuln"],
        "maxTargets": 1000,
        "timeout": 300
      }
    }
    ```

=== "Path Protection"

    ```json
    // config/allowedPaths.json
    {
      "jailRoot": "/opt/redquanta/vol",
      "allowedDirs": ["tmp", "reports", "config", "logs"],
      "allowedExtensions": [".txt", ".json", ".xml", ".csv"],
      "maxFileSize": 104857600,
      "readOnly": true
    }
    ```

### 3. Tool Verification

Run the doctor command to verify tool availability:

```bash
# Check system requirements and tool availability
node dist/cli.js doctor

# Expected output:
# 🏥 RedQuanta MCP System Check:
# ✅ Node.js v20.11.0 (OK)
# ✅ Platform: win32 x64
# ✅ Config: allowedCommands.json found
# ✅ Config: allowedPaths.json found
# 💡 Run `redquanta-mcp server` to perform complete tool detection
```

---

## Verification & Testing

### 1. Health Check

=== "CLI Health Check"

    ```bash
    # Start the server in background
    npm run start:prod &
    
    # Wait for startup
    sleep 5
    
    # Check health endpoint
    curl http://localhost:5891/health
    
    # Expected response:
    # {
    #   "status": "healthy",
    #   "version": "0.3.0",
    #   "mode": "rest",
    #   "platform": "linux",
    #   "uptime": 5.234,
    #   "timestamp": "2025-06-25T10:00:00.000Z"
    # }
    ```

=== "Interactive Test"

    ```bash
    # List available tools
    node dist/cli.js tools
    
    # Expected output:
    # 🛠️  Available RedQuanta MCP Tools:
    # 
    #   nmap_scan            - Network discovery and port scanning
    #   masscan_scan         - High-speed port scanning
    #   ffuf_fuzz           - Web fuzzing and directory discovery
    #   nikto_scan          - Web vulnerability scanning
    #   workflow_enum       - Automated enumeration workflow
    #   workflow_scan       - Automated vulnerability scanning
    ```

### 2. First Security Scan

=== "Network Discovery"

    ```bash
    # Safe network discovery (no actual scanning)
    node dist/cli.js enum 127.0.0.1 --scope network --depth light
    
    # Expected output includes:
    # 🎯 Starting enumeration workflow...
    # Target: 127.0.0.1
    # Scope: network
    # Depth: light
    # ✅ Enumeration workflow completed successfully!
    ```

=== "Web Application Test"

    ```bash
    # Safe web application assessment
    node dist/cli.js scan httpbin.org --services http --coaching beginner
    
    # Expected output includes:
    # 🔍 Starting vulnerability scanning...
    # Target: httpbin.org
    # Services: http
    # ✅ Vulnerability scanning workflow completed successfully!
    ```

### 3. API Testing

=== "REST API Test"

    ```bash
    # Test tool listing endpoint
    curl -s http://localhost:5891/tools | jq
    
    # Test tool execution (safe example)
    curl -X POST http://localhost:5891/tools/web_search \
      -H "Content-Type: application/json" \
      -d '{
        "query": "security testing methodology",
        "maxResults": 5,
        "safeSearch": true
      }' | jq
    ```

=== "MCP Protocol Test"

    ```bash
    # Install MCP client for testing
    npm install -g @modelcontextprotocol/client-cli
    
    # Test MCP connection
    mcp-client --transport stdio -- node dist/server.js
    ```

---

## Next Steps

### Immediate Actions

1. **[Configure Your Environment](configuration.md)** - Customize settings for your needs
2. **[Run Your First Scan](first-scan.md)** - Perform a real security assessment
3. **[Explore the Tools](../tools/overview.md)** - Learn about available security tools

### Learning Path

=== "Beginners"

    1. [Security Best Practices](../security/legal-ethics.md)
    2. [Basic Scanning Examples](../examples/basic-scanning.md)
    3. [Understanding Results](../user-guide/understanding-results.md)
    4. [Common Workflows](../examples/common-workflows.md)

=== "Advanced Users"

    1. [Advanced Workflows](../examples/advanced-workflows.md)
    2. [Custom Plugin Development](../development/plugin-development.md)
    3. [Enterprise Deployment](../tutorials/enterprise-setup.md)
    4. [CI/CD Integration](../tutorials/cicd-integration.md)

### Troubleshooting

If you encounter issues:

- 📚 Check the [Troubleshooting Guide](../deployment/troubleshooting.md)
- 🐛 Search [GitHub Issues](https://github.com/sc4rfurry/RedQuanta-MCP/issues)
- 💬 Ask in [Discussions](https://github.com/sc4rfurry/RedQuanta-MCP/discussions)
- 📧 Email: support@redquanta.dev

---

!!! success "Installation Complete!"
    
    **Congratulations!** RedQuanta MCP is now installed and ready for use.
    
    - ✅ Server is running on http://localhost:5891
    - ✅ CLI tools are available via `node dist/cli.js`
    - ✅ API documentation at http://localhost:5891/docs
    - ✅ Health monitoring at http://localhost:5891/health
    
    **Next:** [Run your first security scan](first-scan.md) → 