# Installation Guide

Complete installation instructions for RedQuanta MCP across all supported platforms.

## Quick Installation

=== "NPM (Recommended)"
    ```bash
    git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
    cd RedQuanta-MCP
    npm install
    npm run build
    ```

=== "Docker"
    ```bash
    docker run -p 5891:5891 redquanta/mcp:latest
    ```

=== "Binary"
    Download from [GitHub Releases](https://github.com/sc4rfurry/RedQuanta-MCP/releases)

## Platform-Specific Setup

### Windows
```powershell
# Install Node.js 20 LTS
winget install OpenJS.NodeJS.LTS

# Clone and setup
git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
cd RedQuanta-MCP
npm install
npm run build
```

### Linux
```bash
# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Clone and setup
git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
cd RedQuanta-MCP
npm install
npm run build
```

### macOS
```bash
# Install Node.js
brew install node@20

# Clone and setup
git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
cd RedQuanta-MCP
npm install
npm run build
```

## Verification

```bash
# Check installation
npm test

# Start server
npm run start:prod
```

## Next Steps

- [First Scan](first-scan.md)
- [Configuration](configuration.md)
- [Quick Start](quick-start.md) 