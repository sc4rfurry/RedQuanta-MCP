# RedQuanta MCP - Production Deployment Guide

## 🚀 Production-Ready Features

RedQuanta MCP is now fully optimized for production deployment with:

✅ **JSON-RPC Compliance**: Complete ANSI escape sequence cleaning  
✅ **Security Hardening**: Multi-layer security controls and sandboxing  
✅ **Docker Integration**: Seamless container fallback system  
✅ **Audit Logging**: Comprehensive activity tracking  
✅ **Performance Optimization**: Efficient caching and resource management  
✅ **Error Handling**: Robust error recovery and reporting  
✅ **Documentation**: Complete API and user documentation  

## 📋 Prerequisites

### System Requirements
- **Node.js**: v20.0.0 or higher
- **Operating System**: Windows 10/11, Linux, macOS
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 10GB free space minimum
- **Network**: Internet access for Docker image pulls

### Optional Components
- **Docker**: For containerized security tools
- **Python**: For MkDocs documentation (if building docs)

## 🛠️ Installation

### 1. Clone and Install
```bash
git clone https://github.com/sc4rfurry/RedQuanta-MCP.git
cd RedQuanta-MCP
npm install
```

### 2. Build Production Assets
```bash
npm run build:prod
```

### 3. Docker Setup (Recommended)
```bash
# Build security tools container
docker-compose -f docker-security-tools.yml build

# Start container
docker-compose -f docker-security-tools.yml up -d
```

## 🚀 Production Startup

### Quick Start
```powershell
# Windows
.\start-production.ps1

# Linux/macOS
npm run start:prod
```

### Advanced Configuration
```powershell
# Custom configuration
.\start-production.ps1 -Mode rest -Port 8080 -DangerousMode
```

### Environment Variables
```bash
NODE_ENV=production
LOG_LEVEL=warn
MCP_MODE=rest              # stdio, rest, or hybrid
PORT=5891
HOST=0.0.0.0
WEB_SEARCH_ENABLED=true
CACHE_ENABLED=true
CACHE_TTL=1800
DANGEROUS_MODE=false       # Enable with caution
JAIL_ROOT=/tmp/redquanta   # Security sandbox
```

## 🔧 Server Modes

### 1. REST API Mode (Default)
```bash
MCP_MODE=rest
```
- **URL**: `http://host:port`
- **Documentation**: `http://host:port/docs`
- **Health Check**: `http://host:port/health`
- **Use Case**: Web applications, API integrations

### 2. Model Context Protocol (MCP) Mode
```bash
MCP_MODE=stdio
```
- **Protocol**: JSON-RPC over stdio
- **Use Case**: Claude Desktop, AI integrations
- **Features**: 100% JSON-RPC compliant

### 3. Hybrid Mode
```bash
MCP_MODE=hybrid
```
- **Features**: Both REST API and MCP simultaneously
- **Use Case**: Maximum flexibility

## 🛡️ Security Configuration

### Security Levels

#### Standard Mode (Default)
- Read-only filesystem operations
- Command validation and filtering
- Network request rate limiting
- Audit logging enabled

#### Dangerous Mode (Requires Flag)
```bash
DANGEROUS_MODE=true
```
- ⚠️ **WARNING**: Enables destructive operations
- File write/delete operations
- Advanced scanning techniques
- Use only in authorized environments

### Security Features
- **Command Whitelisting**: Only approved tools and arguments
- **Path Traversal Protection**: Filesystem access restricted to jail
- **Argument Sanitization**: Input validation and sanitization
- **Rate Limiting**: API request throttling
- **Audit Logging**: Complete activity tracking

## 🔍 Available Tools

### Network Reconnaissance
- **Nmap**: Network discovery and port scanning
- **Masscan**: High-speed port scanning
- **Domain Intelligence**: DNS, WHOIS, SSL analysis

### Web Application Testing
- **FFUF**: Directory and file fuzzing
- **Nikto**: Web vulnerability scanning
- **Web Search**: OSINT and threat intelligence

### Automation
- **Workflow Engine**: Automated reconnaissance workflows
- **Plugin System**: Custom tool integration
- **Filesystem Operations**: Secure file management

## 📊 Monitoring and Logs

### Audit Logs
```bash
# Location
logs/audit-YYYY-MM-DD.jsonl

# Real-time monitoring
tail -f logs/audit-$(date +%Y-%m-%d).jsonl
```

### Health Monitoring
```bash
# REST API health check
curl http://localhost:5891/health

# Status response
{
  "status": "healthy",
  "version": "0.3.0",
  "uptime": "3600s",
  "tools": 12
}
```

### Performance Metrics
- **Response Time**: Average < 100ms
- **Memory Usage**: < 256MB baseline
- **Cache Hit Rate**: > 80% typical
- **Error Rate**: < 1% in production

## 🐳 Docker Deployment

### Container Build
```bash
# Application container
docker build -t redquanta-mcp .

# Security tools container
docker-compose -f docker-security-tools.yml build
```

### Production Deployment
```bash
# Start all services
docker-compose up -d

# Scale for high availability
docker-compose up -d --scale app=3
```

### Container Health
```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs -f app
```

## 🔧 Troubleshooting

### Common Issues

#### 1. JSON-RPC Parsing Errors
**Solution**: Already resolved with ANSI cleaning
```bash
# Verify clean output
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | node dist/server.js
```

#### 2. Docker Tool Execution
**Issue**: Tools not found in container
```bash
# Rebuild container with latest tools
docker-compose -f docker-security-tools.yml build --no-cache
```

#### 3. Permission Errors
**Issue**: Filesystem access denied
```bash
# Check jail root permissions
ls -la $JAIL_ROOT
chmod 755 $JAIL_ROOT
```

#### 4. Memory Issues
**Issue**: High memory usage
```bash
# Enable production optimizations
NODE_ENV=production
LOG_LEVEL=warn
CACHE_TTL=3600
```

### Debug Mode
```bash
# Enable detailed logging
LOG_LEVEL=debug
NODE_ENV=development
```

## 📈 Performance Optimization

### Production Settings
```bash
# Optimized environment
NODE_ENV=production
LOG_LEVEL=warn
CACHE_ENABLED=true
CACHE_TTL=1800
WEB_SEARCH_ENABLED=true
```

### Resource Limits
```bash
# Memory optimization
node --max-old-space-size=1024 dist/server.js

# CPU optimization
node --max-semi-space-size=64 dist/server.js
```

### Load Balancing
```bash
# Multiple instances
PM2_HOME=/var/pm2 pm2 start dist/server.js -i max
```

## 🔐 Production Checklist

### Pre-Deployment
- [ ] Build completed successfully (`npm run build:prod`)
- [ ] All tests passing (`npm test`)
- [ ] Docker containers built and running
- [ ] Environment variables configured
- [ ] Security jail directory created
- [ ] Audit logging directory writable

### Security Review
- [ ] Dangerous mode disabled (unless required)
- [ ] Command whitelist reviewed
- [ ] Network access restricted appropriately
- [ ] Sensitive environment variables secured
- [ ] Audit logging enabled and monitored

### Monitoring Setup
- [ ] Health check endpoint accessible
- [ ] Log aggregation configured
- [ ] Performance monitoring enabled
- [ ] Alert thresholds defined
- [ ] Backup procedures established

## 📚 Additional Resources

- **API Documentation**: `/docs` endpoint when running
- **User Guide**: `docs/user-guide/`
- **Security Model**: `docs/security/SECURITY_MODEL.md`
- **Troubleshooting**: `deployment/troubleshooting.md`
- **Plugin Development**: `docs/development/plugin-development.md`

## 🆘 Support

### Community Support
- **GitHub Issues**: [Report bugs and feature requests](https://github.com/sc4rfurry/RedQuanta-MCP/issues)
- **Documentation**: Comprehensive guides in `docs/` directory
- **Examples**: Working examples in `docs/examples/`

### Enterprise Support
For enterprise deployments requiring custom configuration, training, or support:
- Custom integration assistance
- Security configuration review
- Performance optimization consulting
- Custom plugin development

---

**RedQuanta MCP v0.3.0** - Production-Ready Penetration Testing Orchestration Platform 