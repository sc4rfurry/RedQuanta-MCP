# Configuration Guide

Complete configuration reference for RedQuanta MCP.

## Environment Variables

```bash
# Core Configuration
NODE_ENV=production
LOG_LEVEL=info
PORT=5891
HOST=localhost

# Security Settings
DANGEROUS_MODE=false
JAIL_ROOT=/opt/redquanta/vol

# Features
CACHE_ENABLED=true
WEB_SEARCH_ENABLED=true
```

## Configuration Files

### Security Policies
- `config/allowedCommands.json` - Command whitelist
- `config/allowedPaths.json` - Path restrictions
- `config/deniedPatterns.json` - Blocked patterns

### Tool Configuration
Tools are configured in `allowedCommands.json`:

```json
{
  "nmap": {
    "binary": "nmap",
    "allowedArgs": ["-A", "-T4", "-sV"],
    "dangerousArgs": ["--script", "vuln"],
    "timeout": 300
  }
}
```

## Advanced Configuration

### Docker Settings
```yaml
# docker-compose.yml
environment:
  - NODE_ENV=production
  - JAIL_ROOT=/app/vol
  - DANGEROUS_MODE=false
```

### Kubernetes
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: redquanta-config
data:
  NODE_ENV: "production"
  LOG_LEVEL: "info"
```

## Next Steps

- [First Scan](first-scan.md)
- [Security Model](../security/model.md) 