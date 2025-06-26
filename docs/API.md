# API Reference

Complete API reference for RedQuanta MCP including REST endpoints, MCP protocol, and integration examples.

## REST API Reference

### Base URL
```
http://localhost:5891/api/v1
```

### Authentication
```bash
# API Key Header
X-API-Key: your-api-key

# Bearer Token
Authorization: Bearer your-token
```

## Core Endpoints

### Health & Status

#### GET /health
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "uptime": 86400,
  "version": "0.3.0"
}
```

#### GET /status
```json
{
  "server": {
    "status": "running",
    "mode": "rest",
    "dangerous_mode": false
  },
  "tools": {
    "available": 8,
    "active_scans": 2
  }
}
```

### Tool Management

#### GET /tools
List all available tools with their capabilities.

#### GET /tools/{tool_name}
Get detailed information about a specific tool.

#### POST /tools/{tool_name}
Execute a security tool with specified parameters.

## Tool-Specific APIs

### Network Scanning

#### POST /tools/nmap_scan
```json
{
  "target": "192.168.1.1",
  "scanType": "tcp",
  "ports": "80,443,22",
  "timing": "4"
}
```

#### POST /tools/masscan_scan
```json
{
  "target": "192.168.1.0/24",
  "ports": "1-1000",
  "rate": 1000
}
```

### Web Testing

#### POST /tools/nikto_scan
```json
{
  "target": "https://example.com",
  "tuning": "1,2,3,4,5"
}
```

#### POST /tools/ffuf_fuzz
```json
{
  "url": "https://example.com/FUZZ",
  "wordlist": "common-directories.txt",
  "method": "GET"
}
```

### Workflow Automation

#### POST /tools/workflow_enum
```json
{
  "target": "192.168.1.0/24",
  "scope": "network",
  "depth": "comprehensive"
}
```

#### POST /tools/workflow_scan
```json
{
  "target": "example.com",
  "scope": "web",
  "tests": ["owasp-top10", "ssl-config"]
}
```

## Response Formats

### Success Response
```json
{
  "success": true,
  "tool": "nmap",
  "version": "7.95",
  "target": "192.168.1.1",
  "duration": 15.234,
  "data": {
    "hosts": [...],
    "ports": [...],
    "vulnerabilities": [...]
  }
}
```

### Error Response
```json
{
  "error": {
    "code": "INVALID_TARGET",
    "message": "Target parameter is required",
    "details": {
      "field": "target",
      "provided": null,
      "expected": "string"
    }
  }
}
```

## Best Practices

### API Usage
- Use HTTPS in production
- Implement proper error handling
- Respect rate limits
- Validate all inputs
- Log API interactions

### Performance
- Use pagination for large datasets
- Implement connection pooling
- Cache frequently accessed data
- Monitor response times
- Use appropriate timeouts

### Security
- Secure API key storage
- Implement IP whitelisting
- Use least privilege access
- Monitor for abuse
- Regular security audits

## Next Steps

- [User Guide](user-guide/overview.md)
- [Tool Documentation](tools/overview.md)
- [Integration Examples](examples/advanced-workflows.md)