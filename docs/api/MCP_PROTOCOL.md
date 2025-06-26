# Model Context Protocol (MCP) Integration

Comprehensive guide to using RedQuanta MCP via the Model Context Protocol for LLM integration.

## Protocol Overview

The Model Context Protocol (MCP) enables secure, structured communication between Language Learning Models (LLMs) and external tools. RedQuanta MCP implements the full MCP specification for seamless AI integration.

### Key Features
- **Structured Tool Calls**: JSON-RPC 2.0 based communication
- **Type-Safe Operations**: Schema-validated requests and responses
- **Resource Management**: Efficient resource allocation and cleanup
- **Security Context**: Built-in security controls and audit logging
- **Streaming Support**: Real-time output streaming for long operations

## Connection Methods

### 1. Standard I/O (stdio)
```bash
# Direct stdio connection
node dist/server.js --mode stdio

# With LLM integration
{
  "name": "redquanta-mcp",
  "command": "node",
  "args": ["dist/server.js", "--mode", "stdio"],
  "env": {
    "NODE_ENV": "production"
  }
}
```

### 2. Server Socket Connection
```bash
# Start MCP server
node dist/server.js --mode server --port 8080

# Connect via WebSocket
ws://localhost:8080/mcp
```

### 3. Named Pipe (Windows)
```bash
# Windows named pipe
node dist/server.js --mode pipe --pipe-name \\.\pipe\redquanta-mcp
```

## MCP Message Format

### Request Structure
```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "method": "tools/call",
  "params": {
    "name": "nmap_scan",
    "arguments": {
      "target": "192.168.1.1",
      "scanType": "tcp",
      "ports": "80,443"
    }
  }
}
```

### Response Structure
```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Scan completed successfully"
      },
      {
        "type": "resource", 
        "resource": {
          "uri": "mcp://redquanta/scan-results/abc123",
          "name": "Nmap Scan Results",
          "mimeType": "application/json"
        }
      }
    ],
    "isError": false
  }
}
```

### Error Response
```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "details": "Target parameter is required",
      "validationErrors": [
        {
          "field": "target",
          "message": "Required field missing"
        }
      ]
    }
  }
}
```

## Available MCP Methods

### 1. Tool Discovery
```json
{
  "method": "tools/list",
  "params": {}
}
```

Response:
```json
{
  "result": {
    "tools": [
      {
        "name": "nmap_scan",
        "description": "Network discovery and port scanning",
        "inputSchema": {
          "type": "object",
          "properties": {
            "target": {"type": "string"},
            "scanType": {"type": "string", "enum": ["tcp", "syn", "udp", "ping"]},
            "ports": {"type": "string"}
          },
          "required": ["target"]
        }
      }
    ]
  }
}
```

### 2. Tool Execution
```json
{
  "method": "tools/call",
  "params": {
    "name": "nmap_scan",
    "arguments": {
      "target": "192.168.1.1",
      "scanType": "tcp",
      "ports": "1-1000"
    }
  }
}
```

### 3. Resource Access
```json
{
  "method": "resources/read",
  "params": {
    "uri": "mcp://redquanta/scan-results/abc123"
  }
}
```

### 4. Resource Listing
```json
{
  "method": "resources/list",
  "params": {
    "cursor": "optional-pagination-cursor"
  }
}
```

### 5. Server Information
```json
{
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "roots": {
        "listChanged": true
      },
      "sampling": {}
    },
    "clientInfo": {
      "name": "LLM Client",
      "version": "1.0.0"
    }
  }
}
```

## Tool Integration Examples

### Network Scanning Workflow
```python
import json
import asyncio
from mcp_client import MCPClient

async def network_assessment(client, target_network):
    """Complete network assessment workflow"""
    
    # Step 1: Host Discovery
    discovery_result = await client.call_tool(
        "nmap_scan",
        {
            "target": target_network,
            "scanType": "ping"
        }
    )
    
    if not discovery_result["isError"]:
        live_hosts = extract_live_hosts(discovery_result)
        
        # Step 2: Port Scanning
        for host in live_hosts:
            port_scan = await client.call_tool(
                "masscan_scan",
                {
                    "target": host,
                    "ports": "1-65535",
                    "rate": "1000"
                }
            )
            
            if not port_scan["isError"]:
                open_ports = extract_open_ports(port_scan)
                
                # Step 3: Service Detection
                if open_ports:
                    service_scan = await client.call_tool(
                        "nmap_scan",
                        {
                            "target": host,
                            "scanType": "version",
                            "ports": ",".join(map(str, open_ports))
                        }
                    )
    
    return discovery_result
```

### Web Application Testing
```python
async def web_app_assessment(client, target_url):
    """Comprehensive web application security assessment"""
    
    # Directory enumeration
    dir_enum = await client.call_tool(
        "ffuf_fuzz",
        {
            "url": f"{target_url}/FUZZ",
            "wordlist": "common-directories.txt",
            "extensions": "php,html,js"
        }
    )
    
    # Vulnerability scanning
    vuln_scan = await client.call_tool(
        "nikto_scan",
        {
            "target": target_url
        }
    )
    
    # Custom web workflow
    workflow_result = await client.call_tool(
        "workflow_scan",
        {
            "target": target_url,
            "scope": "web",
            "depth": "comprehensive"
        }
    )
    
    return {
        "directory_enumeration": dir_enum,
        "vulnerability_scan": vuln_scan,
        "workflow_assessment": workflow_result
    }
```

## Resource Management

### Scan Results as Resources
```json
{
  "method": "resources/read",
  "params": {
    "uri": "mcp://redquanta/scan-results/nmap-20240115-103000"
  }
}
```

Response:
```json
{
  "result": {
    "contents": [
      {
        "uri": "mcp://redquanta/scan-results/nmap-20240115-103000",
        "mimeType": "application/json",
        "text": "{\"tool\":\"nmap\",\"target\":\"192.168.1.1\",\"results\":[...]}"
      }
    ]
  }
}
```

### Report Generation
```json
{
  "method": "tools/call",
  "params": {
    "name": "generate_report",
    "arguments": {
      "format": "sarif",
      "include_resources": [
        "mcp://redquanta/scan-results/nmap-20240115-103000",
        "mcp://redquanta/scan-results/nikto-20240115-103500"
      ]
    }
  }
}
```

## Security Features

### Authentication
```json
{
  "method": "auth/login",
  "params": {
    "credentials": {
      "type": "api_key",
      "key": "your-api-key"
    }
  }
}
```

### Permission Validation
```json
{
  "method": "tools/call",
  "params": {
    "name": "nmap_scan",
    "arguments": {
      "target": "192.168.1.1",
      "scripts": "vuln"
    },
    "requiresDangerous": true
  }
}
```

### Audit Logging
```json
{
  "method": "audit/query",
  "params": {
    "timeRange": {
      "start": "2024-01-15T00:00:00Z",
      "end": "2024-01-15T23:59:59Z"
    },
    "actions": ["tool_execution", "resource_access"]
  }
}
```

## Streaming Support

### Long-Running Operations
```json
{
  "method": "tools/call",
  "params": {
    "name": "workflow_enum",
    "arguments": {
      "target": "192.168.1.0/24",
      "scope": "comprehensive"
    },
    "stream": true
  }
}
```

Progress Updates:
```json
{
  "jsonrpc": "2.0",
  "method": "notifications/progress",
  "params": {
    "token": "req-123",
    "value": {
      "kind": "progress",
      "percentage": 45,
      "message": "Scanning host 192.168.1.45..."
    }
  }
}
```

## Error Handling

### Standard Error Codes
```yaml
-32700: Parse error
-32600: Invalid Request  
-32601: Method not found
-32602: Invalid params
-32603: Internal error

# Custom RedQuanta errors
-40001: Tool not available
-40002: Insufficient permissions
-40003: Rate limit exceeded
-40004: Target validation failed
-40005: Dangerous operation requires explicit flag
```

### Error Response Example
```json
{
  "jsonrpc": "2.0",
  "id": "req-123",
  "error": {
    "code": -40002,
    "message": "Insufficient permissions",
    "data": {
      "required_permission": "dangerous_tools",
      "current_permissions": ["basic_scanning"],
      "suggestion": "Enable dangerous mode or use safer alternatives"
    }
  }
}
```

## Client Libraries

### Python Client
```python
from redquanta_mcp import MCPClient

async def main():
    async with MCPClient("stdio") as client:
        # Initialize connection
        await client.initialize()
        
        # List available tools
        tools = await client.list_tools()
        
        # Execute scan
        result = await client.call_tool(
            "nmap_scan",
            {"target": "192.168.1.1", "scanType": "tcp"}
        )
        
        print(f"Scan result: {result}")

if __name__ == "__main__":
    asyncio.run(main())
```

### JavaScript/TypeScript Client
```typescript
import { MCPClient } from '@redquanta/mcp-client';

const client = new MCPClient({
  transport: 'stdio',
  command: 'node',
  args: ['dist/server.js', '--mode', 'stdio']
});

await client.connect();

const scanResult = await client.callTool('nmap_scan', {
  target: '192.168.1.1',
  scanType: 'tcp',
  ports: '80,443'
});

console.log(scanResult);
```

## Configuration

### MCP Server Settings
```json
{
  "mcp": {
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "RedQuanta MCP",
      "version": "0.3.0"
    },
    "capabilities": {
      "tools": {
        "listChanged": true
      },
      "resources": {
        "subscribe": true,
        "listChanged": true
      },
      "logging": {
        "level": "info"
      },
      "prompts": {
        "listChanged": true
      }
    },
    "transports": {
      "stdio": {
        "enabled": true
      },
      "server": {
        "enabled": true,
        "host": "localhost",
        "port": 8080
      }
    }
  }
}
```

### Environment Variables
```bash
# MCP Configuration
MCP_PROTOCOL_VERSION=2024-11-05
MCP_SERVER_NAME="RedQuanta MCP"
MCP_LOG_LEVEL=info

# Transport Settings
MCP_STDIO_ENABLED=true
MCP_SERVER_ENABLED=true
MCP_SERVER_HOST=localhost
MCP_SERVER_PORT=8080

# Security Settings
MCP_AUTH_REQUIRED=false
MCP_API_KEY_HEADER=X-API-Key
MCP_RATE_LIMIT_ENABLED=true
```

## Best Practices

### Efficient Tool Usage
```python
# Batch operations when possible
async def batch_scan(client, targets):
    tasks = []
    for target in targets:
        task = client.call_tool("nmap_scan", {"target": target})
        tasks.append(task)
    
    results = await asyncio.gather(*tasks)
    return results

# Use appropriate timeouts
result = await client.call_tool(
    "masscan_scan",
    {"target": "large-network", "ports": "1-65535"},
    timeout=300  # 5 minute timeout for large scans
)
```

### Resource Cleanup
```python
async def managed_assessment(client, target):
    resources = []
    try:
        # Perform scans
        scan_result = await client.call_tool("nmap_scan", {"target": target})
        
        # Track resources for cleanup
        if scan_result.get("resources"):
            resources.extend(scan_result["resources"])
        
        return scan_result
        
    finally:
        # Clean up resources
        for resource in resources:
            await client.delete_resource(resource["uri"])
```

### Error Recovery
```python
async def resilient_scan(client, target):
    max_retries = 3
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            result = await client.call_tool("nmap_scan", {"target": target})
            return result
            
        except MCPError as e:
            if e.code == -40003:  # Rate limit
                await asyncio.sleep(retry_delay * (attempt + 1))
                continue
            elif e.code == -40001:  # Tool not available
                # Try alternative tool
                return await client.call_tool("masscan_scan", {"target": target})
            else:
                raise
    
    raise Exception(f"Failed to scan {target} after {max_retries} attempts")
```

## Integration Examples

### Claude Desktop Integration
```json
{
  "mcpServers": {
    "redquanta": {
      "command": "node",
      "args": ["dist/server.js", "--mode", "stdio"],
      "cwd": "/path/to/redquanta-mcp",
      "env": {
        "NODE_ENV": "production",
        "LOG_LEVEL": "info"
      }
    }
  }
}
```

### Cursor IDE Integration
```json
{
  "mcp.servers": [
    {
      "name": "redquanta-mcp",
      "command": "node",
      "args": ["dist/server.js", "--mode", "stdio"],
      "env": {
        "NODE_ENV": "development"
      }
    }
  ]
}
```

## Next Steps

- [REST API Documentation](REST_API.md)
- [Tool Reference](../tools/overview.md)
- [Security Configuration](../security/model.md) 