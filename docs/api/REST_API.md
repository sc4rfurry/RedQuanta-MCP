# 📡 RedQuanta MCP REST API Reference

<div align="center">

![API Version](https://img.shields.io/badge/API%20Version-v1.0-blue?style=for-the-badge&logo=fastify)
![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0-green?style=for-the-badge&logo=swagger)
![Response Format](https://img.shields.io/badge/Format-JSON-orange?style=for-the-badge&logo=json)

**🚀 Complete REST API Documentation for RedQuanta MCP**

*Professional penetration testing orchestration via HTTP/REST*

</div>

---

## 🎯 **API Overview**

### 🏗️ **Architecture**

```
┌─────────────────┐    HTTP/HTTPS    ┌─────────────────┐
│                 │ ──────────────► │                 │
│   Client App    │                 │  RedQuanta MCP  │
│                 │ ◄────────────── │   REST Server   │
└─────────────────┘    JSON/SARIF   └─────────────────┘
        │                                     │
        │                                     │
        ▼                                     ▼
┌─────────────────┐                 ┌─────────────────┐
│   Web UI        │                 │   Security      │
│   CLI Tools     │                 │   Tools Engine  │
│   Automation    │                 │   Workflows     │
└─────────────────┘                 └─────────────────┘
```

### 📋 **Base Configuration**

| **Parameter** | **Value** | **Description** |
|---------------|-----------|-----------------|
| **Base URL** | `http://localhost:5891` | Default server address |
| **Protocol** | `HTTP/1.1`, `HTTP/2` | Supported protocols |
| **Content-Type** | `application/json` | Request/response format |
| **Authentication** | `Bearer Token` (optional) | API key authentication |
| **Rate Limiting** | `100 req/min` | Default rate limits |

---

## 🔧 **Quick Start**

### ⚡ **Test Your API Connection**

<details>
<summary><strong>🧪 cURL Examples</strong></summary>

```bash
# Health check
curl -X GET "http://localhost:5891/health" \
  -H "Accept: application/json"

# List all tools
curl -X GET "http://localhost:5891/tools" \
  -H "Accept: application/json"

# Execute a network scan
curl -X POST "http://localhost:5891/tools/nmap_scan" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "127.0.0.1",
    "dangerous": false
  }'
```

</details>

<details>
<summary><strong>🐍 Python Examples</strong></summary>

```python
import requests
import json

# Initialize client
base_url = "http://localhost:5891"
headers = {"Content-Type": "application/json"}

# Health check
response = requests.get(f"{base_url}/health")
print(f"Health: {response.json()}")

# List tools
tools = requests.get(f"{base_url}/tools").json()
print(f"Available tools: {len(tools['tools'])}")

# Execute scan
scan_request = {
    "target": "127.0.0.1",
    "dangerous": False
}
result = requests.post(
    f"{base_url}/tools/nmap_scan", 
    json=scan_request
).json()
print(f"Scan result: {result['success']}")
```

</details>

<details>
<summary><strong>📜 JavaScript Examples</strong></summary>

```javascript
// Using fetch API
const API_BASE = 'http://localhost:5891';

// Health check
const health = await fetch(`${API_BASE}/health`)
  .then(res => res.json());
console.log('Health:', health);

// Execute enumeration workflow
const enumResult = await fetch(`${API_BASE}/enum`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: '192.168.1.0/24',
    scope: 'network',
    depth: 'light'
  })
}).then(res => res.json());

console.log('Enumeration:', enumResult);
```

</details>

---

## 🛠️ **Core Endpoints**

### 🏥 **System & Health**

<table>
<tr>
<td width="30%"><strong>Endpoint</strong></td>
<td width="10%"><strong>Method</strong></td>
<td width="60%"><strong>Description</strong></td>
</tr>
<tr>
<td><code>/health</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>🏥 System health check and status</td>
</tr>
<tr>
<td><code>/config</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>⚙️ Server configuration and capabilities</td>
</tr>
<tr>
<td><code>/version</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>📋 Version and build information</td>
</tr>
<tr>
<td><code>/metrics</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>📊 Performance and usage metrics</td>
</tr>
</table>

#### **🏥 GET /health**

<details>
<summary><strong>📝 Response Schema</strong></summary>

```json
{
  "status": "healthy",
  "version": "0.3.0",
  "platform": "win32",
  "dangerous": false,
  "timestamp": "2024-12-24T10:30:00.000Z",
  "uptime": 3600,
  "jailRoot": "C:\\Users\\%USERNAME%\\AppData\\Local\\RedQuanta\\vol",
  "toolsLoaded": 14,
  "capabilities": {
    "mcp": true,
    "rest": true,
    "plugins": true,
    "workflows": true
  }
}
```

</details>

#### **⚙️ GET /config**

<details>
<summary><strong>📝 Response Schema</strong></summary>

```json
{
  "server": {
    "mode": "rest",
    "version": "0.3.0",
    "platform": "win32",
    "dangerousMode": false,
    "jailRoot": "C:\\Users\\%USERNAME%\\AppData\\Local\\RedQuanta\\vol"
  },
  "capabilities": {
    "totalTools": 14,
    "toolCategories": {
      "discovery": 2,
      "web": 3,
      "exploitation": 3,
      "workflow": 4,
      "system": 2
    }
  },
  "security": {
    "auditLogging": true,
    "pathValidation": true,
    "commandSanitization": true,
    "dangerousOperationsGated": true
  },
  "performance": {
    "cacheEnabled": true,
    "maxConcurrentJobs": 10,
    "requestTimeout": 300000
  }
}
```

</details>

---

### 🛠️ **Tool Management**

<table>
<tr>
<td width="35%"><strong>Endpoint</strong></td>
<td width="10%"><strong>Method</strong></td>
<td width="55%"><strong>Description</strong></td>
</tr>
<tr>
<td><code>/tools</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>📋 List all available tools with schemas</td>
</tr>
<tr>
<td><code>/tools/{toolName}</code></td>
<td><span style="background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px;">POST</span></td>
<td>⚡ Execute specific tool with parameters</td>
</tr>
<tr>
<td><code>/tools/{toolName}/help</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>📚 Get detailed tool documentation</td>
</tr>
<tr>
<td><code>/tools/{toolName}/schema</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>📐 Get tool input/output schema</td>
</tr>
</table>

#### **📋 GET /tools**

<details>
<summary><strong>📝 Response Schema</strong></summary>

```json
{
  "success": true,
  "count": 14,
  "categories": {
    "discovery": ["nmap", "masscan"],
    "web": ["ffuf", "gobuster", "nikto"],
    "exploitation": ["sqlmap_test", "john_crack", "hydra_bruteforce"],
    "workflow": ["workflow_enum", "workflow_scan", "workflow_report"],
    "system": ["filesystem_ops", "command_run"]
  },
  "tools": [
    {
      "name": "nmap",
      "description": "Advanced network discovery and port scanning",
      "category": "discovery",
      "dangerous": false,
      "inputSchema": {
        "type": "object",
        "properties": {
          "target": {
            "type": "string",
            "description": "Target IP, hostname, or CIDR range",
            "examples": ["192.168.1.10", "example.com", "10.0.0.0/24"]
          },
          "dangerous": {
            "type": "boolean",
            "description": "Enable dangerous/aggressive scanning",
            "default": false
          }
        },
        "required": ["target"]
      }
    }
  ]
}
```

</details>

#### **⚡ POST /tools/{toolName}**

<details>
<summary><strong>📋 Request Examples</strong></summary>

**Nmap Network Scan:**
```json
{
  "target": "192.168.1.0/24",
  "dangerous": false,
  "custom_flags": ["-sS", "-T4"],
  "timeout": 300000
}
```

**FFUF Web Fuzzing:**
```json
{
  "url": "https://example.com/FUZZ",
  "wordlist": "/usr/share/wordlists/dirb/common.txt",
  "dangerous": false,
  "custom_headers": {
    "Authorization": "Bearer token123"
  },
  "filter_codes": "404,403"
}
```

**Workflow Enumeration:**
```json
{
  "target": "example.com",
  "scope": "full",
  "depth": "normal",
  "coaching": "beginner",
  "custom_options": {
    "nmap_flags": ["-sV", "-sC"],
    "timing_template": "T3"
  }
}
```

</details>

<details>
<summary><strong>📝 Response Schema</strong></summary>

```json
{
  "success": true,
  "executionId": "exec_12345",
  "tool": "nmap",
  "target": "192.168.1.1",
  "startTime": "2024-12-24T10:30:00.000Z",
  "endTime": "2024-12-24T10:30:45.123Z",
  "duration": 45123,
  "data": {
    "hosts": [
      {
        "ip": "192.168.1.1",
        "hostname": "router.local",
        "status": "up",
        "ports": [
          {
            "port": 80,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "version": "nginx/1.18.0"
          }
        ]
      }
    ],
    "summary": {
      "hostsUp": 1,
      "portsOpen": 1,
      "services": ["http"]
    }
  },
  "rawOutput": "# Nmap 7.80 scan initiated...",
  "metadata": {
    "command": "nmap -sT -T4 192.168.1.1",
    "dangerous": false,
    "cached": false
  },
  "recommendations": [
    "🔍 Scan revealed HTTP service on port 80",
    "⚡ Consider web application testing with FFUF or Nikto",
    "🛡️ Review server version for known vulnerabilities"
  ]
}
```

</details>

---

### 🤖 **Workflow Automation**

<table>
<tr>
<td width="30%"><strong>Endpoint</strong></td>
<td width="10%"><strong>Method</strong></td>
<td width="60%"><strong>Description</strong></td>
</tr>
<tr>
<td><code>/enum</code></td>
<td><span style="background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px;">POST</span></td>
<td>🔍 Automated reconnaissance workflow</td>
</tr>
<tr>
<td><code>/scan</code></td>
<td><span style="background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px;">POST</span></td>
<td>🛡️ Vulnerability assessment workflow</td>
</tr>
<tr>
<td><code>/report</code></td>
<td><span style="background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px;">POST</span></td>
<td>📊 Professional report generation</td>
</tr>
<tr>
<td><code>/workflows</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>📋 List available workflow templates</td>
</tr>
</table>

#### **🔍 POST /enum**

<details>
<summary><strong>📋 Request Schema</strong></summary>

```json
{
  "target": "192.168.1.0/24",
  "scope": "network",
  "depth": "normal",
  "coaching": "beginner",
  "custom_options": {
    "nmap_flags": ["-sV", "-sC"],
    "timing_template": "T3",
    "wordlists": {
      "directories": "/usr/share/wordlists/dirb/common.txt",
      "subdomains": "/usr/share/wordlists/subdomains.txt"
    }
  }
}
```

**Parameters:**
- **target**: IP, hostname, or CIDR range
- **scope**: `network` | `web` | `full`
- **depth**: `light` | `normal` | `deep`
- **coaching**: `beginner` | `advanced`

</details>

#### **🛡️ POST /scan**

<details>
<summary><strong>📋 Request Schema</strong></summary>

```json
{
  "target": "example.com",
  "services": ["http", "https", "ssh"],
  "aggressive": false,
  "coaching": "beginner",
  "scan_options": {
    "network_scan": {
      "os_detection": true,
      "version_detection": true,
      "script_scanning": true
    },
    "web_scan": {
      "directories": true,
      "vulnerabilities": true,
      "ssl_analysis": true
    },
    "database_scan": {
      "injection_testing": false,
      "brute_force": false
    }
  }
}
```

</details>

---

### 🔌 **Plugin Management**

<table>
<tr>
<td width="30%"><strong>Endpoint</strong></td>
<td width="10%"><strong>Method</strong></td>
<td width="60%"><strong>Description</strong></td>
</tr>
<tr>
<td><code>/plugins</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>🧩 List loaded plugins and their status</td>
</tr>
<tr>
<td><code>/plugins/reload</code></td>
<td><span style="background-color: #007bff; color: white; padding: 2px 6px; border-radius: 3px;">POST</span></td>
<td>🔄 Hot reload all plugins</td>
</tr>
<tr>
<td><code>/plugins/{name}/info</code></td>
<td><span style="background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px;">GET</span></td>
<td>ℹ️ Get detailed plugin information</td>
</tr>
</table>

---

## 🔐 **Authentication & Security**

### 🔑 **API Authentication**

<details>
<summary><strong>Bearer Token Authentication</strong></summary>

```bash
# Set API key in headers
curl -X GET "http://localhost:5891/tools" \
  -H "Authorization: Bearer your-api-key-here" \
  -H "Accept: application/json"
```

**API Key Configuration:**
```json
{
  "apiKey": "redquanta_ak_1234567890abcdef",
  "keyType": "bearer",
  "expiresAt": "2024-12-31T23:59:59Z",
  "permissions": ["read", "execute", "dangerous"]
}
```

</details>

### 🛡️ **Security Headers**

All API responses include security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: default-src 'self'
```

---

## 📊 **Response Formats**

### ✅ **Success Response**

```json
{
  "success": true,
  "data": { /* Tool-specific data */ },
  "metadata": {
    "executionId": "exec_12345",
    "timestamp": "2024-12-24T10:30:00.000Z",
    "duration": 1234,
    "cached": false
  },
  "recommendations": [
    "Next step suggestions..."
  ]
}
```

### ❌ **Error Response**

```json
{
  "success": false,
  "error": {
    "code": "INVALID_TARGET",
    "message": "Target IP address is invalid",
    "details": "The provided target '999.999.999.999' is not a valid IP address",
    "timestamp": "2024-12-24T10:30:00.000Z",
    "requestId": "req_67890"
  },
  "documentation": "https://github.com/sc4rfurry/RedQuanta-MCP/docs/api/errors.md#invalid-target"
}
```

### 📈 **Streaming Response**

For long-running operations:

```json
{
  "type": "progress",
  "executionId": "exec_12345",
  "phase": "host_discovery",
  "progress": 25,
  "message": "Discovered 5 hosts, scanning ports...",
  "timestamp": "2024-12-24T10:30:15.000Z"
}
```

---

## 🚨 **Error Codes**

<table>
<tr>
<th width="15%"><strong>Code</strong></th>
<th width="25%"><strong>HTTP Status</strong></th>
<th width="60%"><strong>Description</strong></th>
</tr>
<tr>
<td><code>INVALID_TARGET</code></td>
<td>400 Bad Request</td>
<td>Target IP/hostname is invalid or malformed</td>
</tr>
<tr>
<td><code>TOOL_NOT_FOUND</code></td>
<td>404 Not Found</td>
<td>Requested tool is not available</td>
</tr>
<tr>
<td><code>DANGEROUS_OPERATION</code></td>
<td>403 Forbidden</td>
<td>Operation requires dangerous flag</td>
</tr>
<tr>
<td><code>RATE_LIMITED</code></td>
<td>429 Too Many Requests</td>
<td>Too many requests in time window</td>
</tr>
<tr>
<td><code>EXECUTION_TIMEOUT</code></td>
<td>408 Request Timeout</td>
<td>Tool execution exceeded timeout</td>
</tr>
<tr>
<td><code>INTERNAL_ERROR</code></td>
<td>500 Internal Server Error</td>
<td>Unexpected server error occurred</td>
</tr>
</table>

---

## 📈 **Rate Limiting**

### 🚦 **Default Limits**

| **Endpoint Category** | **Limit** | **Window** | **Burst** |
|-----------------------|-----------|------------|-----------|
| **Health/Config** | 100 req/min | 1 minute | 10 |
| **Tool Listing** | 50 req/min | 1 minute | 5 |
| **Tool Execution** | 20 req/min | 1 minute | 3 |
| **Workflows** | 10 req/min | 1 minute | 2 |

### 📊 **Rate Limit Headers**

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
X-RateLimit-RetryAfter: 60
```

---

## 🧪 **Testing & Development**

### 🔬 **API Testing**

<details>
<summary><strong>Postman Collection</strong></summary>

```json
{
  "info": {
    "name": "RedQuanta MCP API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Health Check",
      "request": {
        "method": "GET",
        "url": "{{baseUrl}}/health"
      }
    },
    {
      "name": "List Tools",
      "request": {
        "method": "GET",
        "url": "{{baseUrl}}/tools"
      }
    },
    {
      "name": "Nmap Scan",
      "request": {
        "method": "POST",
        "url": "{{baseUrl}}/tools/nmap",
        "body": {
          "mode": "raw",
          "raw": "{\n  \"target\": \"127.0.0.1\",\n  \"dangerous\": false\n}"
        }
      }
    }
  ],
  "variable": [
    {
      "key": "baseUrl",
      "value": "http://localhost:5891"
    }
  ]
}
```

</details>

### 📋 **OpenAPI Specification**

Full OpenAPI 3.0 specification available at:
- **Interactive Docs**: `http://localhost:5891/api/docs`
- **JSON Spec**: `http://localhost:5891/api/openapi.json`
- **YAML Spec**: `http://localhost:5891/api/openapi.yaml`

---

## 📞 **Support & Resources**

### 🆘 **Getting Help**

<div align="center">

[![GitHub Issues](https://img.shields.io/badge/🐛-Report%20API%20Bug-red?style=for-the-badge)](https://github.com/sc4rfurry/RedQuanta-MCP/issues/new?template=api_bug.md)
[![API Questions](https://img.shields.io/badge/❓-API%20Questions-blue?style=for-the-badge)](https://github.com/sc4rfurry/RedQuanta-MCP/discussions/categories/api)
[![Feature Request](https://img.shields.io/badge/💡-Request%20Feature-green?style=for-the-badge)](https://github.com/sc4rfurry/RedQuanta-MCP/issues/new?template=api_feature.md)

</div>

### 📚 **Additional Resources**

- **[📖 MCP Protocol Guide](MCP_PROTOCOL.md)** - Model Context Protocol documentation
- **[🧩 Plugin Development](../development/PLUGIN_DEVELOPMENT.md)** - Create custom tools
- **[🔒 Security Guide](../security/SECURITY_MODEL.md)** - Security best practices
- **[🚨 Troubleshooting](../troubleshooting/API.md)** - Common API issues

---

<div align="center">

**📡 API Version 1.0**

![Build Status](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge)
![API Tests](https://img.shields.io/badge/API%20Tests-100%25-brightgreen?style=for-the-badge)
![Response Time](https://img.shields.io/badge/Response%20Time-<100ms-blue?style=for-the-badge)

**Made with 🚀 by [@sc4rfurry](https://github.com/sc4rfurry)**

*Powerful APIs for intelligent security automation*

</div> 