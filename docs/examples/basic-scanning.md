# Basic Scanning Examples

Learn RedQuanta MCP fundamentals with practical, real-world scanning examples.

## 🎯 Prerequisites

!!! warning "Legal Authorization Required"
    
    **⚠️ Only scan systems you own or have explicit written permission to test**

## 🔍 Network Discovery Examples

### Example 1: Basic Host Discovery

```bash
# Discover live hosts on local network
node dist/cli.js scan 192.168.1.0/24 --discovery-only

# REST API equivalent
curl -X POST http://localhost:5891/tools/nmap_scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "scanType": "ping"}'
```

### Example 2: Port Scanning

```bash
# Scan most common 1000 ports
node dist/cli.js scan scanme.nmap.org --ports top-1000

# Service detection
curl -X POST http://localhost:5891/tools/nmap_scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "ports": "top-100",
    "options": {
      "serviceDetection": true,
      "versionDetection": true
    }
  }'
```

## 🌐 Web Application Scanning

### Example 3: Directory Discovery

```bash
# Basic directory enumeration
node dist/cli.js tools ffuf_fuzz \
  --url "https://httpbin.org/FUZZ" \
  --wordlist "common_directories" \
  --threads 20
```

### Example 4: Vulnerability Scanning

```bash
# Web vulnerability assessment
node dist/cli.js tools nikto_scan \
  --target "https://httpbin.org" \
  --ssl
```

## 🔄 Automated Workflows

### Example 5: Complete Enumeration

```bash
# Comprehensive reconnaissance
node dist/cli.js enum example.com \
  --scope "comprehensive" \
  --depth "normal" \
  --coaching "beginner"
```

### Example 6: Vulnerability Assessment

```bash
# Complete security assessment
node dist/cli.js scan webapp.example.com \
  --scope "application" \
  --depth "comprehensive"
```

For detailed examples and advanced techniques, see our [comprehensive documentation](../index.md).