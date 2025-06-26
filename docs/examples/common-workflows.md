# Common Workflows

Essential security testing workflows for everyday penetration testing tasks.

## Network Discovery

### Basic Network Scanning
```bash
# Quick network discovery
redquanta-mcp nmap_scan 192.168.1.0/24 --scan-type ping --timing 5

# Port scan discovered hosts
redquanta-mcp masscan_scan 192.168.1.100-110 --ports 1-1000 --rate 1000

# Service identification
redquanta-mcp nmap_scan 192.168.1.100 --scan-type version --ports 22,80,443
```

### Home Network Assessment
```bash
# Comprehensive home network scan
redquanta-mcp workflow_enum 192.168.1.0/24 \
  --scope basic \
  --output-format json \
  --report-file home-network-scan.json
```

## Web Application Testing

### Basic Website Security Check
```bash
# Quick web vulnerability scan
redquanta-mcp nikto_scan https://example.com --output-format json

# Directory enumeration
redquanta-mcp ffuf_fuzz \
  --url "https://example.com/FUZZ" \
  --wordlist common-directories.txt \
  --filter-codes 404
```

### E-commerce Site Testing
```bash
# Comprehensive e-commerce security assessment
redquanta-mcp workflow_scan https://shop.example.com \
  --scope web \
  --tests "owasp-top10,payment-security" \
  --depth comprehensive
```

## Infrastructure Assessment

### Server Hardening Check
```bash
# Security baseline assessment
redquanta-mcp nmap_scan server.example.com \
  --scripts "default,safe" \
  --scan-type version \
  --timing 3
```

### Cloud Instance Security
```bash
# AWS EC2 instance security check
redquanta-mcp workflow_scan ec2-instance.amazonaws.com \
  --scope cloud \
  --tests "cloud-metadata,open-ports,ssl-config" \
  --dangerous
```

## Automated Workflows

### Daily Security Monitoring
```bash
#!/bin/bash
# daily-security-check.sh

DATE=$(date +%Y%m%d)
REPORT_DIR="reports/$DATE"
mkdir -p "$REPORT_DIR"

# Network perimeter scan
redquanta-mcp nmap_scan company-firewall.com \
  --scan-type tcp \
  --ports 80,443,22,21,25 \
  --output-file "$REPORT_DIR/perimeter-scan.json"

# Web application health check
redquanta-mcp nikto_scan https://company.com \
  --output-file "$REPORT_DIR/web-scan.json"
```

## Development Testing

### CI/CD Security Pipeline
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Security Scan
      run: |
        npm start &
        sleep 30
        redquanta-mcp nikto_scan http://localhost:3000
```

## Best Practices
- Always obtain proper authorization before scanning
- Start with lightweight scans and increase intensity gradually
- Monitor network impact during scanning
- Document all activities and findings
- Follow responsible disclosure practices

## Next Steps
- [Advanced Workflows](advanced-workflows.md)
- [Enterprise Setup](../tutorials/enterprise-setup.md)
- [Tool Documentation](../tools/overview.md)
