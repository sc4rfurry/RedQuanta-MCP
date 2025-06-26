# OpenAPI Specification

RedQuanta MCP provides a comprehensive REST API with full OpenAPI 3.0.3 specification for enterprise integration and automation.

## 📋 API Overview

!!! info "API Information"
    
    **Base URL**: `http://localhost:5891`  
    **Version**: `0.3.0`  
    **OpenAPI Version**: `3.0.3`  
    **License**: MIT  

### Interactive Documentation

Access the complete API documentation at:

=== "Swagger UI"
    ```
    📍 http://localhost:5891/docs
    ```

=== "ReDoc"
    ```
    📍 http://localhost:5891/redoc  
    ```

=== "OpenAPI JSON"
    ```
    📍 http://localhost:5891/openapi.json
    ```

## 🚀 Quick Start

### Basic API Call

```bash
# Health check
curl http://localhost:5891/health

# List available tools
curl http://localhost:5891/tools

# Execute Nmap scan
curl -X POST http://localhost:5891/tools/nmap_scan \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1", "ports": "top-1000"}'
```

For complete API documentation with all endpoints, schemas, and examples, visit the interactive documentation at **http://localhost:5891/docs**. 