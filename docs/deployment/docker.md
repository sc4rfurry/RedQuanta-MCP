# Docker Deployment

Production-grade Docker deployment guide for RedQuanta MCP server.

## Quick Start

### Pull Official Image
```bash
docker pull redquanta/mcp:latest
```

### Run Container
```bash
docker run -d \
  --name redquanta-mcp \
  -p 5891:5891 \
  -v $(pwd)/data:/app/vol \
  -v $(pwd)/config:/app/config:ro \
  redquanta/mcp:latest
```

## Production Configuration

### Docker Compose
```yaml
version: '3.8'

services:
  redquanta-mcp:
    image: redquanta/mcp:latest
    container_name: redquanta-mcp
    restart: unless-stopped
    ports:
      - "5891:5891"
    volumes:
      - ./data:/app/vol
      - ./config:/app/config:ro
      - ./logs:/app/logs
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=info
      - DANGEROUS_MODE=false
      - JAIL_ROOT=/app/vol
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5891/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - redquanta-net
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE

networks:
  redquanta-net:
    driver: bridge
```

### Environment Variables
```bash
# Core Configuration
NODE_ENV=production
LOG_LEVEL=info
PORT=5891
HOST=0.0.0.0

# Security Settings
DANGEROUS_MODE=false
JAIL_ROOT=/app/vol
API_KEY_REQUIRED=true

# Features
CACHE_ENABLED=true
WEB_SEARCH_ENABLED=false
TELEMETRY_ENABLED=true
```

## Multi-Architecture Builds

### Supported Platforms
- `linux/amd64`
- `linux/arm64`
- `linux/arm/v7`

### Build Commands
```bash
# Multi-platform build
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag redquanta/mcp:latest \
  --push .

# Local build
docker build -t redquanta/mcp:local .
```

## Security Hardening

### Container Security
```dockerfile
# Use non-root user
USER 1001:1001

# Read-only root filesystem
--read-only
--tmpfs /tmp
--tmpfs /var/run

# Resource limits
--memory="512m"
--cpus="1.0"
--pids-limit=100
```

### Network Security
```bash
# Isolated network
docker network create --driver bridge redquanta-net

# Firewall rules
ufw allow 5891/tcp
ufw enable
```

## Monitoring & Logging

### Health Checks
```bash
# Manual health check
curl -f http://localhost:5891/health

# Container logs
docker logs redquanta-mcp --follow

# Resource usage
docker stats redquanta-mcp
```

### Prometheus Metrics
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'redquanta-mcp'
    static_configs:
      - targets: ['localhost:5891']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

## Backup & Recovery

### Data Backup
```bash
# Backup volumes
docker run --rm \
  -v redquanta_data:/data \
  -v $(pwd):/backup \
  alpine tar czf /backup/redquanta-backup-$(date +%Y%m%d).tar.gz -C /data .

# Restore backup
docker run --rm \
  -v redquanta_data:/data \
  -v $(pwd):/backup \
  alpine tar xzf /backup/redquanta-backup-20240101.tar.gz -C /data
```

### Configuration Backup
```bash
# Export configuration
docker exec redquanta-mcp cat /app/config/allowedCommands.json > config-backup.json

# Restore configuration
docker cp config-backup.json redquanta-mcp:/app/config/allowedCommands.json
```

## Scaling & High Availability

### Load Balancer Configuration
```nginx
upstream redquanta_backend {
    server redquanta-mcp-1:5891;
    server redquanta-mcp-2:5891;
    server redquanta-mcp-3:5891;
}

server {
    listen 80;
    server_name redquanta.example.com;
    
    location / {
        proxy_pass http://redquanta_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Docker Swarm Deployment
```yaml
version: '3.8'

services:
  redquanta-mcp:
    image: redquanta/mcp:latest
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.5'
      update_config:
        parallelism: 1
        delay: 10s
        failure_action: rollback
    networks:
      - redquanta-overlay

networks:
  redquanta-overlay:
    driver: overlay
    attachable: true
```

## Troubleshooting

### Common Issues

#### Container Won't Start
```bash
# Check logs
docker logs redquanta-mcp

# Common fixes
docker run --rm -it redquanta/mcp:latest sh
docker exec -it redquanta-mcp sh
```

#### Permission Denied
```bash
# Fix volume permissions
sudo chown -R 1001:1001 ./data
sudo chmod 755 ./data
```

#### Network Issues
```bash
# Check port binding
docker port redquanta-mcp
netstat -tlnp | grep 5891

# Test connectivity
curl -v http://localhost:5891/health
```

### Performance Tuning
```bash
# Increase memory limits
docker update --memory="1g" redquanta-mcp

# CPU optimization
docker update --cpus="2.0" redquanta-mcp

# Logging optimization
docker update --log-opt max-size=10m --log-opt max-file=3 redquanta-mcp
```

## CI/CD Integration

### GitHub Actions
```yaml
- name: Build and push Docker image
  uses: docker/build-push-action@v5
  with:
    context: .
    platforms: linux/amd64,linux/arm64
    push: true
    tags: |
      redquanta/mcp:latest
      redquanta/mcp:${{ github.sha }}
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'docker build -t redquanta/mcp:${BUILD_NUMBER} .'
            }
        }
        stage('Test') {
            steps {
                sh 'docker run --rm redquanta/mcp:${BUILD_NUMBER} npm test'
            }
        }
        stage('Deploy') {
            steps {
                sh 'docker push redquanta/mcp:${BUILD_NUMBER}'
            }
        }
    }
}
```

## Next Steps

- [Monitoring Setup](monitoring.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Security Hardening](../security/model.md) 