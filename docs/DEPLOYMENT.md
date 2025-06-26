# 🚀 Production Deployment Guide

<div align="center">

![Deployment](https://img.shields.io/badge/Deployment-Production%20Ready-success?style=for-the-badge&logo=rocket)
![Docker](https://img.shields.io/badge/Docker-Supported-blue?style=for-the-badge&logo=docker)
![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-blue?style=for-the-badge&logo=kubernetes)

**Enterprise-Grade Deployment Options for RedQuanta MCP**

</div>

---

## 📋 **Deployment Options**

### 🐳 **Docker Deployment (Recommended)**

#### Quick Start with Docker

```bash
# Pull the latest image
docker pull sc4rfurry/redquanta-mcp:latest

# Run with default settings
docker run -d \
  --name redquanta-mcp \
  -p 5891:5891 \
  -v $(pwd)/vol:/opt/redquanta/vol \
  -e DANGEROUS_MODE=false \
  -e WEB_SEARCH_ENABLED=true \
  sc4rfurry/redquanta-mcp:latest
```

#### Docker Compose (Production)

```yaml
version: '3.8'

services:
  redquanta-mcp:
    image: sc4rfurry/redquanta-mcp:latest
    container_name: redquanta-mcp-prod
    ports:
      - "5891:5891"
    volumes:
      - ./vol:/opt/redquanta/vol
      - ./config:/opt/redquanta/config
      - ./logs:/opt/redquanta/logs
    environment:
      - NODE_ENV=production
      - HOST=0.0.0.0
      - PORT=5891
      - MCP_MODE=rest
      - DANGEROUS_MODE=false
      - LOG_LEVEL=info
      - WEB_SEARCH_ENABLED=true
      - CACHE_ENABLED=true
      - SECURITY_HEADERS=true
      - API_DOCS_ENABLED=true
      - RATE_LIMIT_MAX=100
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5891/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    networks:
      - redquanta-network

  # Optional: Redis for caching
  redis:
    image: redis:7-alpine
    container_name: redquanta-redis
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    networks:
      - redquanta-network

  # Optional: Nginx reverse proxy
  nginx:
    image: nginx:alpine
    container_name: redquanta-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - redquanta-mcp
    restart: unless-stopped
    networks:
      - redquanta-network

volumes:
  redis-data:

networks:
  redquanta-network:
    driver: bridge
```

### ☸️ **Kubernetes Deployment**

#### Kubernetes Manifests

```yaml
# redquanta-namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: redquanta-mcp
  labels:
    name: redquanta-mcp

---

# redquanta-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: redquanta-config
  namespace: redquanta-mcp
data:
  NODE_ENV: "production"
  HOST: "0.0.0.0"
  PORT: "5891"
  MCP_MODE: "rest"
  DANGEROUS_MODE: "false"
  LOG_LEVEL: "info"
  WEB_SEARCH_ENABLED: "true"
  CACHE_ENABLED: "true"
  SECURITY_HEADERS: "true"
  API_DOCS_ENABLED: "true"

---

# redquanta-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redquanta-mcp
  namespace: redquanta-mcp
  labels:
    app: redquanta-mcp
spec:
  replicas: 3
  selector:
    matchLabels:
      app: redquanta-mcp
  template:
    metadata:
      labels:
        app: redquanta-mcp
    spec:
      containers:
      - name: redquanta-mcp
        image: sc4rfurry/redquanta-mcp:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 5891
          name: http
        envFrom:
        - configMapRef:
            name: redquanta-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 5891
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 5891
          initialDelaySeconds: 5
          periodSeconds: 5
        volumeMounts:
        - name: redquanta-storage
          mountPath: /opt/redquanta/vol
      volumes:
      - name: redquanta-storage
        persistentVolumeClaim:
          claimName: redquanta-pvc

---

# redquanta-pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redquanta-pvc
  namespace: redquanta-mcp
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi

---

# redquanta-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: redquanta-service
  namespace: redquanta-mcp
spec:
  selector:
    app: redquanta-mcp
  ports:
  - name: http
    port: 80
    targetPort: 5891
  type: ClusterIP

---

# redquanta-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: redquanta-ingress
  namespace: redquanta-mcp
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit: "100"
    nginx.ingress.kubernetes.io/rate-limit-window: "1m"
spec:
  tls:
  - hosts:
    - redquanta.yourdomain.com
    secretName: redquanta-tls
  rules:
  - host: redquanta.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: redquanta-service
            port:
              number: 80
```

### 🖥️ **Bare Metal Deployment**

#### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 4GB | 8GB+ |
| **Storage** | 20GB | 50GB+ |
| **OS** | Ubuntu 20.04+ | Ubuntu 22.04 LTS |
| **Node.js** | 20.0.0+ | 20.11.0+ |

#### Installation Steps

```bash
# 1. System Preparation
sudo apt update && sudo apt upgrade -y
sudo apt install -y nodejs npm git curl

# 2. Create redquanta user
sudo useradd -m -s /bin/bash redquanta
sudo usermod -aG sudo redquanta

# 3. Clone and setup
sudo -u redquanta git clone https://github.com/sc4rfurry/RedQuanta-MCP.git /home/redquanta/redquanta-mcp
cd /home/redquanta/redquanta-mcp

# 4. Install dependencies
sudo -u redquanta npm install --production

# 5. Build application
sudo -u redquanta npm run build

# 6. Create systemd service
sudo tee /etc/systemd/system/redquanta-mcp.service << EOF
[Unit]
Description=RedQuanta MCP Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=redquanta
Group=redquanta
WorkingDirectory=/home/redquanta/redquanta-mcp
ExecStart=/usr/bin/node dist/server.js
Restart=always
RestartSec=10
Environment=NODE_ENV=production
Environment=HOST=0.0.0.0
Environment=PORT=5891
Environment=MCP_MODE=rest
Environment=DANGEROUS_MODE=false

[Install]
WantedBy=multi-user.target
EOF

# 7. Start and enable service
sudo systemctl daemon-reload
sudo systemctl enable redquanta-mcp
sudo systemctl start redquanta-mcp

# 8. Verify deployment
curl http://localhost:5891/health
```

### ☁️ **Cloud Deployment**

#### AWS ECS with Fargate

```json
{
  "family": "redquanta-mcp",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "redquanta-mcp",
      "image": "sc4rfurry/redquanta-mcp:latest",
      "portMappings": [
        {
          "containerPort": 5891,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "NODE_ENV", "value": "production"},
        {"name": "HOST", "value": "0.0.0.0"},
        {"name": "PORT", "value": "5891"},
        {"name": "MCP_MODE", "value": "rest"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/redquanta-mcp",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:5891/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

#### Google Cloud Run

```bash
# Deploy to Cloud Run
gcloud run deploy redquanta-mcp \
  --image=sc4rfurry/redquanta-mcp:latest \
  --platform=managed \
  --region=us-central1 \
  --allow-unauthenticated \
  --port=5891 \
  --memory=1Gi \
  --cpu=1 \
  --set-env-vars="NODE_ENV=production,MCP_MODE=rest,DANGEROUS_MODE=false"
```

---

## 🔧 **Configuration Management**

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NODE_ENV` | `development` | Node.js environment |
| `HOST` | `localhost` | Server bind address |
| `PORT` | `5891` | Server port |
| `MCP_MODE` | `rest` | Server mode (stdio/rest/hybrid) |
| `DANGEROUS_MODE` | `false` | Enable dangerous operations |
| `LOG_LEVEL` | `info` | Logging level |
| `WEB_SEARCH_ENABLED` | `false` | Enable web search |
| `CACHE_ENABLED` | `true` | Enable caching |
| `SECURITY_HEADERS` | `true` | Security headers |
| `API_DOCS_ENABLED` | `true` | API documentation |

### Production Configuration

```bash
# Create production environment file
cat > .env.production << EOF
NODE_ENV=production
HOST=0.0.0.0
PORT=5891
MCP_MODE=rest
DANGEROUS_MODE=false
LOG_LEVEL=warn
WEB_SEARCH_ENABLED=true
CACHE_ENABLED=true
CACHE_TTL=3600
SECURITY_HEADERS=true
API_DOCS_ENABLED=true
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000
CORS_ORIGINS=https://yourdomain.com
EOF
```

---

## 📊 **Monitoring & Observability**

### Health Checks

```bash
# Basic health check
curl http://localhost:5891/health

# Detailed status
curl http://localhost:5891/config

# Metrics endpoint (if enabled)
curl http://localhost:5891/metrics
```

### Logging

RedQuanta MCP provides structured logging with multiple levels:

```bash
# View logs (systemd)
sudo journalctl -u redquanta-mcp -f

# View logs (Docker)
docker logs -f redquanta-mcp

# View logs (Kubernetes)
kubectl logs -f deployment/redquanta-mcp -n redquanta-mcp
```

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'redquanta-mcp'
    static_configs:
      - targets: ['localhost:5891']
    metrics_path: /metrics
    scrape_interval: 30s
```

---

## 🔒 **Security Hardening**

### SSL/TLS Configuration

```nginx
# nginx.conf
server {
    listen 443 ssl http2;
    server_name redquanta.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    location / {
        proxy_pass http://redquanta-mcp:5891;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Firewall Configuration

```bash
# UFW configuration
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 5891/tcp comment 'RedQuanta MCP'
```

---

## 🔄 **CI/CD Pipeline**

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: 🚀 Deploy to Production

on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: 📥 Checkout
        uses: actions/checkout@v4
        
      - name: 🔧 Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          
      - name: 📦 Install dependencies
        run: npm ci
        
      - name: 🏗️ Build application
        run: npm run build
        
      - name: 🧪 Run tests
        run: npm test
        
      - name: 🐳 Build Docker image
        run: |
          docker build -t sc4rfurry/redquanta-mcp:${{ github.sha }} .
          docker tag sc4rfurry/redquanta-mcp:${{ github.sha }} sc4rfurry/redquanta-mcp:latest
          
      - name: 📤 Push to Registry
        run: |
          echo ${{ secrets.DOCKER_PASSWORD }} | docker login -u ${{ secrets.DOCKER_USERNAME }} --password-stdin
          docker push sc4rfurry/redquanta-mcp:${{ github.sha }}
          docker push sc4rfurry/redquanta-mcp:latest
          
      - name: 🚀 Deploy to production
        run: |
          # Deploy script here
          echo "Deploying to production..."
```

---

## 📞 **Support & Troubleshooting**

### Common Issues

| Issue | Solution |
|-------|----------|
| **Port already in use** | Change PORT environment variable |
| **Permission denied** | Ensure proper file permissions |
| **Memory issues** | Increase container/VM memory |
| **SSL certificate errors** | Verify certificate configuration |

### Getting Help

- 📁 [GitHub Issues](https://github.com/sc4rfurry/RedQuanta-MCP/issues)
- 💬 [Discussions](https://github.com/sc4rfurry/RedQuanta-MCP/discussions)
- 📖 [Documentation](https://sc4rfurry.github.io/RedQuanta-MCP/)

---

<div align="center">

**🛡️ RedQuanta MCP - Production Deployment Guide**

![Built with](https://img.shields.io/badge/Built%20with-❤️-red?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-First-green?style=for-the-badge)

*Made with 🔒 by [@sc4rfurry](https://github.com/sc4rfurry)*

</div> 