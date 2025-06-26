# Deployment Troubleshooting

Comprehensive troubleshooting guide for RedQuanta MCP deployment and operational issues.

## Common Installation Issues

### Node.js Version Problems

#### Symptom
```
Error: Unsupported Node.js version
```

#### Diagnosis
```bash
node --version  # Check current version
npm --version   # Check npm version
```

#### Solution
```bash
# Install Node.js 18+ using nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install 18
nvm use 18

# Verify installation
node --version  # Should show v18.x.x or higher
```

### Dependency Installation Failures

#### Symptom
```
npm ERR! peer dep missing
npm ERR! ERESOLVE unable to resolve dependency tree
```

#### Diagnosis
```bash
npm ls --depth=0  # Check dependency tree
npm audit         # Check for vulnerabilities
```

#### Solution
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and package-lock.json
rm -rf node_modules package-lock.json

# Reinstall with legacy peer deps
npm install --legacy-peer-deps

# Alternative: Use pnpm
npm install -g pnpm
pnpm install
```

### Build Failures

#### Symptom
```
Error: TypeScript compilation failed
```

#### Diagnosis
```bash
npx tsc --noEmit  # Check TypeScript errors
npm run lint      # Check linting errors
```

#### Solution
```bash
# Fix TypeScript errors
npx tsc --noEmit --listFiles

# Update TypeScript
npm install -D typescript@latest

# Rebuild project
npm run clean
npm run build
```

## Runtime Issues

### Server Startup Failures

#### Symptom
```
Error: Cannot start RedQuanta MCP server
Port 5891 already in use
```

#### Diagnosis
```bash
# Check port usage
netstat -tlnp | grep 5891
lsof -i :5891

# Check process status
ps aux | grep redquanta
```

#### Solution
```bash
# Kill existing process
sudo kill -9 $(lsof -t -i:5891)

# Use alternative port
export PORT=5892
npm run start

# Check for firewall issues
sudo ufw status
sudo iptables -L
```

### Permission Errors

#### Symptom
```
Error: EACCES: permission denied
Error: Cannot create jail directory
```

#### Diagnosis
```bash
# Check current user permissions
whoami
id

# Check directory permissions
ls -la /app/vol
ls -la /tmp/redquanta
```

#### Solution
```bash
# Fix directory permissions
sudo mkdir -p /app/vol
sudo chown $(whoami):$(whoami) /app/vol
sudo chmod 755 /app/vol

# Run with appropriate user
sudo -u redquanta npm start

# Fix temporary directory
sudo mkdir -p /tmp/redquanta
sudo chmod 777 /tmp/redquanta
```

### Memory Issues

#### Symptom
```
JavaScript heap out of memory
FATAL ERROR: Ineffective mark-compacts near heap limit
```

#### Diagnosis
```bash
# Monitor memory usage
top -p $(pgrep node)
htop
free -h
```

#### Solution
```bash
# Increase Node.js heap size
export NODE_OPTIONS="--max-old-space-size=4096"

# Monitor memory usage
node --expose-gc -e "
setInterval(() => {
  global.gc();
  console.log(process.memoryUsage());
}, 5000);
"

# Optimize application
npm run start:optimized
```

## Docker Issues

### Container Build Failures

#### Symptom
```
ERROR: failed to solve: executor failed running
COPY failed: file not found
```

#### Diagnosis
```bash
# Check Dockerfile syntax
docker build --no-cache -t redquanta-test .

# Inspect build layers
docker build --progress=plain -t redquanta-test .
```

#### Solution
```bash
# Fix Dockerfile paths
COPY package*.json ./
COPY src/ ./src/
COPY config/ ./config/

# Build with specific context
docker build -f Dockerfile.prod -t redquanta-mcp .

# Clean build cache
docker builder prune -a
```

### Container Runtime Issues

#### Symptom
```
Container exits immediately
Health check failing
```

#### Diagnosis
```bash
# Check container logs
docker logs redquanta-mcp
docker logs --follow redquanta-mcp

# Inspect container
docker inspect redquanta-mcp
docker exec -it redquanta-mcp sh
```

#### Solution
```bash
# Fix health check
docker run --health-cmd "curl -f http://localhost:5891/health" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  redquanta/mcp:latest

# Debug container startup
docker run -it --entrypoint sh redquanta/mcp:latest

# Check resource limits
docker stats redquanta-mcp
```

### Networking Problems

#### Symptom
```
Connection refused
Cannot reach container service
```

#### Diagnosis
```bash
# Check port mapping
docker port redquanta-mcp

# Test connectivity
curl -v http://localhost:5891/health
telnet localhost 5891
```

#### Solution
```bash
# Fix port mapping
docker run -p 5891:5891 redquanta/mcp:latest

# Check firewall rules
sudo iptables -L DOCKER
sudo ufw status

# Test from host
docker exec redquanta-mcp curl http://localhost:5891/health
```

## Tool Integration Issues

### Tool Not Found Errors

#### Symptom
```
Error: nmap not found in PATH
Tool execution failed: command not found
```

#### Diagnosis
```bash
# Check tool availability
which nmap
which masscan
which nikto

# Check PATH
echo $PATH
```

#### Solution
```bash
# Install missing tools (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install nmap masscan nikto

# Install tools (CentOS/RHEL)
sudo yum install nmap masscan nikto

# Install tools (macOS)
brew install nmap masscan nikto

# Configure custom tool paths
export TOOL_PATH="/custom/tools/bin:$PATH"
```

### Tool Execution Timeouts

#### Symptom
```
Error: Tool execution timeout
Scan terminated after 300 seconds
```

#### Diagnosis
```bash
# Check system resources
top
iostat 1 5
sar -u 1 5
```

#### Solution
```bash
# Increase timeout values
export TOOL_TIMEOUT=600

# Optimize scan parameters
node dist/cli.js nmap_scan target --timing 4 --max-parallelism 50

# Use faster scanning methods
node dist/cli.js masscan_scan target --rate 1000
```

### Permission Denied for Tools

#### Symptom
```
Error: You need to be root to perform SYN scans
Permission denied: raw socket
```

#### Diagnosis
```bash
# Check user capabilities
getcap /usr/bin/nmap
ls -la /usr/bin/nmap
```

#### Solution
```bash
# Add capabilities to nmap
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Run with sudo (development only)
sudo npm start

# Use non-privileged scan types
node dist/cli.js nmap_scan target --scan-type tcp
```

## Database Issues

### Connection Failures

#### Symptom
```
Error: connect ECONNREFUSED 127.0.0.1:5432
Database connection failed
```

#### Diagnosis
```bash
# Check PostgreSQL status
sudo systemctl status postgresql
pg_isready -h localhost -p 5432

# Check connection parameters
psql -h localhost -U redquanta_user -d redquanta
```

#### Solution
```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql -c "CREATE DATABASE redquanta;"
sudo -u postgres psql -c "CREATE USER redquanta_user WITH PASSWORD 'password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE redquanta TO redquanta_user;"

# Fix connection string
export DATABASE_URL="postgresql://redquanta_user:password@localhost:5432/redquanta"
```

### Migration Failures

#### Symptom
```
Error: Migration failed
Table does not exist
```

#### Diagnosis
```bash
# Check migration status
npm run migrate:status

# Check database schema
psql -h localhost -U redquanta_user -d redquanta -c "\dt"
```

#### Solution
```bash
# Run migrations
npm run migrate:up

# Reset database (development only)
npm run migrate:reset

# Manual migration
psql -h localhost -U redquanta_user -d redquanta -f migrations/001_initial.sql
```

## Performance Issues

### Slow Response Times

#### Symptom
```
API requests taking >30 seconds
High CPU usage
Memory leaks
```

#### Diagnosis
```bash
# Profile application
npm run profile

# Monitor resources
htop
iotop
nethogs

# Check logs
tail -f logs/redquanta.log | grep ERROR
```

#### Solution
```bash
# Optimize configuration
export NODE_OPTIONS="--max-old-space-size=4096 --optimize-for-size"

# Enable clustering
export CLUSTER_WORKERS=4

# Tune garbage collection
export NODE_OPTIONS="$NODE_OPTIONS --gc-interval=100"

# Use connection pooling
export DB_POOL_SIZE=20
```

### High Memory Usage

#### Symptom
```
Memory usage constantly increasing
Out of memory errors
Swap usage high
```

#### Diagnosis
```bash
# Monitor memory
free -h
vmstat 1 5
cat /proc/meminfo

# Check for memory leaks
node --inspect dist/server.js
```

#### Solution
```bash
# Increase swap space
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Optimize memory usage
export NODE_OPTIONS="--max-old-space-size=2048"

# Enable memory monitoring
npm run start:monitor-memory
```

## Security Issues

### SSL/TLS Problems

#### Symptom
```
SSL certificate verification failed
HTTPS connection refused
```

#### Diagnosis
```bash
# Check certificate
openssl s_client -connect localhost:5891 -servername localhost

# Verify certificate files
openssl x509 -in cert.pem -text -noout
openssl rsa -in key.pem -check
```

#### Solution
```bash
# Generate new certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Fix certificate permissions
chmod 600 key.pem
chmod 644 cert.pem

# Update configuration
export SSL_CERT_PATH="/app/config/cert.pem"
export SSL_KEY_PATH="/app/config/key.pem"
```

### Authentication Failures

#### Symptom
```
API key authentication failed
Unauthorized access attempts
```

#### Diagnosis
```bash
# Check API key
curl -H "X-API-Key: test-key" http://localhost:5891/tools

# Check authentication logs
grep "authentication" logs/audit.log
```

#### Solution
```bash
# Generate new API key
node scripts/generate-api-key.js

# Update API key
export API_KEY="new-secure-api-key"

# Reset authentication
npm run auth:reset
```

## Monitoring and Diagnostics

### Log Analysis

#### Centralized Logging
```bash
# Tail application logs
tail -f logs/redquanta.log

# Filter error logs
grep ERROR logs/redquanta.log | tail -100

# Analyze access patterns
awk '{print $1}' logs/access.log | sort | uniq -c | sort -nr
```

#### Log Rotation
```bash
# Configure logrotate
sudo tee /etc/logrotate.d/redquanta << EOF
/app/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 redquanta redquanta
}
EOF
```

### Health Monitoring

#### Automated Health Checks
```bash
#!/bin/bash
# health-check.sh

HEALTH_URL="http://localhost:5891/health"
ALERT_EMAIL="admin@company.com"

response=$(curl -s -o /dev/null -w "%{http_code}" "$HEALTH_URL")

if [ "$response" != "200" ]; then
    echo "RedQuanta MCP health check failed: HTTP $response" | \
    mail -s "RedQuanta MCP Alert" "$ALERT_EMAIL"
    
    # Attempt restart
    sudo systemctl restart redquanta-mcp
fi
```

#### Resource Monitoring
```bash
#!/bin/bash
# monitor-resources.sh

CPU_THRESHOLD=80
MEMORY_THRESHOLD=85
DISK_THRESHOLD=90

# Check CPU usage
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
if (( $(echo "$CPU_USAGE > $CPU_THRESHOLD" | bc -l) )); then
    echo "High CPU usage: $CPU_USAGE%"
fi

# Check memory usage
MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
if (( $(echo "$MEMORY_USAGE > $MEMORY_THRESHOLD" | bc -l) )); then
    echo "High memory usage: $MEMORY_USAGE%"
fi

# Check disk usage
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
if [ "$DISK_USAGE" -gt "$DISK_THRESHOLD" ]; then
    echo "High disk usage: $DISK_USAGE%"
fi
```

## Recovery Procedures

### Service Recovery

#### Automatic Restart
```bash
# systemd service with auto-restart
sudo tee /etc/systemd/system/redquanta-mcp.service << EOF
[Unit]
Description=RedQuanta MCP Server
After=network.target

[Service]
Type=simple
User=redquanta
WorkingDirectory=/app/redquanta-mcp
ExecStart=/usr/bin/node dist/server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable redquanta-mcp
sudo systemctl start redquanta-mcp
```

#### Database Recovery
```bash
# Backup before recovery
pg_dump redquanta > backup.sql

# Restore from backup
dropdb redquanta
createdb redquanta
psql redquanta < backup.sql

# Rebuild indexes
psql redquanta -c "REINDEX DATABASE redquanta;"
```

### Configuration Recovery

#### Backup Configuration
```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backups/config/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration files
cp -r config/ "$BACKUP_DIR/"
cp package.json "$BACKUP_DIR/"
cp .env "$BACKUP_DIR/"

# Create archive
tar -czf "$BACKUP_DIR.tar.gz" -C /backups/config "$(basename $BACKUP_DIR)"
```

#### Restore Configuration
```bash
#!/bin/bash
# restore-config.sh

BACKUP_FILE="$1"
if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

# Extract backup
tar -xzf "$BACKUP_FILE" -C /tmp/

# Restore configuration
cp -r /tmp/config/* config/
cp /tmp/package.json .
cp /tmp/.env .

# Restart service
sudo systemctl restart redquanta-mcp
```

## Emergency Procedures

### Complete System Recovery

#### Disaster Recovery Plan
```bash
#!/bin/bash
# disaster-recovery.sh

echo "Starting RedQuanta MCP disaster recovery..."

# 1. Stop all services
sudo systemctl stop redquanta-mcp
sudo systemctl stop postgresql
sudo systemctl stop redis

# 2. Restore from backup
./restore-config.sh latest-backup.tar.gz
./restore-database.sh latest-db-backup.sql

# 3. Verify installation
npm install --production
npm run build

# 4. Start services
sudo systemctl start postgresql
sudo systemctl start redis
sudo systemctl start redquanta-mcp

# 5. Verify recovery
sleep 30
curl -f http://localhost:5891/health || exit 1

echo "Recovery completed successfully"
```

### Data Recovery

#### Lost Scan Data Recovery
```bash
# Recover from audit logs
grep "scan_completed" logs/audit.log | \
jq -r '.scan_id' | \
while read scan_id; do
    echo "Recovering scan: $scan_id"
    # Implement recovery logic
done

# Rebuild indexes
psql redquanta -c "
DROP INDEX IF EXISTS idx_scans_target;
CREATE INDEX idx_scans_target ON scans(target);
ANALYZE scans;
"
```

## Preventive Measures

### Regular Maintenance

#### Daily Tasks
- Monitor system resources
- Check service health
- Review error logs
- Backup critical data

#### Weekly Tasks
- Update security patches
- Rotate log files
- Performance analysis
- Configuration review

#### Monthly Tasks
- Security audit
- Capacity planning
- Documentation updates
- Disaster recovery testing

### Monitoring Setup

#### Prometheus Integration
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'redquanta-mcp'
    static_configs:
      - targets: ['localhost:5891']
    metrics_path: '/metrics'
```

#### Grafana Dashboards
```json
{
  "dashboard": {
    "title": "RedQuanta MCP Health",
    "panels": [
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_request_duration_seconds[5m])"
          }
        ]
      }
    ]
  }
}
```

## Contact and Support

### Support Channels
- **GitHub Issues**: Technical problems and bug reports
- **Documentation**: Comprehensive guides and troubleshooting
- **Community Forum**: User discussions and solutions
- **Enterprise Support**: Priority support for enterprise customers

### Escalation Process
1. **Level 1**: Self-service troubleshooting using this guide
2. **Level 2**: Community support and documentation
3. **Level 3**: Professional support and development team
4. **Level 4**: Emergency response and escalation

## Next Steps

- [Performance Optimization](../development/performance.md)
- [Monitoring Setup](monitoring.md)
- [Security Hardening](../security/model.md)