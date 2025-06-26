# Monitoring & Observability

Enterprise monitoring setup for RedQuanta MCP with metrics, logging, and alerting.

## Overview

RedQuanta MCP provides comprehensive observability through:
- **Metrics**: Prometheus-compatible metrics
- **Logging**: Structured JSON logging with correlation IDs
- **Tracing**: OpenTelemetry distributed tracing
- **Health Checks**: Application and dependency health monitoring

## Metrics Collection

### Prometheus Integration

#### Metrics Endpoint
```bash
# Built-in metrics endpoint
curl http://localhost:5891/metrics
```

#### Key Metrics
```prometheus
# Application Metrics
redquanta_requests_total{method, status, endpoint}
redquanta_request_duration_seconds{method, endpoint}
redquanta_active_connections
redquanta_tool_executions_total{tool, status}
redquanta_tool_execution_duration_seconds{tool}

# System Metrics
nodejs_heap_size_total_bytes
nodejs_heap_size_used_bytes
nodejs_external_memory_bytes
nodejs_gc_duration_seconds{kind}

# Security Metrics
redquanta_auth_attempts_total{status}
redquanta_path_validations_total{status}
redquanta_command_validations_total{status}
```

#### Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "redquanta_rules.yml"

scrape_configs:
  - job_name: 'redquanta-mcp'
    static_configs:
      - targets: ['localhost:5891']
    metrics_path: '/metrics'
    scrape_interval: 30s
    scrape_timeout: 10s
    
  - job_name: 'redquanta-node-exporter'
    static_configs:
      - targets: ['localhost:9100']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Grafana Dashboards

#### RedQuanta MCP Dashboard
```json
{
  "dashboard": {
    "title": "RedQuanta MCP",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(redquanta_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph", 
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(redquanta_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Tool Execution Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(redquanta_tool_executions_total{status=\"success\"}[5m]) / rate(redquanta_tool_executions_total[5m]) * 100",
            "legendFormat": "Success Rate %"
          }
        ]
      }
    ]
  }
}
```

## Logging Infrastructure

### Structured Logging Format
```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "level": "info",
  "msg": "Tool execution completed",
  "reqId": "req-abc123",
  "userId": "user-456",
  "tool": "nmap",
  "target": "192.168.1.1",
  "duration": 2.345,
  "exitCode": 0,
  "success": true
}
```

### Log Aggregation with ELK Stack

#### Filebeat Configuration
```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /app/logs/*.jsonl
  json.keys_under_root: true
  json.add_error_key: true
  
output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "redquanta-logs-%{+yyyy.MM.dd}"
  
setup.template.name: "redquanta"
setup.template.pattern: "redquanta-*"
```

#### Logstash Pipeline
```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][service] == "redquanta-mcp" {
    mutate {
      add_tag => ["redquanta"]
    }
    
    if [level] == "error" {
      mutate {
        add_tag => ["alert"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "redquanta-logs-%{+YYYY.MM.dd}"
  }
}
```

#### Kibana Visualizations
```json
{
  "visualization": {
    "title": "RedQuanta Error Rate",
    "visState": {
      "type": "line",
      "params": {
        "seriesParams": [
          {
            "data": {
              "label": "Error Rate",
              "id": "1"
            },
            "valueAxis": "ValueAxis-1",
            "drawLinesBetweenPoints": true,
            "showCircles": true
          }
        ]
      }
    }
  }
}
```

## Distributed Tracing

### OpenTelemetry Setup
```javascript
// tracing.js
const { NodeSDK } = require('@opentelemetry/sdk-node');
const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
const { JaegerExporter } = require('@opentelemetry/exporter-jaeger');

const sdk = new NodeSDK({
  instrumentations: [getNodeAutoInstrumentations()],
  traceExporter: new JaegerExporter({
    endpoint: 'http://jaeger:14268/api/traces',
  }),
  serviceName: 'redquanta-mcp',
});

sdk.start();
```

### Trace Context Propagation
```typescript
// Example trace spans
import { trace } from '@opentelemetry/api';

const tracer = trace.getTracer('redquanta-mcp');

async function executeNmapScan(target: string) {
  const span = tracer.startSpan('nmap_scan', {
    attributes: {
      'tool.name': 'nmap',
      'scan.target': target
    }
  });

  try {
    // Tool execution
    const result = await runNmap(target);
    span.setAttributes({
      'scan.success': result.success,
      'scan.duration': result.duration
    });
    return result;
  } catch (error) {
    span.recordException(error);
    span.setStatus({ code: SpanStatusCode.ERROR });
    throw error;
  } finally {
    span.end();
  }
}
```

## Health Monitoring

### Health Check Endpoints
```bash
# Application health
curl http://localhost:5891/health

# Dependency health 
curl http://localhost:5891/health/deep

# Readiness probe
curl http://localhost:5891/ready

# Liveness probe  
curl http://localhost:5891/alive
```

### Health Check Response
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00.123Z",
  "uptime": 86400,
  "version": "0.3.0",
  "checks": {
    "database": { "status": "healthy", "responseTime": 12 },
    "filesystem": { "status": "healthy", "freeSpace": "85%" },
    "memory": { "status": "healthy", "usage": "67%" },
    "tools": {
      "nmap": { "status": "available", "version": "7.95" },
      "masscan": { "status": "available", "version": "1.3.2" }
    }
  }
}
```

## Alerting Rules

### Prometheus Alert Rules
```yaml
# redquanta_rules.yml
groups:
- name: redquanta.rules
  rules:
  - alert: HighErrorRate
    expr: rate(redquanta_requests_total{status=~"5.."}[5m]) > 0.1
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High error rate detected"
      description: "Error rate is {{ $value }}% over the last 5 minutes"

  - alert: HighResponseTime
    expr: histogram_quantile(0.95, rate(redquanta_request_duration_seconds_bucket[5m])) > 2
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "High response time"
      description: "95th percentile response time is {{ $value }}s"

  - alert: ServiceDown
    expr: up{job="redquanta-mcp"} == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "RedQuanta MCP service is down"
      description: "Service has been down for more than 1 minute"

  - alert: ToolExecutionFailures
    expr: rate(redquanta_tool_executions_total{status="failure"}[5m]) > 0.05
    for: 3m
    labels:
      severity: warning
    annotations:
      summary: "High tool execution failure rate"
      description: "Tool failure rate is {{ $value }}% over the last 5 minutes"
```

### Alertmanager Configuration
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'localhost:587'
  smtp_from: 'alerts@redquanta.com'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'web.hook'

receivers:
- name: 'web.hook'
  email_configs:
  - to: 'admin@redquanta.com'
    subject: 'RedQuanta Alert: {{ .GroupLabels.alertname }}'
    body: |
      {{ range .Alerts }}
      Alert: {{ .Annotations.summary }}
      Description: {{ .Annotations.description }}
      {{ end }}
  
  slack_configs:
  - api_url: 'YOUR_SLACK_WEBHOOK_URL'
    channel: '#alerts'
    title: 'RedQuanta Alert'
    text: '{{ range .Alerts }}{{ .Annotations.summary }}{{ end }}'
```

## Performance Monitoring

### APM Integration
```typescript
// apm.ts
import apm from 'elastic-apm-node';

const apmAgent = apm.start({
  serviceName: 'redquanta-mcp',
  secretToken: process.env.ELASTIC_APM_SECRET_TOKEN,
  serverUrl: process.env.ELASTIC_APM_SERVER_URL,
  environment: process.env.NODE_ENV,
  captureBody: 'errors'
});

export { apmAgent };
```

### Custom Metrics
```typescript
// metrics.ts
import { register, Counter, Histogram, Gauge } from 'prom-client';

export const httpRequestsTotal = new Counter({
  name: 'redquanta_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'status', 'endpoint']
});

export const httpRequestDuration = new Histogram({
  name: 'redquanta_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'endpoint'],
  buckets: [0.1, 0.5, 1, 2, 5, 10]
});

export const activeConnections = new Gauge({
  name: 'redquanta_active_connections',
  help: 'Number of active connections'
});

register.registerMetric(httpRequestsTotal);
register.registerMetric(httpRequestDuration);
register.registerMetric(activeConnections);
```

## Docker Compose Monitoring Stack
```yaml
version: '3.8'

services:
  redquanta-mcp:
    image: redquanta/mcp:latest
    ports:
      - "5891:5891"
    depends_on:
      - prometheus
      - grafana

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - ./redquanta_rules.yml:/etc/prometheus/redquanta_rules.yml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana

  alertmanager:
    image: prom/alertmanager:latest
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml

  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"
      - "14268:14268"

volumes:
  grafana-storage:
```

## Monitoring Runbook

### Daily Checks
- [ ] Review Grafana dashboards
- [ ] Check alert status in Alertmanager
- [ ] Verify log ingestion in Kibana
- [ ] Monitor resource utilization

### Weekly Reviews
- [ ] Analyze performance trends
- [ ] Review and update alert thresholds
- [ ] Check for new monitoring requirements
- [ ] Update dashboards based on usage patterns

### Incident Response
1. **Alert Received** → Check Grafana for context
2. **Investigate** → Use logs and traces to identify root cause
3. **Mitigate** → Apply immediate fixes
4. **Document** → Update runbooks and improve monitoring

## Next Steps

- [Troubleshooting Guide](troubleshooting.md)
- [Performance Tuning](../development/performance.md)
- [Security Monitoring](../security/audit-logging.md) 