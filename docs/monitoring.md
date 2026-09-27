## Monitoring Guide

Comprehensive guide for monitoring DataFence in production.

## Overview

DataFence provides built-in monitoring capabilities:

- **Metrics**: Prometheus-compatible metrics
- **Logging**: Structured JSON logging
- **Health Checks**: Liveness and readiness probes
- **Audit Logs**: Security event tracking
- **Performance Monitoring**: Request timing and statistics

## Metrics

### Prometheus Metrics

DataFence exposes Prometheus-compatible metrics for monitoring.

#### Setup

```python
from datafence import DataFence
from datafence.monitoring import get_metrics_collector

fence = DataFence.from_yaml("policy.yaml", connector)
collector = get_metrics_collector()

# Execute requests
result = fence.execute(request)

# Export metrics
print(collector.export_prometheus())
```

#### Available Metrics

**Request Counters:**
- `datafence_requests_total` - Total requests processed
- `datafence_requests_allowed` - Requests allowed by policy
- `datafence_requests_denied` - Requests denied by policy
- `datafence_requests_errors` - Requests that resulted in errors

**Security Counters:**
- `datafence_sql_firewall_blocks` - Queries blocked by SQL firewall
- `datafence_pii_detections` - PII instances detected
- `datafence_pii_redactions` - PII instances redacted

**Performance Histograms:**
- `datafence_request_duration_seconds` - Full request processing time
- `datafence_policy_eval_duration_seconds` - Policy evaluation time
- `datafence_connector_duration_seconds` - Database query time

#### Metrics Middleware

Automatically collect metrics for all requests:

```python
from datafence.monitoring.metrics import MetricsMiddleware

middleware = MetricsMiddleware(fence)
result = middleware.execute(request)

# Metrics are automatically recorded
```

#### Prometheus Integration

Expose metrics at `/metrics` endpoint:

```python
from fastapi import FastAPI
from datafence.monitoring import get_metrics_collector

app = FastAPI()

@app.get("/metrics")
def metrics():
    collector = get_metrics_collector()
    return Response(
        content=collector.export_prometheus(),
        media_type="text/plain"
    )
```

### Grafana Dashboard

Example Grafana queries:

**Request Rate:**
```promql
rate(datafence_requests_total[5m])
```

**Success Rate:**
```promql
rate(datafence_requests_allowed[5m]) / rate(datafence_requests_total[5m])
```

**Average Latency:**
```promql
rate(datafence_request_duration_seconds_sum[5m]) / rate(datafence_request_duration_seconds_count[5m])
```

**p95 Latency:**
```promql
histogram_quantile(0.95, rate(datafence_request_duration_seconds_bucket[5m]))
```

## Logging

### Structured Logging

DataFence supports structured JSON logging for production.

#### Setup

```python
from datafence.monitoring import setup_logging, get_logger

# Setup JSON logging
setup_logging(level="INFO", format="json", output="stdout")

# Get logger
logger = get_logger(__name__)

# Log with context
logger.info(
    "Request processed",
    extra={
        "actor_id": "user:123",
        "tenant_id": "acme",
        "resource": "transactions",
        "decision": "allow"
    }
)
```

Output:
```json
{
  "timestamp": "2024-01-15T10:30:00.123Z",
  "level": "INFO",
  "logger": "datafence.engine",
  "message": "Request processed",
  "actor_id": "user:123",
  "tenant_id": "acme",
  "resource": "transactions",
  "decision": "allow"
}
```

#### Logging Middleware

Automatically log all requests:

```python
from datafence.monitoring.logging import LoggingMiddleware

middleware = LoggingMiddleware(fence)
result = middleware.execute(request)

# Logs are automatically generated
```

### Audit Logging

Separate audit logs for security and compliance:

```python
from datafence.monitoring.logging import AuditLogger

audit = AuditLogger(output_file="datafence-audit.log")

# Log data access
audit.log_access(
    actor_id="user:123",
    tenant_id="acme",
    operation="read",
    resource="transactions",
    decision="allow",
    fields=["id", "amount"],
    row_count=10
)

# Log policy violation
audit.log_policy_violation(
    actor_id="agent:bot",
    tenant_id="acme",
    operation="read",
    resource="transactions",
    reasons=["Field 'ssn' is denied"]
)

# Log SQL injection attempt
audit.log_sql_injection_attempt(
    actor_id="user:suspicious",
    tenant_id="acme",
    query="SELECT * FROM users WHERE id='1' OR '1'='1'",
    reason="SQL injection pattern detected"
)

# Log PII access
audit.log_pii_access(
    actor_id="user:123",
    tenant_id="acme",
    resource="customers",
    pii_types=["email", "phone"],
    redacted=True
)
```

### Log Aggregation

Forward logs to aggregation systems:

**Elasticsearch/Kibana:**
```bash
# Filebeat configuration
filebeat.inputs:
- type: log
  paths:
    - /var/log/datafence/*.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
```

**CloudWatch Logs:**
```python
import watchtower

handler = watchtower.CloudWatchLogHandler(log_group="datafence")
logger.addHandler(handler)
```

**Datadog:**
```python
from datadog import initialize, statsd

initialize(api_key="YOUR_KEY", app_key="YOUR_APP_KEY")

# Log to Datadog
statsd.increment('datafence.requests.total')
```

## Health Checks

### Basic Health Check

```python
from datafence.monitoring import HealthChecker

checker = HealthChecker(fence)
health = checker.check_all()

print(health)
# {
#   "status": "healthy",
#   "uptime_seconds": 3600.5,
#   "checks": {
#     "uptime": {"status": "healthy", "message": "..."},
#     "policy": {"status": "healthy", "message": "..."},
#     "connector": {"status": "healthy", "message": "..."}
#   }
# }
```

### Kubernetes Probes

#### Liveness Probe

Checks if the service is alive (not deadlocked):

```python
from datafence.monitoring.health import LivenessChecker

liveness = LivenessChecker()

@app.get("/healthz")
def liveness_check():
    return liveness.check()
```

Kubernetes configuration:
```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 10
```

#### Readiness Probe

Checks if the service is ready to accept traffic:

```python
from datafence.monitoring.health import ReadinessChecker

readiness = ReadinessChecker(fence)

@app.get("/ready")
def readiness_check():
    result = readiness.check()
    status_code = 200 if result["ready"] else 503
    return Response(content=json.dumps(result), status_code=status_code)
```

Kubernetes configuration:
```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 5
```

### FastAPI Integration

```python
from fastapi import FastAPI
from datafence.monitoring.health import create_health_endpoint

app = FastAPI()

# Auto-configured health endpoint
health_endpoint = create_health_endpoint(fence)
app.get("/health")(health_endpoint)
```

## Performance Monitoring

### Request Timing

Track request performance:

```python
from datafence.optimization import get_performance_monitor

monitor = get_performance_monitor()

# Timing is automatically recorded
result = fence.execute(request)

# Get statistics
stats = monitor.get_stats("request_execution")
print(f"Average: {stats['avg']:.2f}s")
print(f"p95: {stats['p95']:.2f}s")
```

### Custom Metrics

Add custom metrics:

```python
from datafence.monitoring import get_metrics_collector

collector = get_metrics_collector()

# Register custom counter
collector.register_counter("my_custom_metric", "My custom metric")

# Increment
collector.inc_counter("my_custom_metric")

# Register custom histogram
collector.register_histogram("my_latency", "My latency metric")

# Observe value
collector.observe_histogram("my_latency", 0.150)
```

## Alerting

### Prometheus Alerts

Example alert rules:

```yaml
groups:
- name: datafence
  rules:
  # High error rate
  - alert: DataFenceHighErrorRate
    expr: rate(datafence_requests_errors[5m]) > 0.1
    for: 5m
    annotations:
      summary: "High error rate in DataFence"

  # High denial rate
  - alert: DataFenceHighDenialRate
    expr: rate(datafence_requests_denied[5m]) / rate(datafence_requests_total[5m]) > 0.5
    for: 10m
    annotations:
      summary: "High policy denial rate"

  # High latency
  - alert: DataFenceHighLatency
    expr: histogram_quantile(0.95, rate(datafence_request_duration_seconds_bucket[5m])) > 0.5
    for: 10m
    annotations:
      summary: "p95 latency above 500ms"

  # SQL injection attempts
  - alert: DataFenceSQLInjection
    expr: increase(datafence_sql_firewall_blocks[1h]) > 10
    annotations:
      summary: "Multiple SQL injection attempts detected"
```

### Log-Based Alerts

Alert on security events:

```json
{
  "alert": "SQL Injection Attempt",
  "query": "event_type:sql_injection_attempt",
  "threshold": "count > 5 in 1 hour"
}
```

## Dashboards

### Example Grafana Dashboard

Key panels:

1. **Request Rate** - Requests per second
2. **Success Rate** - Percentage of allowed requests
3. **Error Rate** - Percentage of errors
4. **Latency** - p50, p95, p99 latencies
5. **Security Events** - SQL firewall blocks, PII detections
6. **Resource Usage** - By tenant, resource, actor

### Example Datadog Dashboard

```python
{
  "title": "DataFence Overview",
  "widgets": [
    {
      "title": "Request Rate",
      "type": "timeseries",
      "query": "rate(datafence.requests.total{*}.as_count())"
    },
    {
      "title": "Policy Decisions",
      "type": "query_value",
      "query": "sum:datafence.requests.allowed{*}.as_count()"
    }
  ]
}
```

## Troubleshooting

### High Latency

Check:
1. Database performance (connector latency)
2. PII detection overhead (disable if not needed)
3. Complex policies (simplify if possible)
4. Connection pool size (increase if needed)

### High Denial Rate

Check:
1. Policy configuration (too restrictive?)
2. Actor permissions (correct tenant_id?)
3. Field restrictions (requesting denied fields?)

### Memory Usage

Monitor:
1. Schema cache size (use `clear_schema_cache()` if needed)
2. Query cache size (adjust max_size)
3. Log buffer size (rotate logs regularly)

## Best Practices

1. **Use Structured Logging** - JSON format for easy parsing
2. **Export Metrics** - Expose `/metrics` endpoint for Prometheus
3. **Set Up Alerts** - High error rate, high latency, security events
4. **Dashboard Creation** - Key metrics visible at a glance
5. **Audit Logging** - Separate logs for compliance
6. **Health Checks** - Kubernetes liveness/readiness probes
7. **Performance Monitoring** - Track latency trends
8. **Log Rotation** - Prevent disk space issues
9. **Retention Policies** - Keep metrics for 30+ days
10. **Security Monitoring** - Alert on suspicious patterns

## Next Steps

- Set up Prometheus scraping
- Create Grafana dashboards
- Configure log aggregation
- Set up alerting rules
- Review audit logs regularly
