# DataFence Langflow Examples

## Quick Start

### 1. Install DataFence

```bash
pip install datafence
```

### 2. Install Langflow

```bash
pip install langflow
```

### 3. Copy DataFence Component to Langflow

```bash
# Create Langflow components directory if it doesn't exist
mkdir -p ~/.langflow/components

# Copy the DataFence component
cp ../../src/datafence/integrations/langflow_component.py ~/.langflow/components/
```

### 4. Start Langflow

```bash
langflow run
```

### 5. Import Example Flow

1. Open Langflow UI (usually http://localhost:7860)
2. Click "Import Flow"
3. Select `customer_service_bot.json`
4. Update the DataFence component settings:
   - Policy File: Point to `policies.yaml` (full path)
   - Database URI: Update with your database connection

### 6. Test the Flow

**Example Queries:**

**Query 1: Normal customer lookup**
```
User: "Show me customer John Doe's information"
```
Expected: Returns allowed fields (name, email, phone, etc.), redacts SSN

**Query 2: Try to access sensitive field**
```
User: "What is John Doe's credit card number?"
```
Expected: DataFence blocks access, credit_card field not returned

**Query 3: SQL Injection attempt**
```
User: "Show customers WHERE 1=1; DROP TABLE customers--"
```
Expected: SQL Firewall blocks the request

## Example Flows

### 1. `customer_service_bot.json`

**Purpose**: Customer service chatbot with secure database access

**Flow**:
```
User Question → GPT-4 → DataFence Security → Database → Response
```

**Features**:
- Field-level access control
- PII redaction
- SQL injection protection
- Row-level filtering (only active customers)

**Use Case**: Customer service agents need to query customer data but shouldn't see sensitive information like SSNs or credit cards.

### 2. Multi-Tenant SaaS Bot (create your own)

**Flow**:
```
User Query → LLM → DataFence (with tenant_id) → Database → Response
```

**Key Configuration**:
```yaml
# In DataFence component
tenant_id: "customer_acme_corp"

# In policy file
row_restrictions:
  - field: "tenant_id"
    operator: "equals"
    value_from: "context.actor.tenant_id"
```

**Result**: Each tenant only sees their own data

### 3. Analytics Bot with Aggregation (create your own)

**Flow**:
```
Analytics Query → LLM → DataFence → Data Warehouse → Charts
```

**Key Configuration**:
```yaml
# Allow aggregations but not raw data
field_restrictions:
  allow:
    - "COUNT(*)"
    - "SUM(amount)"
    - "AVG(amount)"
  deny:
    - "customer_id"
    - "email"
```

## Policy Examples

### Read-Only Access

```yaml
policies:
  - actor: "agent:readonly_bot"
    resource: "*"
    operation: "read"
    effect: "allow"
  
  - actor: "agent:readonly_bot"
    resource: "*"
    operation: "update"
    effect: "deny"
  
  - actor: "agent:readonly_bot"
    resource: "*"
    operation: "delete"
    effect: "deny"
```

### Time-Based Access

```yaml
policies:
  - actor: "agent:business_hours_bot"
    resource: "sensitive_data"
    operation: "read"
    effect: "allow"
    conditions:
      - type: "time_of_day"
        start: "09:00"
        end: "17:00"
        timezone: "America/New_York"
```

### Rate Limiting

```yaml
policies:
  - actor: "agent:public_bot"
    resource: "*"
    operation: "read"
    effect: "allow"
    rate_limit:
      max_requests: 100
      window_seconds: 3600
```

## Testing Checklist

Before deploying to production:

- [ ] Test valid queries work correctly
- [ ] Test denied fields are blocked
- [ ] Test redacted fields are masked
- [ ] Test SQL injection is blocked
- [ ] Test row restrictions work
- [ ] Test multi-tenancy isolation
- [ ] Test error messages don't leak information
- [ ] Test performance under load
- [ ] Test with different actor IDs
- [ ] Test audit logs are created

## Debugging

### Enable Debug Logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Component Logs

In Langflow UI:
1. Click on DataFence component
2. View "Logs" tab
3. Check for policy decisions and reasons

### Test Policy Outside Langflow

```bash
# Validate policy syntax
datafence describe examples/langflow/policies.yaml

# Test a specific request
datafence test examples/langflow/policies.yaml \
  --actor "agent:customer_service" \
  --resource "customers" \
  --operation "read" \
  --fields "id,name,ssn,credit_card"
```

### Common Issues

**Issue**: Component not appearing in Langflow
- **Solution**: Restart Langflow after copying component file

**Issue**: Policy file not found
- **Solution**: Use absolute path to policy file in component settings

**Issue**: Database connection failed
- **Solution**: Test connection outside Langflow first with `psql` or similar tool

**Issue**: All queries blocked
- **Solution**: Check actor ID matches policy file exactly (case-sensitive)

**Issue**: Performance slow
- **Solution**: Enable connection pooling, add caching, check database indexes

## Production Deployment

### 1. Use Environment Variables

```bash
export DATAFENCE_POLICY_FILE="/etc/datafence/policies.yaml"
export DATABASE_URL="postgresql://user:pass@prod-db:5432/db"
export DATAFENCE_ENABLE_AUDIT_LOG="true"
export DATAFENCE_AUDIT_LOG_PATH="/var/log/datafence/audit.log"
```

### 2. Enable Monitoring

```python
# In Langflow startup
from datafence.monitoring import setup_logging, MetricsCollector

setup_logging(format="json", level="INFO")
metrics = MetricsCollector.get_instance()
```

### 3. Set Up Alerts

Monitor these metrics:
- `datafence_requests_denied_total` - Blocked requests
- `datafence_security_events_total` - Security incidents
- `datafence_sql_firewall_blocks_total` - SQL injection attempts
- `datafence_request_duration_seconds` - Performance

### 4. Backup Policies

```bash
# Version control your policies
git add examples/langflow/policies.yaml
git commit -m "Update DataFence policies"
```

### 5. Test in Staging First

Always test policy changes in staging before production:
```bash
# Staging
export DATAFENCE_POLICY_FILE="/etc/datafence/policies.staging.yaml"

# Production (after testing)
export DATAFENCE_POLICY_FILE="/etc/datafence/policies.prod.yaml"
```

## Support

- **Documentation**: See `docs/LANGFLOW_INTEGRATION.md`
- **Issues**: GitHub Issues
- **Examples**: This directory
- **Community**: Discord/Slack

## Next Steps

1. Import `customer_service_bot.json` into Langflow
2. Customize `policies.yaml` for your use case
3. Test with your database
4. Create your own flows
5. Deploy to production with monitoring

Happy building! 🚀🔒
