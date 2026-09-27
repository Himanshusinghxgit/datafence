# DataFence Langflow Integration

## Overview

DataFence provides custom components for Langflow that add a security layer between LLM agents and databases.

## Flow Architecture

```
User Query 
    ↓
LLM Agent
    ↓
DataFence Security Component ← Policy Enforcement
    ↓
Database Connector (Postgres/Athena/Snowflake/etc.)
    ↓
DataFence Validation ← Result Verification
    ↓
LLM Response
```

## Installation

1. Install DataFence with Langflow dependencies:
```bash
pip install datafence[langflow]
```

2. Copy the component to Langflow custom components directory:
```bash
cp src/datafence/integrations/langflow_component.py ~/.langflow/components/
```

3. Restart Langflow:
```bash
langflow run
```

## Components

### 1. DataFence Security Component

**Purpose**: Enforce security policies on individual database requests.

**Inputs**:
- Policy File: Path to YAML policy file
- Connector Type: memory, sqlite, postgres, athena, snowflake
- Database URI: Connection string (if needed)
- Actor ID: User/agent identifier
- Tenant ID: Multi-tenancy support
- Operation: read, insert, update, delete
- Resource: Table name
- Fields: Comma-separated columns
- Filters: JSON filter conditions
- Limit: Max rows
- Enable SQL Firewall: Block SQL injection
- Enable PII Detection: Detect/redact PII

**Outputs**:
- Result: Full result with decision
- Data: Just the data rows
- Decision: Policy decision (allow/deny)

### 2. DataFence LLM Agent Wrapper

**Purpose**: Wrap entire LLM agents with DataFence security.

**Inputs**:
- Policy File: Path to YAML policy file
- Actor ID: Agent identifier
- Tenant ID: Tenant identifier

**Outputs**:
- Secured Agent: Agent configuration with security

## Example Flows

### Flow 1: Simple Query with Security

```
[User Input] 
    → [LLM (OpenAI/Claude)] 
    → [DataFence Security] 
    → [Output]
```

**Configuration**:
1. Add "Chat Input" component
2. Add "OpenAI" or "Claude" component
3. Add "DataFence Security" component:
   - Policy File: `/path/to/policies.yaml`
   - Connector Type: `postgres`
   - Database URI: `postgresql://user:pass@localhost/db`
   - Resource: `customers`
   - Fields: `id, name, email`
4. Add "Chat Output" component

### Flow 2: Agent with Database Tools

```
[User Query]
    → [LLM Agent with Tools]
    → [DataFence LLM Wrapper]
    → [Database Connector]
    → [Response]
```

**Configuration**:
1. Create LangChain agent with database tools
2. Wrap with DataFence security
3. Connect to database
4. Policy enforcement happens automatically

## Usage Examples

### Example 1: Customer Query

**Policy** (`policies.yaml`):
```yaml
policies:
  - actor: "agent:langflow"
    resource: "customers"
    operation: "read"
    effect: "allow"
    field_restrictions:
      allow:
        - id
        - name
        - email
      redact:
        - ssn
        - credit_card
```

**Flow Configuration**:
- Actor ID: `agent:langflow`
- Resource: `customers`
- Fields: `id, name, email, ssn`
- Operation: `read`

**Result**: 
- Returns `id`, `name`, `email`
- Redacts `ssn`
- Blocks `credit_card` completely

### Example 2: Multi-Tenant Access

**Policy**:
```yaml
policies:
  - actor: "agent:*"
    resource: "orders"
    operation: "read"
    effect: "allow"
    row_restrictions:
      - field: "tenant_id"
        operator: "equals"
        value_from: "context.actor.tenant_id"
```

**Flow Configuration**:
- Actor ID: `agent:sales_bot`
- Tenant ID: `tenant_123`
- Resource: `orders`
- Operation: `read`

**Result**: Only returns orders where `tenant_id = 'tenant_123'`

### Example 3: SQL Injection Protection

**Query** (malicious attempt):
```
resource: "users WHERE 1=1; DROP TABLE users--"
```

**DataFence Response**:
- SQL Firewall detects injection
- Blocks query
- Returns decision: `deny`
- Reason: `SQL injection attempt detected`

## Integration with LangChain Agents

For LangChain agents in Langflow:

```python
from datafence.integrations.langchain_tool import create_datafence_tools

# Create secured tools
tools = create_datafence_tools(
    policy_file="policies.yaml",
    connector=connector,
    actor={"id": "agent:langflow"},
)

# Use in agent
agent = create_agent(llm, tools)
```

## Environment Variables

For production connectors:

```bash
# PostgreSQL
export DATABASE_URL="postgresql://user:pass@localhost/db"

# Athena
export ATHENA_DATABASE="analytics"
export ATHENA_S3_OUTPUT="s3://bucket/results/"
export AWS_REGION="us-east-1"

# Snowflake
export SNOWFLAKE_ACCOUNT="account"
export SNOWFLAKE_USER="user"
export SNOWFLAKE_PASSWORD="password"
export SNOWFLAKE_DATABASE="db"
export SNOWFLAKE_WAREHOUSE="warehouse"
```

## Monitoring in Langflow

DataFence components expose metrics:

```python
from datafence.monitoring import MetricsCollector

# Get metrics
metrics = MetricsCollector.get_instance()
print(metrics.export_prometheus())
```

View in Langflow logs:
- Policy decisions
- Blocked requests
- Performance metrics
- Security events

## Best Practices

1. **Always use policy files**: Don't hardcode policies in flows
2. **Set appropriate actor IDs**: Use unique identifiers per agent
3. **Enable SQL firewall**: Always on for production
4. **Enable PII detection**: Always on for sensitive data
5. **Use tenant isolation**: Multi-tenant apps must set tenant_id
6. **Monitor security events**: Check logs for blocked requests
7. **Test policies**: Use CLI to validate before deploying

## Testing in Langflow

1. Create test flow with DataFence component
2. Try valid request → should succeed
3. Try unauthorized request → should block
4. Try SQL injection → should block
5. Check component outputs for decision/reasons

## Troubleshooting

### Component not showing up
- Restart Langflow after copying component
- Check `~/.langflow/components/` directory
- Verify DataFence is installed

### Connection errors
- Verify database URI format
- Check environment variables
- Test connector outside Langflow first

### Policy denials
- Check policy file syntax
- Verify actor ID matches policy
- Use `datafence describe` to inspect policies
- Check component logs for reasons

### Performance issues
- Enable caching in DataFence
- Use connection pooling
- Set appropriate limits
- Monitor with Prometheus

## Example Complete Flow

**Scenario**: Customer service chatbot with secure database access

1. **Components**:
   - Chat Input
   - OpenAI GPT-4
   - DataFence Security
   - Chat Output

2. **Configuration**:
   ```yaml
   # policies.yaml
   policies:
     - actor: "agent:customer_service"
       resource: "customers"
       operation: "read"
       effect: "allow"
       field_restrictions:
         allow: ["id", "name", "email", "account_status"]
         redact: ["ssn", "credit_card"]
       row_restrictions:
         - field: "account_status"
           operator: "equals"
           value: "active"
   ```

3. **DataFence Settings**:
   - Policy File: `policies.yaml`
   - Actor ID: `agent:customer_service`
   - Resource: `customers`
   - Enable SQL Firewall: `true`
   - Enable PII Detection: `true`

4. **Result**: 
   - Chatbot can query customer data
   - Only sees active customers
   - PII is automatically redacted
   - SQL injection blocked
   - All queries audited

## Support

For issues or questions:
- GitHub: https://github.com/yourusername/datafence
- Docs: https://datafence.readthedocs.io
- Examples: `examples/langflow/`
