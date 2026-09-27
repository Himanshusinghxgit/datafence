# Langflow + DataFence Architecture

## High-Level Flow

```
┌─────────────┐
│    User     │
│   Query     │
└──────┬──────┘
       │
       │ "Show me customer John Doe's account"
       │
       ▼
┌─────────────────────────┐
│   LLM Agent (GPT-4)     │
│                         │
│  Understands intent:    │
│  - Query customers      │
│  - Filter by name       │
│  - Get account info     │
└──────────┬──────────────┘
           │
           │ Proposes database query
           │
           ▼
┌───────────────────────────────────────┐
│    DataFence Security Component       │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  1. Load Policy                 │ │
│  │     - actors.yaml               │ │
│  │     - resources.yaml            │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  2. Authorization Check         │ │
│  │     ✓ Actor: agent:langflow     │ │
│  │     ✓ Resource: customers       │ │
│  │     ✓ Operation: read           │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  3. Field Validation            │ │
│  │     ✓ Allow: id, name, email    │ │
│  │     ⚠ Redact: ssn               │ │
│  │     ✗ Deny: credit_card         │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  4. Row Filtering               │ │
│  │     WHERE name = 'John Doe'     │ │
│  │     AND tenant_id = 'acme'      │ │
│  │     AND status = 'active'       │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  5. SQL Firewall                │ │
│  │     ✓ No DROP, DELETE           │ │
│  │     ✓ No SQL injection          │ │
│  │     ✓ Parameterized query       │ │
│  └─────────────────────────────────┘ │
│                                       │
│  Decision: ALLOW                      │
└───────────────┬───────────────────────┘
                │
                │ Approved query
                │
                ▼
┌───────────────────────────────────────┐
│   Database Connector                  │
│   (PostgreSQL/Athena/Snowflake)       │
│                                       │
│   SELECT id, name, email, ssn         │
│   FROM customers                      │
│   WHERE name = 'John Doe'             │
│     AND tenant_id = 'acme'            │
│     AND status = 'active'             │
│   LIMIT 10                            │
└───────────────┬───────────────────────┘
                │
                │ Raw results
                │
                ▼
┌───────────────────────────────────────┐
│    DataFence Result Validation        │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  1. Verify Fields                │ │
│  │     ✓ Only allowed fields        │ │
│  │     ✓ No unexpected columns      │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  2. Apply Redaction              │ │
│  │     ssn: "123-45-6789" → "***"  │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  3. PII Detection                │ │
│  │     ✓ No leaked emails           │ │
│  │     ✓ No leaked phones           │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  4. Generate Evidence            │ │
│  │     - Hash of data               │ │
│  │     - Timestamp                  │ │
│  │     - Policy applied             │ │
│  └─────────────────────────────────┘ │
│                                       │
│  ┌─────────────────────────────────┐ │
│  │  5. Audit Log                    │ │
│  │     - Actor: agent:langflow      │ │
│  │     - Resource: customers        │ │
│  │     - Result: success            │ │
│  │     - Rows returned: 1           │ │
│  └─────────────────────────────────┘ │
└───────────────┬───────────────────────┘
                │
                │ Protected results
                │
                ▼
┌───────────────────────────────────────┐
│  Protected Data                       │
│                                       │
│  {                                    │
│    "id": "123",                       │
│    "name": "John Doe",                │
│    "email": "john@example.com",       │
│    "ssn": "***"                       │
│  }                                    │
└───────────────┬───────────────────────┘
                │
                │
                ▼
┌───────────────────────────────────────┐
│   LLM Agent                           │
│                                       │
│   Formats response:                   │
│   "John Doe's account is active.      │
│    Email: john@example.com"           │
└───────────────┬───────────────────────┘
                │
                │
                ▼
┌───────────────────────────────────────┐
│   User                                │
│                                       │
│   Sees: Safe, policy-compliant data   │
│   No PII leakage, no unauthorized     │
│   access, full audit trail            │
└───────────────────────────────────────┘
```

## Component Details

### DataFence Security Component in Langflow

```
┌────────────────────────────────────────────────┐
│  DataFence Security Component                  │
│                                                │
│  Inputs:                                       │
│  ┌──────────────────────────────────────────┐ │
│  │ Policy File:  /path/to/policies.yaml     │ │
│  │ Connector:    postgres                   │ │
│  │ Database URI: postgresql://...           │ │
│  │ Actor ID:     agent:langflow             │ │
│  │ Tenant ID:    acme_corp                  │ │
│  │ Operation:    read                       │ │
│  │ Resource:     customers                  │ │
│  │ Fields:       id,name,email              │ │
│  │ Filters:      {"name": "John Doe"}       │ │
│  │ Limit:        10                         │ │
│  │ SQL Firewall: ✓ enabled                  │ │
│  │ PII Detection: ✓ enabled                 │ │
│  └──────────────────────────────────────────┘ │
│                                                │
│  Outputs:                                      │
│  ┌──────────────────────────────────────────┐ │
│  │ Result:   Full result with metadata      │ │
│  │ Data:     Just the data rows             │ │
│  │ Decision: allow/deny                     │ │
│  └──────────────────────────────────────────┘ │
└────────────────────────────────────────────────┘
```

## Security Layers

```
┌─────────────────────────────────────────────────────┐
│             Security Layers (Defense in Depth)      │
│                                                     │
│  Layer 1: Authorization                             │
│  ┌───────────────────────────────────────────────┐ │
│  │ Who is making the request?                    │ │
│  │ Are they allowed to access this resource?     │ │
│  └───────────────────────────────────────────────┘ │
│                                                     │
│  Layer 2: Resource Validation                       │
│  ┌───────────────────────────────────────────────┐ │
│  │ Does this resource exist?                     │ │
│  │ What operations are allowed?                  │ │
│  └───────────────────────────────────────────────┘ │
│                                                     │
│  Layer 3: Field-Level Security                      │
│  ┌───────────────────────────────────────────────┐ │
│  │ Which columns can be accessed?                │ │
│  │ Which should be redacted?                     │ │
│  │ Which are completely denied?                  │ │
│  └───────────────────────────────────────────────┘ │
│                                                     │
│  Layer 4: Row-Level Security                        │
│  ┌───────────────────────────────────────────────┐ │
│  │ Tenant isolation (tenant_id filter)           │ │
│  │ Custom filters (status = 'active')            │ │
│  │ Dynamic context-based filtering               │ │
│  └───────────────────────────────────────────────┘ │
│                                                     │
│  Layer 5: SQL Firewall                              │
│  ┌───────────────────────────────────────────────┐ │
│  │ Block SQL injection                           │ │
│  │ Block dangerous operations (DROP, DELETE)     │ │
│  │ Validate query structure                      │ │
│  └───────────────────────────────────────────────┘ │
│                                                     │
│  Layer 6: PII Detection                             │
│  ┌───────────────────────────────────────────────┐ │
│  │ Detect emails, phones, SSNs, credit cards     │ │
│  │ Apply redaction strategies                    │ │
│  │ Prevent PII leakage                           │ │
│  └───────────────────────────────────────────────┘ │
│                                                     │
│  Layer 7: Result Validation                         │
│  ┌───────────────────────────────────────────────┐ │
│  │ Verify returned data matches policy           │ │
│  │ Generate cryptographic evidence               │ │
│  │ Create audit trail                            │ │
│  └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Attack Prevention

### 1. SQL Injection

```
❌ Malicious Request:
   Resource: "users WHERE 1=1; DROP TABLE users--"

✓ DataFence Blocks:
   - SQL Firewall detects injection pattern
   - Returns: Decision = DENY
   - Reason: "SQL injection attempt detected"
   - Database never sees the query
```

### 2. Unauthorized Field Access

```
❌ Malicious Request:
   Fields: ["id", "name", "credit_card", "password_hash"]

✓ DataFence Blocks:
   - Field validation detects unauthorized fields
   - Returns: Only allowed fields (id, name)
   - Blocks: credit_card, password_hash
   - Logs: Security event for attempted access
```

### 3. Cross-Tenant Data Access

```
❌ Malicious Request:
   Actor: {id: "agent:acme", tenant_id: "acme"}
   Filters: {"tenant_id": "competitor"}

✓ DataFence Blocks:
   - Row-level security enforces tenant isolation
   - Rewrites query to WHERE tenant_id = 'acme'
   - User input ignored
   - Only acme's data returned
```

### 4. Excessive Data Extraction

```
❌ Malicious Request:
   Limit: 1000000

✓ DataFence Limits:
   - Policy defines max_rows: 1000
   - Overrides malicious limit
   - Enforces rate limiting
   - Logs: Attempted excessive query
```

## Example: Customer Service Chatbot

### User Query
```
"Show me John Doe's account information"
```

### LLM Processing
```javascript
{
  "intent": "query_customer",
  "entity": "John Doe",
  "fields": ["account_id", "name", "email", "status", "ssn"]
}
```

### DataFence Policy Check
```yaml
actor: "agent:customer_service"
resource: "customers"
operation: "read"
field_restrictions:
  allow: ["account_id", "name", "email", "status"]
  redact: ["ssn"]
  deny: ["credit_card", "password"]
```

### Query Execution
```sql
-- Original request (from LLM)
SELECT account_id, name, email, status, ssn
FROM customers
WHERE name = 'John Doe'

-- DataFence applies row-level security
SELECT account_id, name, email, status, ssn
FROM customers
WHERE name = 'John Doe'
  AND tenant_id = 'acme'
  AND status = 'active'
LIMIT 10
```

### Result Processing
```javascript
// Raw database result
{
  "account_id": "123",
  "name": "John Doe",
  "email": "john@acme.com",
  "status": "active",
  "ssn": "123-45-6789"
}

// After DataFence processing
{
  "account_id": "123",
  "name": "John Doe",
  "email": "john@acme.com",
  "status": "active",
  "ssn": "***-**-****"  // Redacted
}
```

### Final Response
```
"John Doe's account (ID: 123) is active. 
You can reach him at john@acme.com."
```

## Monitoring Dashboard

```
┌─────────────────────────────────────────────────┐
│  DataFence Metrics (Prometheus)                 │
├─────────────────────────────────────────────────┤
│                                                 │
│  Requests:                                      │
│    Total:    1,234,567                          │
│    Allowed:  1,234,320 (99.98%)                 │
│    Denied:   247 (0.02%)                        │
│                                                 │
│  Security Events:                               │
│    SQL Injection Attempts:    23                │
│    Unauthorized Access:       184               │
│    PII Leakage Prevented:     40                │
│                                                 │
│  Performance:                                   │
│    Avg Latency:   8.5ms                         │
│    P95 Latency:   12.3ms                        │
│    P99 Latency:   18.7ms                        │
│                                                 │
│  Top Denied Resources:                          │
│    1. credit_cards (98 attempts)                │
│    2. passwords (52 attempts)                   │
│    3. ssn (34 attempts)                         │
└─────────────────────────────────────────────────┘
```

## Summary

**DataFence in Langflow provides:**

✅ **Deterministic Security** - Policies enforce before data access
✅ **Defense in Depth** - Multiple independent security layers
✅ **Zero Trust** - Works even if LLM is compromised
✅ **Full Visibility** - Complete audit trail and monitoring
✅ **Production Ready** - Connection pooling, caching, performance optimized
✅ **Easy Integration** - Drop-in component for Langflow workflows

**The model proposes. DataFence decides. The database executes only what is allowed.**
