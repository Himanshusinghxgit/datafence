# DataFence Architecture

## Overview

DataFence creates a deterministic security boundary between probabilistic AI systems and enterprise data. The core principle is simple:

> **The model proposes. DataFence decides.**

## Architecture Diagram

```text
┌─────────────────────────────────────────┐
│          AI/LLM/Agent System            │
│                                         │
│  • GPT / Claude / Gemini / Llama        │
│  • LangChain / LlamaIndex               │
│  • Custom agents / MCP clients          │
└──────────────┬──────────────────────────┘
               │
               │ Natural Language
               ▼
        ┌──────────────┐
        │  NL → Struct │  ← Intent conversion
        └──────┬───────┘     (application layer)
               │
               │ Structured Request
               ▼
┌──────────────────────────────────────────┐
│           DATAFENCE BOUNDARY             │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  1. Request Normalization          │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  2. Actor Authentication           │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  3. Policy Resolution              │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  4. Authorization                  │ │
│  │     • Resource access              │ │
│  │     • Operation check              │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  5. Field Validation               │ │
│  │     • Column-level security        │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  6. Row Validation                 │ │
│  │     • Tenant isolation              │ │
│  │     • Data scoping                 │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  7. Query Validation               │ │
│  │     • SQL parsing                  │ │
│  │     • Dangerous operation blocking │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  8. Connector Execution            │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  9. Result Validation              │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  10. Provenance Generation         │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  11. Evidence Generation           │ │
│  └────────────────────────────────────┘ │
│  ┌────────────────────────────────────┐ │
│  │  12. Audit Logging                 │ │
│  └────────────────────────────────────┘ │
│                                          │
└──────────────┬───────────────────────────┘
               │
               │ Validated Query
               ▼
┌──────────────────────────────────────────┐
│        Enterprise Data Systems           │
│                                          │
│  • PostgreSQL                            │
│  • MySQL                                 │
│  • Amazon Athena                         │
│  • Snowflake                             │
│  • BigQuery                              │
│  • S3 Data Lakes                         │
│  • Internal APIs                         │
└──────────────────────────────────────────┘
```

## Core Components

### 1. Request Models (`core/request.py`)

All requests must be structured and typed. The `ExecutionRequest` model defines:

- **Actor**: Who is making the request
- **Operation**: What operation (READ, INSERT, UPDATE, DELETE, etc.)
- **Resource**: What resource (table, dataset, API)
- **Fields**: Which fields/columns
- **Filters**: Row-level filters
- **Limits**: Query limits

### 2. Policy Engine (`policy/`)

The policy engine provides deterministic enforcement:

- **Models** (`models.py`): Policy structure (resources, operations, fields, row filters, limits)
- **Loader** (`loader.py`): YAML policy loading and validation
- **Evaluator** (`evaluator.py`): Request evaluation against policies

Policies are:
- **Deterministic**: Same request + policy = same decision
- **Testable**: Can be unit tested
- **Versioned**: Track policy versions
- **Inspectable**: Human-readable YAML

### 3. Connectors (`connectors/`)

Connectors execute validated requests against data systems:

- **Base** (`base.py`): Abstract connector interface
- **Memory** (`memory.py`): In-memory connector for testing
- **SQLite** (`sqlite.py`): Local development connector
- **Future**: PostgreSQL, Athena, Snowflake, etc.

### 4. Security (`security/` - planned)

Security controls include:

- **Authorization**: Actor-based access control
- **Tenant Isolation**: Multi-tenant data separation
- **PII Detection**: Sensitive data identification
- **Query Firewall**: SQL validation and rewriting

### 5. Provenance (`provenance/`)

Track data lineage:

- **Source**: Which system
- **Resource**: Which table/dataset
- **Policy**: Which policy version
- **Actor**: Who accessed
- **Query Hash**: What query

### 6. Evidence (`provenance/models.py`)

Cryptographic proof of policy compliance:

- Request hash
- Query hash
- Result hash
- Checks performed
- Verification status

**Important**: This is NOT proof that the LLM is correct. This IS proof that the result was produced through a policy-compliant execution path.

### 7. Audit (`audit/`)

Complete audit trail:

- Event ID
- Actor information
- Operation and resource
- Decision (allow/deny)
- Policy version
- Timestamp

## Execution Pipeline

```python
def execute(request):
    # 1. Normalize
    request = normalize(request)
    
    # 2. Create context
    context = create_context(request)
    
    # 3. Evaluate policy
    decision = policy.evaluate(request, context)
    
    # 4. Check decision
    if decision.status != ALLOW:
        return denied_result(decision)
    
    # 5. Execute
    data = connector.execute(request, allowed_fields)
    
    # 6. Generate provenance
    provenance = generate_provenance(request, policy, data)
    
    # 7. Generate evidence
    evidence = generate_evidence(request, decision, provenance)
    
    # 8. Audit
    audit_log(request, decision, provenance)
    
    # 9. Return
    return success_result(data, decision, provenance, evidence)
```

## Security Properties

### Fail-Closed

Default behavior: deny on security failures.

```python
try:
    validate_and_execute()
except SecurityError:
    return DENY  # Fail closed
```

### Deterministic

Same input → Same output:

```text
Request + Policy + Context → Decision
```

No LLM calls in the security boundary.

### Explainable

Every decision includes:

- Status (ALLOW/DENY/REDACT/REQUIRE_APPROVAL)
- Reasons (if denied)
- Checks performed
- Policy version

### Auditable

Every request generates:

- Audit event
- Provenance record
- Evidence object

## Policy Enforcement

### Column-Level Security

```yaml
fields:
  allow:
    - user_id
    - username
    - email
  deny:
    - password_hash
    - api_key
    - ssn
```

### Row-Level Security

```yaml
row_filters:
  customer_id: "{{ actor.customer_id }}"
```

Enforces tenant isolation: Actor with `customer_id=123` cannot access `customer_id=456`.

### Operation Control

```yaml
operations:
  allow:
    - read
  deny:
    - insert
    - update
    - delete
    - drop
```

### Limits

```yaml
limits:
  max_rows: 1000
  max_date_range_days: 90
```

## Integration Patterns

### Pattern 1: Agent Tool

```python
# Agent defines tool
def query_transactions(customer_id, date_from, date_to):
    result = datafence.execute({
        "actor": {...},
        "operation": "read",
        "resource": "transactions",
        "filters": {
            "customer_id": customer_id,
            "date_from": date_from,
            "date_to": date_to
        }
    })
    return result.data if result.verified else None
```

### Pattern 2: API Gateway

```python
@app.post("/api/query")
def query_endpoint(request):
    # Convert API request to DataFence request
    df_request = convert_to_datafence_request(request)
    
    # Execute through DataFence
    result = datafence.execute(df_request)
    
    return result
```

### Pattern 3: MCP Server (Future)

```python
# MCP tool wrapped by DataFence
@mcp.tool()
def read_data(resource, filters):
    return datafence.execute({...})
```

## Design Principles

1. **Security first**: Never sacrifice security for convenience
2. **Fail closed**: Default to denial on failures
3. **Deterministic**: No probabilistic security
4. **Explainable**: Every decision has reasons
5. **Auditable**: Complete audit trail
6. **Model agnostic**: Works with any AI system
7. **Minimal dependencies**: Lightweight core
8. **Extensible**: Clean connector interface

## Threat Model

See [threat-model.md](threat-model.md) for complete threat analysis.

Protected against:

- Unauthorized column access
- Unauthorized row access
- Cross-tenant data access
- Dangerous SQL operations
- Excessive query scope
- PII leakage
- Privilege escalation

**Critical**: DataFence enforces security even if the LLM is compromised.
