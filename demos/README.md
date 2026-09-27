# DataFence Killer Demo

**30-second proof of deterministic authorization.**

## The Core Guarantee

> Even if the AI agent is completely compromised, it **cannot** use DataFence to access data or perform operations outside the policy.

## What This Demo Proves

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  UNTRUSTED AI REQUEST                                       │
│         ↓                                                   │
│  Policy Evaluation                                          │
│         ↓                                                   │
│  ExecutionPlan (what DataFence authorizes)                  │
│         ↓                                                   │
│  Connector (executes ONLY the plan)                         │
│         ↓                                                   │
│  Result Validation                                          │
│         ↓                                                   │
│  Verified Result                                            │
│                                                             │
│  The database NEVER executes LLM-generated SQL directly.    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Run the Demo

```bash
cd demos
python killer_demo.py
```

## The 6 Scenarios

### 1. Normal Request ✅

**User**: "Show me my recent transactions"

**LLM Proposes**:
```
Resource: transactions
Fields: id, merchant, amount, timestamp
```

**DataFence Decision**: ALLOW

**ExecutionPlan**:
```python
{
  "resource": "transactions",
  "operation": "read",
  "selected_fields": ["id", "merchant", "amount", "timestamp"],
  "enforced_filters": {"tenant_id": "tenant_a"},
  "limit": 100,
  "policy_version": "banking-demo-v1"
}
```

**Result**: Data returned, evidence generated ✅

---

### 2. SELECT * ⚠️

**LLM Proposes**:
```sql
SELECT * FROM transactions
```

**DataFence Does NOT Execute This SQL**

Instead, DataFence creates an ExecutionPlan:
```python
{
  "selected_fields": ["id", "merchant", "amount", "timestamp"],
  # NOT: card_number (denied by policy)
}
```

**Key Point**: The database executes DataFence's plan, NOT the LLM's `SELECT *`

**Result**: Only authorized fields returned ✅

---

### 3. Sensitive Field ❌

**LLM Requests**:
```
Fields: ["id", "amount", "card_number"]
```

**DataFence Decision**: DENY

**Reason**: "Requested fields are denied: card_number"

**Key Point**: The database **NEVER** received this request. Policy blocked it before execution.

**Result**: Request denied, no data leaked ✅

---

### 4. Cross-Tenant Attack ❌

**Actor**: tenant_a

**LLM Proposes**:
```
Filters: {}  # No tenant filter!
```

**DataFence Enforces**:
```python
{
  "enforced_filters": {"tenant_id": "tenant_a"}
}
```

**Key Point**: The LLM **CANNOT** override tenant isolation. DataFence adds the tenant filter independently.

**Result**: Only tenant_a's data returned ✅

---

### 5. Destructive Operation ❌

**LLM Proposes**:
```sql
DELETE FROM transactions WHERE id = 1
```

**DataFence Decision**: DENY

**Reason**: "Operation delete is explicitly denied"

**Key Point**: The database **NEVER** received the DELETE. Policy blocked it at the boundary.

**Result**: Data is safe ✅

---

### 6. Result Validation 🛡️

**Scenario**: Connector is compromised (returns unauthorized fields)

**LLM Requests**: `["id", "merchant", "amount"]`

**Malicious Connector Adds**: `card_number`, `ssn`

**DataFence Result Validation**: CATCHES IT

**Decision**: DENY

**Reason**: "Result contains unauthorized fields"

**Key Point**: Security exists on **BOTH** sides:
- Request enforcement (before execution)
- Result validation (after execution)

**Result**: Malicious data blocked ✅

---

## What Makes This a "Killer Demo"

### 1. **It's Local**
- SQLite database
- No external services
- Runs in seconds
- Deterministic results

### 2. **It's Complete**
- Creates database with realistic data
- 2 tenants with sensitive fields
- Real policy enforcement
- Full evidence trail

### 3. **It Proves the Core**

Not "7 security layers" or "10,000 lines of code."

Just one thing:

> **The database executes DataFence's authorized ExecutionPlan, not the LLM's untrusted request.**

### 4. **It's Adversarial**

Every scenario tests what happens when:
- LLM requests too much (SELECT *)
- LLM requests denied fields
- LLM tries cross-tenant access
- LLM attempts destructive operations
- Connector is malicious

### 5. **It Shows the Contract**

Every allowed request shows:

```python
ExecutionPlan:
  execution_id: "exec_a1b2c3d4"
  selected_fields: [...]
  enforced_filters: {...}
  policy_version: "banking-demo-v1"
  
Evidence:
  execution_id: "exec_a1b2c3d4"
  policy_version: "banking-demo-v1"
  timestamp: "2024-01-16T10:30:00"
```

This is the **proof** that security was enforced.

---

## The Architecture

```
┌──────────────────────────────────────────────────────────┐
│                       AI Agent                           │
│                                                          │
│  "Show me transactions"                                  │
│  "Delete old records"                                    │
│  "SELECT * FROM users"                                   │
│                                                          │
└────────────────────┬─────────────────────────────────────┘
                     │
                     │ Untrusted Request
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│                  DataFence Boundary                      │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 1. Parse Request                                   │ │
│  │    Actor + Intent → Request                        │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 2. Evaluate Policy                                 │ │
│  │    Check: operation, fields, resource              │ │
│  │    Decision: ALLOW / DENY                          │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 3. Create ExecutionPlan                            │ │
│  │    Authorized fields only                          │ │
│  │    Enforced filters (tenant_id)                    │ │
│  │    Enforced limits                                 │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 4. Execute Plan                                    │ │
│  │    connector.execute_plan(plan)                    │ │
│  │    NOT: execute_sql(llm_sql)                       │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 5. Validate Result                                 │ │
│  │    Check: no unauthorized fields                   │ │
│  │    Check: row count within limit                   │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 6. Generate Evidence                               │ │
│  │    execution_id, policy_version, timestamp         │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
└────────────────────┬─────────────────────────────────────┘
                     │
                     │ Verified Result
                     │
                     ▼
┌──────────────────────────────────────────────────────────┐
│                    Database                              │
│                                                          │
│  Executes:                                               │
│    SELECT id, merchant, amount                           │
│    FROM transactions                                     │
│    WHERE tenant_id = :tenant_id                          │
│    LIMIT 100                                             │
│                                                          │
│  NOT: LLM's raw SQL                                      │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Security Invariants

The demo proves these guarantees:

1. ✅ **Unauthorized field** → Never reaches connector
2. ✅ **Unauthorized row** → Never returned (tenant isolation)
3. ✅ **Unauthorized tenant** → Never accessed
4. ✅ **Unauthorized operation** → Never reaches connector
5. ✅ **Missing policy** → Fails closed (DENY)
6. ✅ **Invalid policy** → Fails closed (DENY)
7. ✅ **LLM SQL** → Never executed directly
8. ✅ **Malicious connector** → Caught by result validation
9. ✅ **Actor identity** → Cannot be overridden
10. ✅ **Policy version** → Recorded in evidence
11. ✅ **Execution ID** → Unique for every request
12. ✅ **Allowed request** → Full provenance
13. ✅ **Denied request** → Auditable decision

---

## The Fundamental Difference

### ❌ What DataFence is NOT:

```python
# WRONG
llm_sql = agent.generate_sql("Show me transactions")
results = database.execute(llm_sql)  # DANGEROUS!
datafence.validate_afterward(results)  # Too late!
```

### ✅ What DataFence IS:

```python
# RIGHT
intent = agent.generate_intent("Show me transactions")
result = datafence.execute(actor, intent)
# DataFence creates ExecutionPlan
# Database executes the PLAN, not LLM SQL
# Result validation ensures safety
```

**The database is unreachable except through DataFence.**

---

## Run the Tests

The demo comes with security invariant tests:

```bash
pytest tests/test_security_invariants.py -v
```

These tests prove the 13 security guarantees listed above.

---

## Next Steps

After running this demo, you understand:

1. **The Core**: ExecutionPlan is the authorized contract
2. **The Boundary**: LLM SQL never reaches the database
3. **The Validation**: Security on request AND result
4. **The Evidence**: Complete provenance trail
5. **The Guarantee**: Compromised agent cannot bypass policy

This is **not** about features.

This is about **deterministic authorization at the boundary**.

---

## Files

- `killer_demo.py` - The complete demo (6 scenarios)
- `../src/datafence/core/types.py` - Core types (ExecutionPlan, etc.)
- `../src/datafence/core/boundary.py` - Security boundary implementation
- `../src/datafence/core/policy_engine.py` - Policy evaluation
- `../src/datafence/connectors/sqlite_connector.py` - ExecutionPlan-only connector
- `../tests/test_security_invariants.py` - Security tests

---

## The Bottom Line

```
┌────────────────────────────────────────────────────┐
│                                                    │
│  "The model proposes. DataFence decides."          │
│                                                    │
│  The database executes ONLY what DataFence         │
│  authorizes.                                       │
│                                                    │
│  NOT what the LLM requests.                        │
│                                                    │
└────────────────────────────────────────────────────┘
```

That's the product.
