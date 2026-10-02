# DataFence

**Deterministic authorization boundary for AI/agent access to enterprise data.**

> **The AI proposes. DataFence decides. Your application executes.**

---

## The problem

AI systems are probabilistic. Enterprise authorization cannot be probabilistic.

When an AI agent requests access to enterprise data, you cannot trust it to:

- Choose its own identity
- Determine which tenant's data it can see
- Decide which fields are sensitive
- Honor row-level isolation rules

You need a deterministic enforcement point between the AI and your data.

That is DataFence.

---

## How it works

```
Authentication (your app)
        ↓
   Principal  ←── trusted identity
        +
    Intent    ←── untrusted AI request
        ↓
  DataFenceBoundary.authorize()
        ├─ ResourceRegistry — does this resource/field exist?
        ├─ PolicyEngine     — is this principal allowed?
        └─ AuthorizedExecution (HMAC-signed)
                ↓
    your_connector.execute(authorized)   ← you own this
                ↓
        Enterprise data
```

DataFence **stops at `AuthorizedExecution`**. It does not own the connector, the database, the credentials, or the query execution. Your application does.

---

## Core concepts

### Principal

Who is making the request? The authenticated identity from **your** auth system.

```python
from datafence import Principal

principal = Principal(
    id="user:alice",
    tenant_id="acme-corp",
    roles=("finance:read",),
    attributes={"department": "finance"},
)
```

The AI cannot choose or modify the Principal. Your application sets it.

### Intent

What does the AI/agent want? An untrusted request.

```python
from datafence import Intent, Operation

intent = Intent(
    resource="orders",
    operation=Operation.READ,
    fields=["id", "total", "status"],
    limit=10,
)
```

Intent is **untrusted**. DataFence validates and authorizes it.

### ResourceRegistry

What resources exist and what are their schemas?

```python
from datafence import ResourceRegistry, ResourceDefinition, FieldDefinition, DataClassification

registry = ResourceRegistry()
registry.register(ResourceDefinition(
    name="orders",
    fields={
        "id":        FieldDefinition("id", "integer"),
        "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
        "total":     FieldDefinition("total", "decimal", DataClassification.CONFIDENTIAL),
        "ssn":       FieldDefinition("ssn", "string", DataClassification.RESTRICTED),
    },
))
```

The registry defines **what exists**. The policy defines **who can access it**.

### Policy

Who can do what, to which resource, under what constraints?

```python
from datafence import DataFencePolicy, DataFencePolicyEngine, ResourcePolicy, ActionDecision, RowRule
from datafence.core.resources import PredicateOperator

policy = DataFencePolicy("my-policy", "1.0", {
    "orders": ResourcePolicy(
        "orders",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id", "tenant_id", "total", "status"],
        denied_fields=["ssn"],
        row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
        max_rows=100,
    )
})
engine = DataFencePolicyEngine(policy, registry=registry)
```

Row filters are **injected by policy**, not supplied by the AI. The AI cannot override them.

Policies can also be loaded from YAML:

```python
from datafence import YAMLPolicyLoader
policy = YAMLPolicyLoader.load("policies/my-policy.yaml")
```

### DataFenceBoundary

The authorization boundary. The only method you call is `authorize()`.

```python
from secrets import token_bytes
from datafence import DataFenceBoundary

key = token_bytes(32)   # secret — keep it safe
fence = DataFenceBoundary.create(engine, registry, key)
```

### AuthorizedExecution

The output of `authorize()`. A cryptographically signed proof that DataFence explicitly authorized this operation.

```python
authorized = fence.authorize(principal, intent)

print(authorized.execution_id)       # unique authorization ID
print(authorized.selected_fields)    # fields actually authorized
print(authorized.filter_constraints()) # predicates to enforce
print(authorized.limit)              # row limit (policy-capped)
```

Your connector verifies the signature before executing:

```python
from datafence import CapabilityVerifier

verifier = CapabilityVerifier(key, expected_audience="my-service")
verifier.verify(authorized)   # raises CapabilityVerificationError on failure
```

---

## Quick start

```python
from secrets import token_bytes
from datafence import (
    Principal, Intent, Operation,
    DataFenceBoundary, DataFencePolicyEngine, DataFencePolicy,
    ResourcePolicy, ActionDecision, RowRule,
    ResourceRegistry, ResourceDefinition, FieldDefinition,
    CapabilityVerifier,
)
from datafence.core.resources import PredicateOperator

# 1. Build the registry (what exists)
registry = ResourceRegistry()
registry.register(ResourceDefinition("orders", fields={
    "id":        FieldDefinition("id", "integer"),
    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
    "total":     FieldDefinition("total", "decimal"),
    "status":    FieldDefinition("status", "string"),
}))

# 2. Define the policy (who can do what)
policy = DataFencePolicy("orders-v1", "1.0", {
    "orders": ResourcePolicy(
        "orders",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id", "tenant_id", "total", "status"],
        row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
        max_rows=100,
    )
})
engine = DataFencePolicyEngine(policy, registry=registry)

# 3. Create the boundary
key = token_bytes(32)
fence = DataFenceBoundary.create(engine, registry, key)

# 4. Authorize — DataFence decides
authorized = fence.authorize(
    Principal("user:alice", "acme"),
    Intent("orders", Operation.READ, fields=["id", "total", "status"]),
)

# 5. Verify and execute — you decide how
CapabilityVerifier(key).verify(authorized)
rows = my_connector.execute(authorized)   # your code, your database
```

---

## What DataFence does NOT do

- Execute database queries
- Own database connections or credentials
- Authenticate users
- Replace your IAM/SSO layer
- Generate SQL
- Access your data
- Know what's in your database

---

## Optional adapters

DataFence ships adapters that feed requests into the authorization boundary from:

| Adapter | Module |
|---------|--------|
| REST API (FastAPI) | `datafence.api` |
| CLI | `datafence.cli` |
| OpenAI function calling | `datafence.integrations.openai_tool` |
| Anthropic Claude tool-use | `datafence.integrations.anthropic_tool` |
| LangChain | `datafence.integrations.langchain_tool` |
| MCP | `datafence.mcp` |

These adapters feed `Principal + Intent` into `DataFenceBoundary.authorize()`. They do not redefine the core architecture.

---

## Reference connector implementations

For tests and demonstrations, `examples/reference_connector/` contains reference implementations for:

- In-memory (always available, no dependencies)
- SQLite
- PostgreSQL
- Snowflake
- AWS Athena

These are **examples only**. For production, implement the `DataConnector` protocol in your own codebase.

---

## Installation

```bash
pip install datafence
```

Optional dependencies:

```bash
pip install 'datafence[api]'           # FastAPI REST adapter
pip install 'datafence[cli]'           # CLI tool
pip install 'datafence[integrations]'  # OpenAI, Anthropic, LangChain
```

---

## Examples

```bash
# Minimal generic example (no database required)
python -m examples.basic.application

# Banking domain example
python -m examples.bank.app
```

---

## Architecture

See [`docs/architecture.md`](docs/architecture.md) for the full security model and design rationale.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
