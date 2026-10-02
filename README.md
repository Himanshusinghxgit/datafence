# DataFence

**Deterministic authorization boundary for AI agents accessing enterprise data.**

The model proposes. DataFence decides. The customer's backend executes.

---

## What is DataFence?

DataFence is a security boundary you place between an AI agent and your
existing data-access layer. It authorizes what the AI may access and returns
a signed capability. Your existing connector verifies the capability and
executes the operation.

DataFence works for banks, healthcare, SaaS, retail, government, and any
enterprise where AI agents need controlled access to data.

## The Problem

Without a boundary:

```
LLM → "SELECT * FROM customers" → database
```

The LLM is not an authorization authority. It cannot be trusted to respect
tenant isolation, field-level restrictions, or operation limits.

## The Solution

```
LLM
 │  Intent (untrusted)
 ▼
DataFence
 │  ResourceRegistry → Policy → Authorization
 ▼
AuthorizedExecution (HMAC-signed)
 │
 ▼
Your existing connector
 │  verify + execute
 ▼
Enterprise data
```

DataFence does not know or care what database you use. It authorizes.
Your connector executes.

---

## What DataFence Owns

| Component | Responsibility |
|-----------|---------------|
| `ResourceRegistry` | WHAT resources exist, WHAT fields, WHAT classifications |
| `DataFencePolicyEngine` | WHO can do WHAT, on WHICH rows, with WHAT limits |
| `DataFenceBoundary` | Authorization + HMAC-signed capability issuance |
| `CapabilityVerifier` | Customer-side signature verification |

## What Your Application Owns

| Component | Responsibility |
|-----------|---------------|
| Authentication | Producing the `Actor` / `Principal` |
| AI/LLM | Generating the `Intent` (untrusted input) |
| Connector | Verifying the capability + executing the operation |
| Database | Storage, connections, credentials |
| Infrastructure | Hosting, networking, secrets management |

---

## Quickstart

```python
from secrets import token_bytes
from datafence import (
    Actor, DataFenceBoundary, DataFencePolicyEngine, DataFencePolicy,
    ResourcePolicy, ActionDecision, RowRule,
    ResourceRegistry, ResourceDefinition, FieldDefinition, DataClassification,
    Intent, Operation, CapabilityVerifier,
)
from datafence.core.resources import PredicateOperator

# 1. Define WHAT resources exist (Registry)
registry = ResourceRegistry()
registry.register(ResourceDefinition("orders", fields={
    "id":        FieldDefinition("id", "integer"),
    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
    "total":     FieldDefinition("total", "decimal", DataClassification.CONFIDENTIAL),
    "status":    FieldDefinition("status", "string"),
}))

# 2. Define WHO can do WHAT (Policy)
policy = DataFencePolicy("orders-policy", "1.0", {
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
signing_key = token_bytes(32)   # keep secret; share with your connector
fence = DataFenceBoundary.create(engine, registry, signing_key)

# 4. Authorize (DataFence decides)
authorized = fence.authorize(
    Actor("user:alice", "tenant-acme"),            # from your auth layer
    Intent("orders", Operation.READ,               # from the AI agent
           fields=["id", "total", "status"]),
)

# 5. Pass to your connector (your code, your database)
CapabilityVerifier(signing_key).verify(authorized)
result = my_connector.execute(authorized)
```

---

## YAML Policy

Policies can also be loaded from YAML:

```yaml
name: orders-policy
version: "1.0"
resources:
  orders:
    actions:
      read: allow
      insert: deny
      update: deny
      delete: deny
    fields:
      allow: [id, tenant_id, total, status, created_at]
      deny: []
    rows:
      - field: tenant_id
        operator: eq
        value: ":actor_tenant_id"
    limits:
      rows: 100
    obligations:
      audit: true
```

```python
from datafence import YAMLPolicyLoader, DataFencePolicyEngine

policy = YAMLPolicyLoader.load("policies/orders.yaml")
engine = DataFencePolicyEngine(policy, registry=registry)
```

---

## CLI

```bash
# Generate a sample policy
datafence init --output policy.yaml

# Validate a policy file
datafence validate policy.yaml --verbose

# Describe a resource in a policy
datafence describe policy.yaml --resource orders
```

---

## Install

```bash
pip install datafence

# Optional extras
pip install "datafence[postgres]"    # PostgreSQL reference connector
pip install "datafence[api]"         # FastAPI REST adapter
pip install "datafence[cli]"         # CLI tool
pip install "datafence[integrations]"# OpenAI, Anthropic, LangChain adapters
```

---

## Security Properties

- **Fail-closed**: Every unknown resource, field, or operation is denied.
- **Lossless predicates**: `amount > 1000` never becomes `amount = 1000`.
- **HMAC-signed capabilities**: Tampering with any field invalidates the signature.
- **Tenant isolation**: Policy-injected row filters cannot be overridden by the LLM.
- **Audience binding**: A capability for service A is rejected by service B.
- **Immutable**: `Actor`, `Intent`, and `AuthorizedExecution` are frozen after creation.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md)
for the full security model.

---

## What DataFence is NOT

- Not an IAM replacement
- Not a database driver or ORM
- Not a SQL firewall
- Not a DLP system
- Not a WAF
- Not a compliance certification (GDPR, HIPAA, PCI)
- Not a hallucination or prompt-injection detector

It can complement all of those.

---

## Examples

- [`examples/basic/`](examples/basic/README.md) — primary quickstart with generic resources
- [`examples/bank/`](examples/bank/README.md) — banking domain example built on DataFence core

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — component design and ownership model
- [`SECURITY.md`](SECURITY.md) — security properties and limitations
- [`docs/threat-model.md`](docs/threat-model.md) — threat model

## License

Apache 2.0 — see [LICENSE](LICENSE).
