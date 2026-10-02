# DataFence Architecture

**Version**: 1.0.0 — Capability-gated authorization boundary

## What DataFence Is

DataFence is a **deterministic authorization boundary** between an AI agent
and enterprise data.

The central principle:

> **The model proposes. DataFence decides. The customer's backend executes.**

The fundamental security invariant:

> An untrusted AI agent must never be able to cause an enterprise data
> connector to execute an operation that DataFence has not explicitly authorized.

DataFence is NOT:
- A banking library
- A database driver or ORM
- A SQL firewall (though typed execution makes injection structurally impossible)
- A replacement for IAM or database permissions
- A compliance certification
- A prompt-injection detector

---

## Ownership Boundary

```
                    ENTERPRISE APPLICATION
┌────────────────────────────────────────────────────────┐
│                                                        │
│  Application Authentication Layer                      │
│           │                                            │
│           ▼                                            │
│       Principal / Actor                                │
│           +                                            │
│       AI Agent / LLM                                   │
│           │                                            │
│           ▼                                            │
│         Intent (untrusted)                             │
│                                                        │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
           ┌────────────────────────┐
           │        DATAFENCE       │
           │                        │
           │   ResourceRegistry     │  ← WHAT exists?
           │          ↓             │
           │      Policy Engine     │  ← WHO can do WHAT?
           │          ↓             │
           │   Authorization        │
           │          ↓             │
           │  AuthorizedExecution   │  ← signed capability
           └──────────┬─────────────┘
                      │
                      │  AuthorizedExecution
                      ▼
           ┌────────────────────────┐
           │  CUSTOMER BACKEND      │
           │                        │
           │  Existing Connector    │  ← verify + execute
           │  / Data Access Layer   │
           └──────────┬─────────────┘
                      │
                      ▼
                Enterprise Data
```

**DataFence owns**: Registry · Policy · Authorization · Capability signing

**Customer owns**: Authentication · Connector · Database · Credentials · Execution

---

## Core Components

### 1. ResourceRegistry (`core/registry.py`)

Answers: **WHAT exists?**

```python
registry = ResourceRegistry()
registry.register(ResourceDefinition(
    name="transactions",
    fields={
        "id":          FieldDefinition("id", "integer", DataClassification.INTERNAL),
        "amount":      FieldDefinition("amount", "decimal", DataClassification.CONFIDENTIAL),
        "card_number": FieldDefinition("card_number", "string", DataClassification.RESTRICTED),
        "tenant_id":   FieldDefinition("tenant_id", "string", is_tenant_key=True),
    },
    supported_operations=("read",),
))
registry.freeze()   # immutable from this point
```

Responsibilities:
- Resource name validation
- Field name and type definitions
- Data classification (PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED)
- Tenant key identification
- Supported operation enumeration
- Validation of intents before policy evaluation

Registry does NOT answer: *who can access what* — that is the Policy's job.

### 2. Policy Engine (`core/policy.py`)

Answers: **WHO can do WHAT, on WHICH resource, with WHAT constraints?**

```python
policy = DataFencePolicy("my-policy", "1.0", {
    "transactions": ResourcePolicy(
        resource="transactions",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id", "amount", "merchant", "timestamp"],
        denied_fields=["card_number", "account_number"],
        row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
        max_rows=100,
    )
})
engine = DataFencePolicyEngine(policy, registry=registry)
```

Responsibilities:
- Action authorization (allow/deny per operation)
- Field allow/deny lists
- Row-level filter injection (policy INJECTS these; the LLM cannot override them)
- Row limits
- Obligations (e.g. `{"audit": True}`)

Policy does NOT execute queries. It produces a `PolicyDecision`.

### 3. DataFenceBoundary (`core/boundary.py`)

The single execution path:

```python
fence = DataFenceBoundary.create(
    policy_engine=engine,
    registry=registry,
    signing_key=signing_key,
    capability_audience="my-service",
)

authorized = fence.authorize(
    principal=Actor("user:alice", "tenant-acme"),
    intent=Intent("transactions", Operation.READ, fields=["id", "amount"]),
)
```

Internal flow:
```
ResourceRegistry.validate_intent()    ← schema check, fail-closed
PolicyEngine.evaluate()               ← authorization check
PolicyDecision (ALLOW/DENY)
    ↓ ALLOW
AuthorizedExecution._create_signed()  ← HMAC-signed capability
```

`DataFenceBoundary` has **no `execute()` method**. It only authorizes.

### 4. AuthorizedExecution (`core/capability.py`)

The signed capability handed to the customer's connector:

```
execution_id        unique identifier per authorization
actor               authenticated principal (from application)
resource            authorized resource name
operation           authorized operation
selected_fields     exact fields the connector may return
enforced_predicates typed, lossless predicate list (full operator preserved)
enforced_filters    EQ-only compatibility view
limit               maximum rows
policy_version      which policy version authorized this
expires_at          capability expiry (UTC)
audience            which service may consume this
nonce               unique per issuance
signature           HMAC-SHA256 over all fields
```

Critical property: **lossless predicates**. A policy rule `amount > 1000`
is stored as `{operator: ">", value: 1000}`, not as `{amount: 1000}`. The
connector compiles the full predicate. Operators are never silently coerced.

### 5. CapabilityVerifier (`core/capability.py`)

The customer connector calls this before executing:

```python
verifier = CapabilityVerifier(signing_key, expected_audience="my-service")
verifier.verify(authorized)   # raises CapabilityVerificationError on failure
result = my_connector.execute(authorized)
```

Verification order:
1. Type check
2. Audience binding
3. Expiry check
4. HMAC signature verification (constant-time comparison)

---

## Authorization Flow Detail

```
Principal (trusted — from app auth)
    +
Intent (untrusted — from AI/agent)
    |
    v
DataFenceBoundary.authorize()
    |
    ├─ 1. ResourceRegistry.validate_intent()
    │      ├─ resource exists?              → deny if not
    │      ├─ operation supported?          → deny if not
    │      ├─ fields known?                 → deny if not
    │      └─ filter fields not RESTRICTED? → deny if so
    │
    ├─ 2. PolicyEngine.evaluate()
    │      ├─ action allowed?               → deny if not
    │      ├─ requested fields authorized?  → deny if not
    │      ├─ inject row filters            → always applied
    │      └─ PolicyDecision (ALLOW/DENY)
    │
    ├─ 3. Structural validation
    │      └─ malformed decision            → PolicyError (fail-closed)
    │
    └─ 4. Capability construction
           ├─ intersect fields (policy ∩ agent request)
           ├─ merge filters (policy takes priority)
           ├─ resolve :actor_* references
           ├─ cap row limit (min(agent, policy))
           └─ HMAC-SHA256 sign all fields
```

**Every failure path produces a deny or error — never a silent allow.**

---

## Capability Security

### HMAC Canonicalization

All security-relevant fields are covered by the HMAC signature:

```
resource · operation · selected_fields · enforced_predicates
actor.id · actor.tenant_id · actor.metadata
policy_version · limit · expires_at · audience · nonce
```

Fields are length-prefixed before joining to prevent canonicalization
collisions from attacker-controlled values containing the separator character.

### Replay Protection

The nonce provides **uniqueness** per issuance — two authorize() calls for
identical inputs produce different nonces.

**Replay protection** (rejecting a previously-used capability) is a
connector-side responsibility and requires the connector to record consumed
nonces. This is a documented limitation; DataFence does not maintain nonce state.

### Audience Binding

A capability is bound to a specific audience tag (e.g. `"customer-data-service"`).
A connector for `"reporting-service"` must reject a capability issued for
`"customer-data-service"`. The CapabilityVerifier enforces this.

---

## What DataFence Does NOT Do

| Concern | Owner |
|---------|-------|
| Authentication | Application IAM layer |
| Database credentials | Customer |
| SQL compilation | Customer connector |
| Database execution | Customer connector |
| Connection pooling | Customer |
| Infrastructure | Customer |
| Replay prevention (nonce store) | Customer connector |
| Schema drift detection | Customer (registry must be kept in sync) |
| DLP / PII scanning | Separate tool |
| Prompt injection detection | Separate tool |
| GDPR/HIPAA/PCI compliance | Requires much more than a library |

---

## Project Structure

```
src/datafence/
├── __init__.py              ← public API (generic, no domain terms)
├── core/
│   ├── boundary.py          ← DataFenceBoundary.authorize()
│   ├── capability.py        ← AuthorizedExecution, CapabilityVerifier
│   ├── policy.py            ← DataFencePolicyEngine, YAMLPolicyLoader
│   ├── registry.py          ← ResourceRegistry, ResourceDefinition
│   ├── resources.py         ← typed IR (Predicate, Filter, RowLimit, …)
│   ├── principal.py         ← Principal (richer Actor with roles)
│   └── types.py             ← Actor, Intent, Request, Operation
├── connectors/
│   ├── protocol.py          ← DataConnector protocol + ConnectorResult
│   ├── memory_connector.py  ← reference in-memory connector (tests/examples)
│   ├── sqlite_connector.py  ← reference SQLite connector
│   ├── postgres_connector.py← reference PostgreSQL connector
│   ├── snowflake_connector.py← reference Snowflake connector
│   └── athena_connector.py  ← reference Athena connector
├── integrations/            ← OpenAI, Anthropic, LangChain adapters
├── mcp/                     ← MCP server + tool wrapper
├── api.py                   ← FastAPI REST adapter
├── cli.py                   ← Click CLI
├── errors.py                ← exception hierarchy
└── _legacy/                 ← deprecated v0.1–v0.4 code (DO NOT USE)

examples/
├── basic/                   ← PRIMARY quickstart (generic, domain-neutral)
└── bank/                    ← domain example (banking on top of DataFence)

tests/
├── test_authorization_boundary.py  ← core boundary tests
├── test_security_invariants.py     ← comprehensive security invariant tests
└── security/
    ├── test_pii.py
    └── test_sql_firewall.py

docs/
├── architecture.md
├── security.md
├── threat-model.md
└── …
```

---

## Non-Goals

DataFence does not aim to be:

- An IAM replacement
- A database permission replacement
- A DLP system
- A WAF
- A SQL firewall
- A compliance certification
- A hallucination detector
- A prompt-injection detector
- A malware scanner
- A database driver or ORM

It can complement those systems.
