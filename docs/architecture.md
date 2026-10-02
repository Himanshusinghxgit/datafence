# DataFence Architecture

## Core principle

> **The AI proposes. DataFence decides. The customer's application executes.**

DataFence is a deterministic authorization boundary that sits between AI agents and enterprise data. It does not execute data operations. It issues cryptographically signed authorization artifacts that the customer's own connector can verify and execute.

---

## System diagram

```
                     CUSTOMER APPLICATION
                             │
              ┌──────────────┴──────────────┐
              │                             │
      Authentication                   AI / LLM
    (app-owned)                        (untrusted)
              │                             │
              ▼                             ▼
         Principal                       Intent
      (trusted identity)           (untrusted request)
              │                             │
              └──────────────┬──────────────┘
                             ▼
                   ┌──────────────────┐
                   │     DATAFENCE    │
                   │                  │
                   │ ResourceRegistry │  ← does resource/field exist?
                   │       ↓          │
                   │   PolicyEngine   │  ← is this principal allowed?
                   │       ↓          │
                   │  Authorization   │
                   │       ↓          │
                   │ PolicyDecision   │
                   │       ↓          │
                   │AuthorizedExec.   │  ← HMAC-signed artifact
                   └────────┬─────────┘
                            │
                   AuthorizedExecution
                            │
                            ▼
                   CUSTOMER APPLICATION
                            │
                            ▼
                      Enterprise Data
```

DataFence ends at `AuthorizedExecution`. The customer application owns everything below.

---

## Components

### Principal

Answers: **Who is making the request?**

- Supplied by the application's authentication layer.
- The AI cannot choose or modify it.
- Immutable frozen dataclass.
- Contains: `id`, `tenant_id`, `roles`, `attributes`.

```python
Principal("user:alice", "acme-corp", roles=("finance:read",))
```

### Intent

Answers: **What does the AI/application want?**

- Supplied by the LLM/agent — **untrusted**.
- Treated as potentially attacker-controlled input.
- Contains: `resource`, `operation`, `fields`, `filters`, `limit`.

```python
Intent("orders", Operation.READ, fields=["id", "total"])
```

### ResourceRegistry

Answers: **What resources exist and what are their schemas?**

- Defines the authorization domain: resources, fields, data classifications, tenant keys, supported operations.
- Frozen before the boundary begins serving requests.
- Does **not** make authorization decisions.

### Policy

Answers: **Who can access what, under which constraints?**

- Defines field allow/deny lists per resource.
- Injects mandatory row filters (e.g. tenant isolation) — the AI cannot override these.
- Sets row limits (the AI may request fewer, never more).
- Loaded from code or YAML.

### DataFenceBoundary

The enforcement point. Has exactly one public method: `authorize()`.

```python
authorized = fence.authorize(principal, intent)
```

Steps:
1. `ResourceRegistry.validate_intent()` — reject unknown resources, fields, operations.
2. `PolicyEngine.evaluate()` — evaluate allow/deny rules.
3. Build and sign `AuthorizedExecution` — or raise `PolicyDeniedError`.

Does **not** instantiate connectors, open connections, or execute queries.

### PolicyDecision

The internal result of policy evaluation:
- `effect`: ALLOW or DENY
- `allowed_fields`: fields this principal may access
- `enforced_filter`: mandatory predicates (policy-injected, not AI-supplied)
- `row_limit`: maximum rows
- `policy_version`: for audit provenance

### AuthorizedExecution

The product of DataFence authorization.

- HMAC-SHA256 signed over all security-relevant fields.
- Immutable frozen dataclass.
- Contains the full authorization context: principal binding, resource, operation, fields, predicates, limit, policy version, audience, expiry, nonce.

The customer's connector must call `CapabilityVerifier.verify()` before executing.

### CapabilityVerifier

Customer-side verification:
1. Type check
2. Audience match
3. Expiry check
4. HMAC signature verification

Any failure raises `CapabilityVerificationError`.

---

## Security properties

### LLM cannot choose identity
The `Principal` is supplied by the application, not parsed from the LLM's output.

### LLM cannot override tenant isolation
Policy injects `tenant_id = :actor_tenant_id` as a mandatory predicate. The LLM can request `filters={"tenant_id": "other-tenant"}` but the policy-enforced filter takes priority.

### LLM cannot access undeclared resources
The `ResourceRegistry` validates every resource and field. Anything not registered is rejected before policy evaluation.

### LLM cannot weaken predicates
All predicates are typed (`PredicateOperator` enum). `amount > 1000` stays `amount > 1000` — it cannot become `amount = 1000`.

### Capability forgery is cryptographically prevented
The HMAC covers: execution_id, created_at, actor.id, actor.tenant_id, actor.attributes, resource, operation, fields, predicates, limit, policy_version, policy_decisions, expires_at, audience, nonce.

Any modification invalidates the signature.

### DataFence does not execute
`DataFenceBoundary` has no `execute()` method. It holds no connector, no connection, no credentials. The `authorize()` method succeeds with no database present.

---

## What DataFence is NOT

- A database driver framework
- An ORM
- A query engine
- An IAM/SSO replacement
- A DLP product
- A WAF
- A compliance certification

---

## Connector ownership

```
DataFence:       Principal + Intent → AuthorizedExecution
                                              ↓
Customer:   connector.verify(authorized) → connector.execute(authorized) → rows
```

The customer's connector:
1. Receives `AuthorizedExecution` from the application.
2. Verifies the HMAC signature, expiry, and audience.
3. Translates the typed IR (`filter_constraints()`, `selected_fields`, `limit`) into a backend call.
4. Returns results to the application.

DataFence never sees those results.

---

## Core vs. optional

| Component | Type |
|-----------|------|
| `Principal`, `Intent`, `Operation` | Core |
| `ResourceRegistry`, `ResourceDefinition`, `FieldDefinition` | Core |
| `DataFencePolicy`, `PolicyEngine`, `PolicyDecision` | Core |
| `DataFenceBoundary` | Core |
| `AuthorizedExecution`, `CapabilityVerifier` | Core |
| `Filter`, `Predicate`, `PredicateOperator` | Core |
| REST API adapter | Optional (`datafence.api`) |
| CLI | Optional (`datafence.cli`) |
| OpenAI / Anthropic / LangChain adapters | Optional (`datafence.integrations`) |
| MCP adapter | Optional (`datafence.mcp`) |
| Reference connectors | Examples only (`examples/reference_connector/`) |

---

## Threat model

See [`docs/threat-model.md`](threat-model.md).
