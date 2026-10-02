# DataFence Architecture

## Core principle

> **The AI proposes. DataFence decides. The customer's application executes.**

DataFence is a deterministic authorization boundary that sits between AI agents and enterprise data. It produces a cryptographically signed authorization artifact (`AuthorizedExecution`). The customer's own connector verifies that artifact and executes against the customer's data source. DataFence never touches the data.

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
                   │ ResourceRegistry │  ← does this resource/field exist?
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
                      connector.verify()
                      connector.execute()
                            │
                            ▼
                      Enterprise Data
```

DataFence ends at `AuthorizedExecution`. Everything below is customer-owned.

---

## Components

### Principal

- Answers: **Who is making the request?**
- Supplied by the application's authentication layer — never by the AI.
- Immutable frozen dataclass: `id`, `tenant_id`, `roles`, `attributes`.

### Intent

- Answers: **What does the AI/application want?**
- Untrusted — treat as potentially attacker-controlled.
- Contains: `resource`, `operation`, `fields`, `filters`, `limit`.

### ResourceRegistry

- Answers: **What resources exist and what are their schemas?**
- Defines the authorization domain: resources, fields, data classifications, tenant keys, supported operations.
- Frozen before the boundary serves requests. Does not make authorization decisions.

### Policy

- Answers: **Who can access what, under which constraints?**
- Defines field allow/deny lists per resource.
- Injects mandatory row filters — the AI cannot override these.
- Sets row limits — the AI may request fewer, never more.
- Loaded from code or YAML.

### DataFenceBoundary

- The enforcement point. One public method: `authorize()`.
- Does not instantiate connectors, open connections, or execute queries.

### PolicyDecision (internal)

- Result of policy evaluation: ALLOW or DENY.
- Carries authorized fields, enforced filter, row limit, policy version.

### AuthorizedExecution

- The product of DataFence authorization.
- HMAC-SHA256 signed over all security-relevant fields.
- Immutable frozen dataclass.
- Single predicate representation — no legacy dual fields.
- The customer connector MUST verify before executing.

### CapabilityVerifier

- Customer-side verification: type → audience → expiry → HMAC.
- Raises `CapabilityVerificationError` on any failure.

---

## Security properties

**LLM cannot choose identity** — Principal comes from the application, never from agent output.

**LLM cannot override tenant isolation** — Policy injects `tenant_id = :actor_tenant_id` as a mandatory predicate. Agent filters are merged after, and policy takes priority.

**LLM cannot access undeclared resources** — Registry validates every resource and field before policy evaluation.

**Predicates are lossless** — `amount > 1000` stays `amount > 1000`. Typed `PredicateOperator` enum; no string coercion.

**Capability forgery is cryptographically prevented** — HMAC covers: execution_id, created_at, actor.id, actor.tenant_id, actor.attributes, resource, operation, fields, predicates, limit, policy_version, policy_decisions, expires_at, audience, nonce.

**DataFence does not execute** — `DataFenceBoundary` has no `execute()`. It holds no connector, no connection, no credentials.

---

## What DataFence is NOT

- A database driver framework
- An ORM or query engine
- An IAM/SSO replacement
- A DLP product
- A WAF

---

## Connector ownership

```
DataFence:   Principal + Intent → AuthorizedExecution
                                        ↓
Customer:    connector.verify(cap) → connector.execute(cap) → rows
```

The connector: verifies signature + expiry + audience, translates `filter_constraints()` / `selected_fields` / `limit` to a backend call, returns results. DataFence never sees those results.

---

## Core vs. optional

| Component | Classification |
|-----------|---------------|
| Principal, Intent, Operation | Core |
| ResourceRegistry, ResourceDefinition, FieldDefinition | Core |
| DataFencePolicy, PolicyEngine, PolicyDecision | Core |
| DataFenceBoundary | Core |
| AuthorizedExecution, CapabilityVerifier | Core |
| Filter, Predicate, PredicateOperator | Core |
| REST API adapter (`datafence.api`) | Optional |
| CLI (`datafence.cli`) | Optional |
| OpenAI / Anthropic / LangChain (`datafence.integrations`) | Optional |
| MCP adapter (`datafence.mcp`) | Optional |
| Reference connectors (`examples/reference_connector/`) | Examples only |

---

## Threat model

See [`threat-model.md`](threat-model.md).
