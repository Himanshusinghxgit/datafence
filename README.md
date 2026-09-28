# DataFence v0.5.0

**Policy-Enforced Data Execution for AI.**

[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)](https://github.com/Himanshusinghxgit/datafence)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Status: Prototype](https://img.shields.io/badge/status-prototype-orange.svg)]()

---

## What DataFence does

An AI agent never gets database access. It gets the ability to **propose an operation**.

DataFence decides whether that proposal becomes an executable capability:

```
                 AI AGENT
                     │
                   Intent (untrusted)
                     │
                     ▼
          ┌────────────────────┐
          │      DATAFENCE     │
          │                    │
          │  Principal Context │
          │         ↓          │
          │  Resource Registry │
          │         ↓          │
          │  Policy Decision   │
          │         ↓          │
          │  Execution IR      │
          │         ↓          │
          │  Signed Capability │
          └─────────┬──────────┘
                    │
                    ▼
              DATA CONNECTOR
                    │
              compiled query
                    │
                    ▼
              DATABASE / LAKE
                    │
                    ▼
              RESULT VALIDATOR
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
       RESULT               EVIDENCE
```

**Core principle:** The model proposes. DataFence decides.

---

## Status: Prototype

DataFence v0.5 is an architectural prototype. The core security boundary is
operational and tested, but this is **not production-ready software**.

---

## Quick Start

```python
from datafence.core.boundary import DataFenceBoundary
from datafence.core.policy import create_banking_policy
from datafence.connectors.sqlite_connector import create_demo_database
from datafence.core.types import Actor, Intent, Operation

# One factory call wires up the boundary + connector with a shared signing key
boundary = DataFenceBoundary.create(
    policy_engine=create_banking_policy(),
    connector_factory=create_demo_database,
    database_path="data.db",
)

# AI agent proposes an operation (untrusted)
actor = Actor(id="agent:finance", tenant_id="acme-corp")
intent = Intent(
    resource="transactions",
    operation=Operation.READ,
    fields=["id", "merchant", "amount"],
)

result = boundary.execute(actor, intent)

if hasattr(result, "execution_result"):
    print(f"Allowed — {result.execution_result.row_count} rows")
else:
    print(f"Denied — {result.decision.reasons}")
```

---

## Architecture

### Six core primitives

| Primitive | Role | Trust level |
|-----------|------|-------------|
| `Principal` | Who is calling | Trusted (from host IAM) |
| `Intent` | What the AI wants | **Untrusted** |
| `Policy` | What is allowed | Deterministic |
| `Execution IR` | Typed, validated plan | DataFence-owned |
| `AuthorizedExecution` | Signed capability | Cryptographic |
| `Evidence` | Audit record | Tamper-evident |

### Security flow

```
Intent (untrusted)
  ↓
Resource Registry       → validates identifiers exist in schema
  ↓
Policy Engine           → ALLOW / DENY with enforced filters
  ↓
AuthorizedExecution     → HMAC-SHA256 signed capability
  ↓
Connector               → verifies signature, compiles safe SQL
  ↓
Result Validator        → no unauthorized fields leak out
  ↓
AllowedRequest + Evidence
```

### Key invariants

- The database never executes LLM-generated SQL
- Policy **injects** row filters (tenant isolation); the LLM cannot bypass them
- User predicates can **narrow** an authorized scope, never widen it
- Identifier injection is prevented by `validate_identifier()` on all SQL identifiers
- Signed capabilities cannot be forged or tampered without the HMAC key
- Fail-closed on all errors

### Trust model

**Host application is responsible for:**
- Authenticating the principal before calling DataFence
- Providing a verified `Actor` / `Principal` object
- Managing sessions, tokens, and identity

**DataFence is responsible for:**
- Authorizing what the authenticated principal may do
- Enforcing row-level and column-level policy
- Generating cryptographically signed execution capabilities
- Validating results
- Producing tamper-evident evidence

DataFence is **not** an IAM system. It authorizes the principal you provide.

---

## What's implemented

### Core (v0.5, stable)
✅ Cryptographic capability model (HMAC-SHA256)  
✅ Typed execution IR (ResourceRef, FieldRef, Predicate, Filter, Projection)  
✅ Identifier validation — no f-string interpolation of SQL identifiers  
✅ Enhanced policy model with YAML loader  
✅ Policy **injects** row filters (not requires them from LLM)  
✅ Resource Registry with data classification  
✅ Column-level security (field allow/deny)  
✅ Row-level security (tenant isolation, injected predicates)  
✅ Result validation (defense-in-depth)  
✅ Tamper-evident evidence / audit trail  
✅ Security regression test suite (all v0.3 attacks blocked)  

### Connectors
✅ SQLite — reference implementation, v0.5 capability interface  
⚠️ PostgreSQL — v0.5 interface, **not integration-tested** (no real DB in CI)  
⚠️ Athena — v0.5 interface, **not integration-tested**  
⚠️ Snowflake — v0.5 interface, **not integration-tested**  

The legacy v0.1–v0.3 connectors (connectors/postgres.py, connectors/athena.py,
connectors/snowflake.py) are **deprecated** and lack capability signatures.

### Integrations (experimental)
⚠️ MCP server + tool — functional, not hardened  
⚠️ OpenAI function-calling adapter — functional  
⚠️ Anthropic tool-use adapter — functional  
⚠️ LangChain tool adapter — functional  

### Not implemented
❌ Write operations (INSERT, UPDATE, DELETE)  
❌ Complex predicates (OR, IN, NOT) from user intent  
❌ Policy management UI  
❌ Key management / rotation  
❌ Deployment tooling  

---

## Security improvements (v0.3 → v0.4 → v0.5)

| Vulnerability | v0.3 | v0.4 | v0.5 |
|---------------|------|------|------|
| ExecutionPlan forgery | ❌ | ✅ HMAC | ✅ |
| Connector bypass | ❌ execute_plan() | ✅ removed | ✅ |
| Identifier injection | ❌ f-strings | ❌ f-strings | ✅ validated |
| Capability tampering | ❌ frozen bypassable | ✅ breaks HMAC | ✅ |
| Tenant isolation | ⚠️ policy only | ✅ + signed | ✅ + registry |
| Field leakage | ⚠️ | ✅ | ✅ + classification |

---

## Testing

```bash
# Install
pip install -e .

# Core security regression tests
pytest tests/test_v04_security.py -v

# Full Phase 1-7 tests
pytest tests/test_phases_1_7.py -v

# Verify all v0.3 attacks are blocked
python attacks/verify_v04_blocks_attacks.py

# Run the killer demo
python demos/killer_demo.py
```

---

## Roadmap

| Version | Focus |
|---------|-------|
| **v0.5.3** ✅ | Single policy interface, compat shim removed, 15 security invariants |
| v0.6.0 | Resource Registry in boundary, PostgreSQL integration tests |
| v0.6.0 | Resource Registry in all connectors, policy semantics formalization |
| v0.7.0 | PostgreSQL production hardening + CI integration tests |
| v0.8.0 | Athena / Snowflake production hardening |
| v0.9.0 | MCP + integrations hardening, benchmarks |
| v1.0.0 | External security review, production hardening |

---

## Known limitations

1. **Actor authentication** — application must authenticate before calling DataFence
2. **SQLite only tested end-to-end** — Postgres/Athena/Snowflake not integration-tested yet
3. **Read-only** — only SELECT implemented
4. **Simple predicate merging** — complex user predicates (OR, IN, NOT) not supported
5. **No key management** — signing key is in-memory, not persisted or rotated
6. **Prototype security** — do NOT use in production without external review

---

## Installation

```bash
git clone https://github.com/Himanshusinghxgit/datafence.git
cd datafence
pip install -e .

# Optional: PostgreSQL support
pip install -e ".[postgres]"

# Optional: Athena support  
pip install -e ".[athena]"
```

---

## License

Apache 2.0

---

**Version:** 0.5.3  
**Status:** Prototype (Architecture stable)  
**Next:** v0.6.0 — Resource Registry integration, PostgreSQL integration tests
