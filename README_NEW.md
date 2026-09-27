# DataFence

> **A deterministic authorization and execution boundary for AI agents accessing data.**

**Status**: Prototype (v0.3.0)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-0.3.0-orange.svg)](https://github.com/yourusername/datafence)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## The Problem

Enterprise organizations want AI agents to access sensitive data. But AI models are probabilistic—they can generate incorrect queries, request unauthorized data, or cross tenant boundaries.

**You cannot secure probabilistic systems with probabilistic controls.**

## The Solution

```
        AI Agent
             │
             │ proposes
             ▼
       ┌──────────┐
       │DataFence │  ← Deterministic authorization
       │          │  ← Policy evaluation
       │ ENFORCES │  ← ExecutionPlan (the contract)
       └────┬─────┘  ← Result validation
            │
            │ executes only what is authorized
            ▼
    Enterprise Data
```

DataFence sits between AI agents and data systems, creating an **authorized ExecutionPlan** before any data access occurs.

### The Core Principle

> **The model proposes. DataFence decides.**

The database executes DataFence's authorized ExecutionPlan, NOT the LLM's untrusted SQL.

## Killer Demo (30 seconds)

```bash
cd demos
python killer_demo.py
```

This proves the security boundary works:

1. ✅ Normal request → Authorized
2. ⚠️ SELECT * → Restricted to allowed fields
3. ❌ Sensitive field → Denied
4. ❌ Cross-tenant attack → Blocked
5. ❌ DELETE operation → Denied
6. 🛡️ Malicious connector → Caught by validation

See [`demos/README.md`](demos/README.md) for details.

## The Core Abstraction: ExecutionPlan

```python
from datafence.core.types import Actor, Intent, Operation
from datafence.core.boundary import DataFenceBoundary

# Create actor (WHO)
actor = Actor(id="agent:finance", tenant_id="acme")

# LLM proposes (UNTRUSTED)
intent = Intent(
    resource="transactions",
    operation=Operation.READ,
    fields=["*"],  # LLM wants everything
)

# DataFence decides
result = boundary.execute(actor, intent)

# If allowed, shows ExecutionPlan
if result.verified:
    print(result.execution_plan)
    # ExecutionPlan(
    #   selected_fields=["id", "amount", "merchant"],  # NOT all fields
    #   enforced_filters={"tenant_id": "acme"},        # Added by policy
    #   limit=100                                       # Enforced
    # )
```

**Key Point**: The database never saw the LLM's `SELECT *`. It executed DataFence's authorized plan.

## What DataFence Provides

### Core Security Boundary ✅

- **Policy-based authorization** - Evaluate before execution
- **ExecutionPlan** - The authorized contract
- **Field-level control** - Allow/deny specific columns
- **Row-level control** - Tenant isolation, custom filters
- **Operation control** - Block DELETE, UPDATE, etc.
- **Result validation** - Verify returned data matches plan
- **Evidence generation** - Proof of policy compliance
- **Audit trail** - Complete record of all requests
- **Fail closed** - Errors result in DENY

### What Works (v0.3.0) ✅

- ExecutionPlan abstraction
- DataFence security boundary
- Simple policy engine
- SQLite connector (ExecutionPlan-only)
- Killer demo (6 scenarios)
- Security invariant tests (13+ guarantees)

### What Needs Work ⚠️

- Production connectors (PostgreSQL, Athena, Snowflake need refactoring)
- YAML policy files (simple engine only)
- PII detection/redaction (exists but not integrated)
- SQL firewall (exists but not integrated)
- Framework adapters (OpenAI, Claude, LangChain need refactoring)
- REST API (exists but needs refactoring)
- CLI (exists but needs refactoring)
- Performance benchmarks (not measured)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AI Agent                             │
│  Generates untrusted Intent                             │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              DataFence Boundary                         │
│                                                         │
│  1. Parse Request (Actor + Intent)                      │
│  2. Evaluate Policy → ALLOW / DENY                      │
│  3. Create ExecutionPlan (if allowed)                   │
│  4. Execute via Connector                               │
│  5. Validate Result                                     │
│  6. Generate Evidence                                   │
│                                                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  Database                               │
│  Executes DataFence's SQL (from ExecutionPlan)          │
│  NOT the LLM's SQL                                      │
└─────────────────────────────────────────────────────────┘
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for details.

## Security Invariants

The killer demo proves these guarantees:

1. An unauthorized field can never reach the connector
2. An unauthorized row can never be returned
3. An unauthorized tenant can never be accessed
4. An unauthorized operation can never reach the connector
5. A missing policy fails closed
6. An invalid policy fails closed
7. A connector cannot execute arbitrary SQL from the LLM
8. Result validation rejects unauthorized fields
9. Actor identity cannot be changed by the LLM
10. Policy version is recorded in evidence
11. Every execution receives a unique execution ID
12. Every allowed execution produces provenance
13. Every denied request produces an auditable decision

See `tests/test_security_invariants.py`.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/datafence.git
cd datafence

# Install dependencies
pip install -e .

# Run the killer demo
cd demos
python killer_demo.py

# Run security tests
pytest tests/test_security_invariants.py -v
```

## What DataFence Is NOT

- ❌ A complete enterprise product (yet—it's a prototype)
- ❌ A replacement for IAM or database permissions
- ❌ A guarantee against LLM hallucinations
- ❌ A prompt injection detector
- ❌ GDPR/HIPAA/PCI compliant by itself
- ❌ Benchmarked for production performance

DataFence is an **additional security layer** that enforces deterministic authorization.

## Example: The Wrong Way vs The Right Way

### ❌ Wrong: Execute LLM SQL Directly

```python
# DANGEROUS
llm_sql = agent.generate_sql("Show transactions")
results = database.execute(llm_sql)  # Uncontrolled!
```

### ✅ Right: DataFence Boundary

```python
# SAFE
intent = agent.generate_intent("Show transactions")
result = datafence.execute(actor, intent)
# DataFence creates ExecutionPlan
# Database executes the authorized plan
# Result validated before returning
```

## Current Focus

We're NOT adding more features.

We're proving the core security boundary works.

**Next steps**:
1. Harden the ExecutionPlan abstraction
2. Refactor existing connectors
3. Comprehensive adversarial testing
4. Real performance benchmarks
5. Production deployment guide

## Documentation

- [`demos/README.md`](demos/README.md) - 30-second killer demo
- [`ARCHITECTURE.md`](ARCHITECTURE.md) - System design
- `tests/test_security_invariants.py` - Security proofs

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 - See [LICENSE](LICENSE).

## Security

Report security issues to [security@datafence.dev](mailto:security@datafence.dev).

**Do not** open public GitHub issues for security vulnerabilities.

---

## The Bottom Line

**This is a prototype.**

The killer demo proves the security boundary concept works.

The next phase is making it production-ready.

**The model proposes. DataFence decides.**

That's the product we're building.
