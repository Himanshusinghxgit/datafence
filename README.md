# DataFence v0.4.0

**A deterministic authorization boundary for AI access to enterprise data.**

[![Version](https://img.shields.io/badge/version-0.4.0-orange.svg)](https://github.com/yourusername/datafence/releases)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Status: Prototype

DataFence v0.4 is a **security-hardened prototype**. The core authorization boundary is operational and tested, but this is not production-ready software.

## The Problem

AI agents need access to enterprise data. But:
- LLMs can hallucinate queries
- Agents can request unauthorized data
- Models can cross tenant boundaries
- Probabilistic systems need deterministic controls

## The Solution

```
    AI Agent
       │
       ├─ "Show me transactions"
       ▼
  DataFence Boundary
       │
       ├─ Policy Evaluation
       ├─ Create Signed Capability
       ├─ Execute & Validate
       ▼
    Database
```

**Core Principle:** The model proposes. DataFence decides.

## Quick Start

```python
from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor, Intent, Operation
from datafence.core.policy_engine import create_banking_demo_policy
from datafence.connectors.sqlite_connector import SQLiteConnector

# Create boundary (v0.4 uses factory method)
boundary = DataFenceBoundary.create(
    policy_engine=create_banking_demo_policy(),
    connector_factory=SQLiteConnector,
    database_path="data.db"
)

# AI agent request
actor = Actor(id="agent:finance", tenant_id="acme-corp")
intent = Intent(
    resource="transactions",
    operation=Operation.READ,
    fields=["id", "merchant", "amount"]
)

# Execute through boundary
result = boundary.execute(actor, intent)

if hasattr(result, 'execution_result'):
    print(f"Allowed: {result.execution_result.row_count} rows")
else:
    print(f"Denied: {result.decision.reasons}")
```

## Architecture (v0.4)

```
┌─────────────────────────────────────────────────┐
│              AI Agent / LLM                     │
│  "Show me recent transactions"                  │
└─────────────────┬───────────────────────────────┘
                  │ Intent
                  ▼
┌─────────────────────────────────────────────────┐
│         DataFenceBoundary (v0.4)                │
│                                                 │
│  1. Policy Evaluation                           │
│     ├─ Field authorization                      │
│     ├─ Operation authorization                  │
│     └─ Tenant isolation                         │
│                                                 │
│  2. Create AuthorizedExecution                  │
│     ├─ HMAC-SHA256 signature                    │
│     ├─ Cryptographic capability                 │
│     └─ Cannot be forged                         │
│                                                 │
│  3. Execute (Private Connector)                 │
│     ├─ Verify signature                         │
│     ├─ Generate SQL from capability             │
│     └─ Prepared statements                      │
│                                                 │
│  4. Validate Result                             │
│     └─ Check returned fields                    │
└─────────────────┬───────────────────────────────┘
                  │ Verified Data
                  ▼
┌─────────────────────────────────────────────────┐
│              Application                        │
└─────────────────────────────────────────────────┘
```

## Security Model (v0.4)

### What v0.4 Protects Against

✅ **Capability Forgery** - HMAC signature prevents forged authorization  
✅ **Connector Bypass** - No `execute_plan()`, connector verifies signatures  
✅ **Tenant Isolation** - Policy enforces tenant boundaries  
✅ **Field Leakage** - Denied fields cannot reach connector  
✅ **Capability Tampering** - Mutation breaks HMAC signature  
✅ **SQL Injection** - Prepared statements + structured queries  

### What v0.4 Does NOT Protect

❌ **Full Python Runtime Compromise** - Explicitly out of scope  
❌ **Database-Level Authorization** - Assumes trusted DB connection  
❌ **Actor Authentication** - Application's responsibility  

### Trust Boundaries

**Application's Responsibility:**
- Authenticate actors before calling DataFence
- Provide verified Actor objects
- Manage sessions and identity

**DataFence's Responsibility:**
- Enforce policy for provided Actor
- Ensure authorized operations only
- Generate cryptographic proof (evidence)
- Validate results

## Security Improvements (v0.3 → v0.4)

| Vulnerability | v0.3 Status | v0.4 Status |
|---------------|-------------|-------------|
| ExecutionPlan forgery | ❌ Anyone can construct | ✅ HMAC signature required |
| Connector bypass | ❌ Public `execute_plan()` | ✅ Removed, signature verified |
| Capability tampering | ❌ `frozen=True` bypassable | ✅ Breaks HMAC signature |
| Tenant isolation | ⚠️ Policy only | ✅ Policy + signed capability |

## What's Implemented (v0.4)

### Core Security
✅ Cryptographic capability model (HMAC-SHA256)  
✅ Signed AuthorizedExecution (prevents forgery)  
✅ Signature verification before execution  
✅ Policy-based authorization  
✅ Column-level security (field restrictions)  
✅ Row-level security (tenant isolation)  
✅ Operation controls (READ operations)  
✅ Result validation (field enforcement)  
✅ Evidence generation  
✅ Audit trail  

### Connectors
✅ SQLite connector (v0.4 with signature verification)  

### Testing & Security
✅ Adversarial test suite (12 security tests)  
✅ Attack verification (5 critical v0.3 attacks blocked)  
✅ Killer demo (6 security scenarios)  

## What's NOT Implemented (Yet)

### Database Connectors
❌ PostgreSQL connector (exists in legacy v0.1-v0.3, not migrated to v0.4)  
❌ Athena connector (legacy only)  
❌ Snowflake connector (legacy only)  

**Note:** Legacy connectors lack v0.4 cryptographic signatures and are marked deprecated.

### Features
❌ Write operations (INSERT, UPDATE, DELETE) - v0.4 is read-only  
❌ Resource abstraction layer (typed resources, schema validation)  
❌ Advanced policy engine (complex conditions, obligations, approval flows)  

### Integrations
❌ MCP integration  
❌ LangChain integration  
❌ OpenAI/Anthropic adapters  
❌ REST API  

### Operations
❌ Policy management UI  
❌ Monitoring & metrics  
❌ Deployment tools  
❌ Key management system  

## Testing

```bash
# Run v0.4 security tests
pytest tests/test_v04_security.py -v

# Verify attacks are blocked
python attacks/verify_v04_blocks_attacks.py

# Run killer demo
python demos/killer_demo.py
```

## Roadmap

- **v0.4** ✅ Core security boundary with cryptographic capabilities
- **v0.5** → Enhanced policy model (richer conditions, constraints)
- **v0.6** → Resource abstraction (typed resources, validated identifiers)
- **v0.7** → PostgreSQL connector
- **v0.8** → Data warehouse connectors (Athena, Snowflake)
- **v0.9** → Agent integrations (OpenAI, Claude, LangChain, MCP)
- **v1.0** → External security review + production hardening

## Known Limitations

1. **Actor Authentication** - Application must authenticate actors
2. **Single Database Connection** - Connector doesn't use actor identity for DB auth
3. **Read-Only** - Only SELECT queries implemented
4. **SQLite Only** - No production database connectors yet
5. **Simple Policy Engine** - Basic field/operation/tenant controls only

## Installation

```bash
git clone https://github.com/yourusername/datafence.git
cd datafence
pip install -e .
```

## Documentation

- `demos/README.md` - 30-second killer demo
- `CAPABILITY_ARCHITECTURE_EVALUATION.md` - Security design decisions
- `tests/test_v04_security.py` - Security test suite
- `attacks/` - Adversarial testing results

## License

Apache 2.0

## Security

This is prototype software. Do NOT use in production without:
- External security review
- Penetration testing
- Proper key management
- Database-level authorization
- Actor authentication integration

For security issues: [Report privately]

---

**Version:** 0.4.0  
**Status:** Prototype (Security Hardened)  
**Next Milestone:** v0.5 (Enhanced Policy Model)
