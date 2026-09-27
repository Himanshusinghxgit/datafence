# DataFence Architecture

**Status**: Prototype / Experimental (v0.3.0)

## What DataFence Is

DataFence is a **deterministic authorization and execution boundary** for AI agents accessing data.

The core principle:

> **The model proposes. DataFence decides.**

The database executes DataFence's authorized ExecutionPlan, not the LLM's untrusted request.

## What DataFence Is NOT

- ❌ A complete enterprise security product (yet)
- ❌ A replacement for IAM or database permissions
- ❌ A guarantee against LLM hallucinations
- ❌ A prompt injection detector
- ❌ GDPR/HIPAA/PCI compliant by itself

## The Core Abstraction: ExecutionPlan

```
LLM Request (untrusted)
        ↓
Policy Evaluation
        ↓
ExecutionPlan (authorized contract)
        ↓
Connector (executes ONLY the plan)
        ↓
Result Validation
        ↓
Verified Result + Evidence
```

### ExecutionPlan Structure

```python
@dataclass(frozen=True)
class ExecutionPlan:
    execution_id: str           # Unique ID
    actor: Actor                # WHO (immutable)
    resource: str               # WHAT table/resource
    operation: Operation        # WHICH operation
    selected_fields: list[str]  # WHICH fields (authorized)
    enforced_filters: dict      # WHICH rows (enforced)
    limit: int                  # HOW MANY rows
    policy_version: str         # WHICH policy
```

This is what the database executes. Not the LLM's SQL.

## Architecture Layers

### 1. Types (`core/types.py`)

First-class types, not dictionaries:

- `Actor` - Immutable identity (id, tenant_id)
- `Intent` - Untrusted request from LLM
- `Request` - Actor + Intent
- `PolicyDecision` - ALLOW / DENY
- `ExecutionPlan` - The authorized contract
- `ExecutionResult` - Validated result
- `Evidence` - Proof of compliance
- `AuditEvent` - Audit trail

### 2. Security Boundary (`core/boundary.py`)

```python
class DataFenceBoundary:
    def execute(self, actor: Actor, intent: Intent):
        # 1. Create Request
        # 2. Evaluate Policy → ALLOW / DENY
        # 3. If DENY: return DeniedRequest
        # 4. If ALLOW: create ExecutionPlan
        # 5. Execute via connector.execute_plan(plan)
        # 6. Validate result
        # 7. Generate evidence
        # 8. Return AllowedRequest
```

**Critical**: Fail closed on ALL errors.

### 3. Policy Engine (`core/policy_engine.py`)

Evaluates:
- Is this operation allowed?
- Which fields can be accessed?
- Which filters must be enforced? (e.g., tenant_id)
- What limits apply?

Returns `PolicyDecision` (ALLOW / DENY).

### 4. Connector (`connectors/sqlite_connector.py`)

```python
class SQLiteConnector:
    def execute_plan(self, plan: ExecutionPlan):
        # Generate SQL FROM the plan
        sql, params = self._generate_sql(plan)
        # Execute with prepared statement
        # Return ONLY authorized fields
```

**Critical**: No method to execute raw LLM SQL.

### 5. Result Validator (`core/boundary.py`)

Even if the connector is compromised:

```python
class ResultValidator:
    def validate(self, plan: ExecutionPlan, data: list):
        # Check: no unauthorized fields
        # Check: row count within limit
        # Return: ExecutionResult (verified=True/False)
```

Security on BOTH sides (request AND result).

## Security Invariants

What the killer demo proves:

1. ✅ Unauthorized field → Never reaches connector
2. ✅ Unauthorized row → Never returned (tenant isolation)
3. ✅ Unauthorized tenant → Never accessed
4. ✅ Unauthorized operation → Never reaches connector
5. ✅ Missing policy → Fails closed (DENY)
6. ✅ Invalid policy → Fails closed (DENY)
7. ✅ LLM SQL → Never executed directly
8. ✅ Malicious connector → Caught by result validation
9. ✅ Actor identity → Cannot be overridden
10. ✅ Policy version → Recorded in evidence
11. ✅ Execution ID → Unique for every request
12. ✅ Allowed request → Full provenance
13. ✅ Denied request → Auditable decision

See `tests/test_security_invariants.py` for proofs.

## The Execution Flow

```
User: "Show me transactions"
        ↓
    LLM Agent
        ↓
    generates Intent
        {
          resource: "transactions",
          operation: READ,
          fields: ["*"],  // SELECT *
        }
        ↓
    DataFence Boundary
        ↓
    Policy Evaluation
        operation: READ → allowed ✓
        resource: transactions → allowed ✓
        fields: * → restrict to authorized ⚠
        ↓
    ExecutionPlan Created
        {
          selected_fields: ["id", "merchant", "amount"],
          enforced_filters: {"tenant_id": "tenant_a"},
          limit: 100
        }
        ↓
    Connector Generates SQL
        SELECT id, merchant, amount
        FROM transactions
        WHERE tenant_id = :tenant_id
        LIMIT 100
        ↓
    Database Executes
        (DataFence's SQL, NOT LLM's "SELECT *")
        ↓
    Result Validation
        ✓ No unauthorized fields
        ✓ Row count within limit
        ↓
    Evidence Generated
        {
          execution_id: "exec_a1b2...",
          policy_version: "banking-v1",
          row_count: 3
        }
        ↓
    Verified Result Returned
```

## What's Implemented (v0.3.0)

### Core ✅
- ExecutionPlan abstraction
- DataFence Boundary with fail-closed
- Policy engine (simple, demo-ready)
- SQLite connector (ExecutionPlan-only)
- Result validation
- Evidence generation
- Audit events

### Demos ✅
- Killer demo (6 scenarios)
- Security invariant tests (13+ tests)
- Local SQLite database
- 2 tenants, realistic data

### What's NOT Implemented

- ❌ Production connectors (PostgreSQL, Athena, Snowflake need refactoring)
- ❌ YAML policy file loading
- ❌ PII detection/redaction (exists but not integrated with new core)
- ❌ SQL firewall (exists but not integrated)
- ❌ Framework adapters (OpenAI, Claude, LangChain exist but not refactored)
- ❌ REST API (exists but not refactored)
- ❌ CLI (exists but not refactored)
- ❌ Monitoring/metrics (exists but not integrated)

## Current Project Structure

```
datafence/
├── src/datafence/
│   ├── core/
│   │   ├── types.py              ✅ NEW - First-class types
│   │   ├── boundary.py           ✅ NEW - Security boundary
│   │   ├── policy_engine.py      ✅ NEW - Policy evaluation
│   │   └── [old files]           ⚠️  Need refactoring
│   │
│   ├── connectors/
│   │   ├── sqlite_connector.py   ✅ NEW - ExecutionPlan-only
│   │   └── [old files]           ⚠️  Need refactoring
│   │
│   ├── integrations/             ⚠️  Experimental - Not refactored
│   ├── security/                 ⚠️  Experimental - Not integrated
│   ├── monitoring/               ⚠️  Experimental - Not integrated
│   └── api.py, cli.py            ⚠️  Experimental - Not refactored
│
├── demos/
│   ├── killer_demo.py            ✅ NEW - 6 scenarios
│   └── README.md                 ✅ NEW - 30-second proof
│
└── tests/
    └── test_security_invariants.py  ✅ NEW - 13+ tests
```

## Roadmap

### Phase 1: Harden Core (Current)
- ✅ ExecutionPlan abstraction
- ✅ Security boundary
- ✅ Killer demo
- ✅ Security tests

### Phase 2: Refactor Existing
- [ ] Refactor PostgreSQL connector for ExecutionPlan
- [ ] Refactor Athena connector for ExecutionPlan
- [ ] Refactor Snowflake connector for ExecutionPlan
- [ ] Integrate SQL firewall with boundary
- [ ] Integrate PII detection with boundary
- [ ] YAML policy file loader

### Phase 3: Framework Adapters
- [ ] Refactor OpenAI adapter
- [ ] Refactor Claude adapter
- [ ] Refactor LangChain adapter
- [ ] Refactor Langflow component
- [ ] MCP integration (new)

### Phase 4: Production Readiness
- [ ] Comprehensive test suite
- [ ] Performance benchmarks (real measurements)
- [ ] Production deployment guide
- [ ] Adversarial security testing
- [ ] Documentation

## Design Decisions

### Why ExecutionPlan?

**Before**: LLM SQL → Database (dangerous)

**After**: LLM Intent → ExecutionPlan → Database (safe)

The ExecutionPlan is the authorized contract. It's what proves DataFence made the decision, not the LLM.

### Why Fail Closed?

Every error results in DENY:
- Policy evaluation error → DENY
- ExecutionPlan creation error → DENY
- Connector execution error → DENY
- Result validation error → DENY

Safety over availability.

### Why Result Validation?

Defense in depth. Even if:
- The connector is compromised
- The database is misconfigured
- SQL generation has bugs

Result validation catches unauthorized data.

### Why Frozen Dataclasses?

Immutability = security.

`Actor` cannot be modified after creation.
`ExecutionPlan` cannot be modified after authorization.

## Performance

**Current**: Not benchmarked.

**Claim**: None.

The killer demo runs in seconds locally. That's all we know.

Production performance depends on:
- Database latency
- Network latency
- Policy complexity
- Result size
- Hardware

Don't make blanket claims until measured.

## Compliance

DataFence does NOT make your organization compliant with:
- GDPR
- HIPAA
- PCI DSS
- SOC 2
- Any regulation

It provides **controls** that may support compliance requirements.

Compliance requires:
- Legal review
- Security audit
- Process documentation
- Organizational controls
- Much more than a Python package

## Security

DataFence enforces policies at the execution boundary.

It does NOT:
- Prevent LLM hallucinations
- Detect prompt injection
- Secure the LLM itself
- Secure the infrastructure
- Replace IAM or database permissions

It's an **additional layer** that enforces deterministic authorization.

## The Product Vision

Not: "AI security toolkit with lots of features"

But: "Deterministic authorization boundary for AI agents"

The moat is NOT:
- SQL firewall
- PII detection
- Framework adapters
- Monitoring
- Deployment

The moat IS:

> **The database executes ONLY what DataFence authorizes.**

That's the product.

## Current Status

**Version**: 0.3.0 (Prototype)

**What Works**: Killer demo proves the security boundary

**What Doesn't**: Production connectors, integrations need refactoring

**Next**: Harden core, refactor existing code to match new architecture

## Getting Started

```bash
# Run the killer demo
cd demos
python killer_demo.py

# Run security tests
pytest tests/test_security_invariants.py -v
```

Read `demos/README.md` for the 30-second proof.

---

**Bottom Line**: DataFence is a prototype proving that deterministic authorization at the AI-data boundary is possible and valuable. The killer demo shows it works. Now we need to make it production-ready.
