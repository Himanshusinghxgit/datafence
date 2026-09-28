# DataFence v0.3 - Attack Surface Analysis

## Initial Code Review Complete

### Architecture Overview

**Intended Flow:**
```
Untrusted LLM/Agent
    ↓
Actor + Intent → Request
    ↓
DataFenceBoundary.execute()
    ├─ Policy Evaluation
    ├─ ExecutionPlan Creation
    ├─ Connector.execute_plan()
    ├─ Result Validation
    └─ Evidence Generation
    ↓
AllowedRequest | DeniedRequest
```

### Key Components Analyzed

1. **Core Types** (`src/datafence/core/types.py`):
   - `Actor` - frozen dataclass (id, tenant_id, metadata)
   - `Intent` - frozen dataclass (untrusted LLM request)
   - `ExecutionPlan` - frozen dataclass (THE authorization artifact)
   - `ExecutionResult`, `Evidence`, `AuditEvent` - audit trail

2. **Boundary** (`src/datafence/core/boundary.py`):
   - `DataFenceBoundary.execute(actor, intent)` - main entry point
   - `PolicyEngine` protocol
   - `Connector` protocol  
   - `ResultValidator` - validates results match plan
   - Fail-closed on all exceptions

3. **Policy Engine** (`src/datafence/core/policy_engine.py`):
   - `SimplePolicyEngine` - field/operation/tenant controls
   - `ResourcePolicy` - per-resource config

4. **SQLite Connector** (`src/datafence/connectors/sqlite_connector.py`):
   - `SQLiteConnector.execute_plan(plan)` - accepts ONLY ExecutionPlan
   - Generates SQL from plan (not from LLM)
   - Uses prepared statements
   - `MaliciousConnector` - test double that adds unauthorized fields

5. **Public API** (`src/datafence/__init__.py`):
   - OLD API: exports `DataFence`, `ExecutionRequest`, `Actor`, etc.
   - NOTE: This is the OLD v1.0 API, not the v0.3 refactored API!
   - CRITICAL: There are TWO parallel implementations!

### CRITICAL DISCOVERY #1: Dual Implementation

The repository contains TWO implementations:

**v0.3 Refactored Code** (demos/):
- `src/datafence/core/types.py` - ExecutionPlan model
- `src/datafence/core/boundary.py` - DataFenceBoundary
- `src/datafence/core/policy_engine.py` - SimplePolicyEngine
- `src/datafence/connectors/sqlite_connector.py` - NEW connector
- `demos/killer_demo.py` - uses v0.3 API

**v1.0 Old Code** (main package):
- `src/datafence/__init__.py` - exports old API
- `src/datafence/core/engine.py` - OLD DataFence class?
- `src/datafence/core/context.py` - OLD Actor/RequestContext?
- `src/datafence/connectors/` - OLD connector implementations

**THREAT:** If the old v1.0 code is still accessible via imports, attackers can bypass v0.3 boundary entirely!

---

## Attack Surface Map

### Entry Points to Data Access

| API | File | Can Access Data? | Requires Authorization? | Threat |
|-----|------|------------------|------------------------|---------|
| `DataFenceBoundary.execute()` | boundary.py | Yes | Yes | LOW - Protected |
| `SQLiteConnector.execute_plan()` | sqlite_connector.py | Yes | ⚠️  Assumes valid plan | **HIGH** |
| `SQLiteConnector()` constructor | sqlite_connector.py | No | N/A | **MEDIUM** - Public |
| OLD `DataFence` API | \_\_init\_\_.py | Yes? | Unknown | **CRITICAL** |
| OLD Connectors | connectors/*.py | Yes? | Unknown | **CRITICAL** |

### Attack Vectors Identified (Before Testing)

#### CRITICAL Severity

1. **ExecutionPlan Direct Construction**
   - `ExecutionPlan` is a frozen dataclass
   - Anyone can call `ExecutionPlan.create(...)`
   - Anyone can call `ExecutionPlan(...)`  
   - No cryptographic verification
   - Status: **LIKELY VULNERABLE**

2. **Connector Direct Instantiation**
   - `SQLiteConnector(db_path)` is public
   - `connector.execute_plan(forged_plan)` is public
   - No verification that plan came from DataFence
   - Status: **CONFIRMED VULNERABLE**

3. **Actor Forgery**
   - `Actor(id="admin", tenant_id="victim")` is public
   - No authentication/verification
   - Actor is "trusted" but caller-created
   - Status: **CONFIRMED VULNERABLE**

4. **Old API Bypass**
   - v1.0 code may still be accessible
   - May have different security model
   - Status: **NEEDS INVESTIGATION**

#### HIGH Severity

5. **Frozen Dataclass Mutation**
   - `frozen=True` prevents normal mutation
   - BUT: `object.__setattr__()` can bypass
   - Can modify `actor`, `tenant_id`, `filters`, etc.
   - Status: **NEEDS TESTING**

6. **Tenant Isolation via SQL**
   - Enforced filters use string concatenation
   - Unclear if identifiers validated
   - Status: **NEEDS SQL INJECTION TESTING**

#### MEDIUM Severity

7. **Result Validation Bypass**
   - Validator checks field names only
   - Doesn't check nested objects, base64, etc.
   - Status: **NEEDS TESTING**

8. **Policy Version Injection**
   - Policy version comes from engine
   - But ExecutionPlan.create() accepts any string
   - Can attacker request old policy version?
   - Status: **NEEDS TESTING**

---

## Next: Begin Attack Attempts

Starting with Category A: ExecutionPlan Forgery...
