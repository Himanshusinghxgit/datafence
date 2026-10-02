# Attack Notes — Historical Research

> **HISTORICAL DOCUMENT — describes the v0.3 architecture, which has been superseded.**
>
> The v0.3 architecture bundled authorization with execution (`DataFenceBoundary.execute()`).
> That architecture was replaced in v1.0. DataFence now issues `AuthorizedExecution`
> (a signed capability) and the customer's connector handles execution.
>
> The attack analysis below documents vulnerabilities in the v0.3 design that motivated
> the v1.0 separation.

---

## v0.3 Architecture (superseded)

The v0.3 boundary used a single `execute()` method that authorized *and* executed:

```
Actor + Intent → Request
    ↓
DataFenceBoundary.execute()
    ├─ Policy Evaluation
    ├─ ExecutionPlan Creation
    ├─ Connector.execute_plan()
    └─ Result Validation
    ↓
AllowedRequest | DeniedRequest
```

### Attack surface in v0.3

1. **ExecutionPlan direct construction** — `ExecutionPlan` was a plain dataclass with no cryptographic protection. An attacker could call `ExecutionPlan(...)` directly and pass it to `SQLiteConnector.execute_plan()` bypassing authorization entirely.

2. **Connector direct instantiation** — `SQLiteConnector(db_path)` was public. An attacker could instantiate the connector and call `execute_plan()` directly with a forged plan.

3. **No audience binding** — No mechanism to verify that a capability was issued for a specific service.

---

## v1.0 Mitigations

- `DataFenceBoundary` has only `authorize()` — no `execute()`.
- `AuthorizedExecution` is HMAC-SHA256 signed covering all security-relevant fields.
- `CapabilityVerifier` verifies signature, expiry, and audience before any execution.
- The connector is customer-owned — DataFence cannot instantiate it.
- Typed predicates (`PredicateOperator`) prevent operator coercion.
- The registry rejects unknown resources, fields, and operations.

See `tests/test_security_invariants.py` and `tests/test_architecture_boundary.py`
for the security invariant test suite.

---

## Attack attempt scripts

The `attacks/` directory contains v0.3-era attack attempt scripts.
These scripts will fail with import errors because the APIs they target
(`boundary.execute`, `ExecutionPlan`, `create_banking_policy`) no longer exist.
They are retained for historical reference only.
