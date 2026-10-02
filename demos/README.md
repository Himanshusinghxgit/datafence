# DataFence v1 — Authorization Boundary Demos

This directory contains runnable demonstrations of the DataFence v1
authorization boundary.

## Architecture

```
Principal (from app auth)
    +
Intent (from AI agent — untrusted)
    ↓
DataFenceBoundary.authorize()     ← DataFence decides
    ↓
AuthorizedExecution (HMAC-signed)
    ↓
connector.execute()               ← Customer executes
    ↓
ConnectorResult
```

DataFence does **not** execute database operations.
The customer's connector does.

## killer_demo.py

Seven scenarios that prove the security boundary works:

| Scenario | What it proves |
|----------|---------------|
| 1. Authorized read | `authorize()` returns a signed capability; connector executes and returns only authorized fields |
| 2. Tenant isolation | Policy-injected row filter overrides agent-supplied tenant — no cross-tenant data returned |
| 3. Restricted field | `card_number` denied even when explicitly requested |
| 4. Unknown resource | Unregistered resource fails closed |
| 5. Denied operation | `DELETE` blocked by policy |
| 6. Forged capability | Tampered `AuthorizedExecution` rejected by connector signature check |
| 7. Verifier | `CapabilityVerifier` accepts valid key, rejects wrong key |

### Run it

From the repo root:

```bash
python -m demos.killer_demo
```

## Key point

```python
# DataFence decides:
authorized = fence.authorize(principal, intent)

# Customer executes:
result = connector.execute(authorized)
```

`DataFenceBoundary` has no `execute()` method.
