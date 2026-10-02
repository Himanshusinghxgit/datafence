# DataFence — Basic Example

This is the primary quickstart example. It uses neutral, domain-independent
resources (`orders`, `documents`, `customers`) to demonstrate the full
authorization flow.

## What this demonstrates

```
Authentication (application-owned)
        ↓
Principal + Intent
        ↓
DataFenceBoundary.authorize()    ← DataFence decides
        ↓
AuthorizedExecution (signed)
        ↓
connector.execute()              ← Customer executes
        ↓
ConnectorResult
```

## Files

| File | Responsibility |
|------|---------------|
| `registry.py` | Defines WHAT resources exist and their field schema |
| `policy.py` | Defines WHO can access WHAT, with what constraints |
| `connector.py` | Example customer-owned connector (in-memory) |
| `application.py` | Full end-to-end demonstration with 7 scenarios |

## Run it

From the repo root:

```bash
python -m examples.basic.application
```

## Scenarios demonstrated

1. **Authorized read** — principal reads their own tenant's orders
2. **Tenant isolation** — policy overrides agent-supplied tenant filter
3. **Restricted field blocked** — SSN cannot be accessed even when requested
4. **Unknown resource blocked** — unregistered resource is denied
5. **Denied operation** — DELETE is denied by policy
6. **Forged capability rejected** — tampered capability fails connector verification
7. **CapabilityVerifier** — customer-side signature verification

## Key takeaway

DataFence authorizes. Your connector executes. The AI never touches the database directly.
