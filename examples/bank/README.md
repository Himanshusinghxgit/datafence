# DataFence — Banking Domain Example

This is a **domain-specific example** showing how a banking application
can use DataFence to protect its data backend. Banking concepts exist only
in this directory — they are not part of DataFence core.

## What this shows

- How to define a domain registry (`registry.py`) using `ResourceRegistry`
- How to write a domain policy (`policy.py`) using `DataFencePolicyEngine`
- How the generic `DataFenceBoundary` protects banking data without
  needing to know anything about banking

## Files

| File | Responsibility |
|------|---------------|
| `registry.py` | Banking resource registry (transactions, customers, accounts) |
| `policy.py` | Banking authorization policy (deny card_number, ssn, etc.) |
| `app.py` | End-to-end demo with 5 scenarios |

## Run it

```bash
python -m examples.bank.app
```

## Key point

`DataFenceBoundary`, `ResourceRegistry`, `DataFencePolicyEngine` are all
**domain-agnostic**. This example uses them for banking. Another team could
use the same classes for healthcare, SaaS, or government data — no code
change needed in DataFence core.

For the primary quickstart, see [`examples/basic/`](../basic/README.md).
