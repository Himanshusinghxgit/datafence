# Reference Connectors

> **These are reference implementations only — NOT part of DataFence core.**

DataFence issues a signed `AuthorizedExecution` and stops there.
It does not own the database, the connection, the query, or the result.

These files show how a **customer-owned connector** can verify and execute
an `AuthorizedExecution` capability. Use them for local testing,
documentation, and understanding the contract. Rewrite them in your own
codebase for production.

---

## The minimal connector contract

Every connector must:

1. Receive `AuthorizedExecution` from your application.
2. Verify the HMAC signature — reject forgeries.
3. Verify expiry — reject stale capabilities.
4. Verify audience — reject mis-targeted capabilities.
5. Translate the typed IR to a backend call (use `capability.filter_constraints()`, `capability.selected_fields`, `capability.limit`).
6. Return only the authorized fields — DataFence never sees the results.

See `datafence/connectors/protocol.py` for the `DataConnector` protocol.

---

## Files

| File | Demonstrates |
|------|-------------|
| `memory.py` | In-memory dict store — fastest for unit tests |
| `sqlite_connector.py` | SQLite with parameterised SQL and identifier validation |
| `postgres_connector.py` | PostgreSQL (psycopg3) reference |
| `snowflake_connector.py` | Snowflake reference |
| `athena_connector.py` | AWS Athena reference |

---

## Architecture reminder

```
DataFenceBoundary.authorize()
        ↓
AuthorizedExecution  (HMAC-signed by DataFence)
        ↓
YOUR connector.execute(authorized)   ← you own this
        ↓
Your enterprise data
```

DataFence stops at `AuthorizedExecution`.
Everything below that line is yours.
