# Connector Guide

## Ownership model

DataFence is an **authorization boundary**, not an execution engine.

```
Principal (your app auth layer)
    + Intent (AI agent request)
          ↓
DataFenceBoundary.authorize()
          ↓
AuthorizedExecution  ←── signed capability
          ↓
Your connector  ←── you own this
          ↓
Enterprise data
```

DataFence issues a cryptographically signed `AuthorizedExecution` capability.
**Your connector** receives that capability, verifies the signature, and
executes the operation using your existing data-access layer.

DataFence core does **not** ship database drivers, connection pools, or
SQL execution code.

---

## The connector contract

Any object with an `execute(capability: AuthorizedExecution) -> ConnectorResult`
method satisfies the `DataConnector` protocol:

```python
from datafence.connectors import DataConnector, ConnectorResult
from datafence.core.capability import AuthorizedExecution, CapabilityVerifier

class MyConnector:
    def __init__(self, signing_key: bytes) -> None:
        self._verifier = CapabilityVerifier(signing_key, expected_audience="my-service")
        # your database connection goes here

    def execute(self, capability: AuthorizedExecution) -> ConnectorResult:
        # 1. Verify — raises CapabilityVerificationError on failure
        self._verifier.verify(capability)

        # 2. Translate the capability into your backend query
        #    Use capability.selected_fields and capability.filter_constraints()
        rows = self._query(
            resource=capability.resource,
            fields=capability.selected_fields,
            predicates=capability.filter_constraints(),
            limit=capability.limit,
        )

        # 3. Return results
        return ConnectorResult(
            rows=rows,
            row_count=len(rows),
            execution_id=capability.execution_id,
        )
```

### `ConnectorResult`

```python
@dataclass
class ConnectorResult:
    rows: list[dict[str, Any]]
    row_count: int
    execution_id: str            # echoed from capability for audit correlation
    metadata: dict[str, Any]     # optional connector-supplied metadata
```

---

## Reference implementation

A minimal in-memory connector for tests and quickstart examples is provided
under `examples/reference_connector/memory.py`.  It demonstrates the full
contract without any database dependency.  **It is not part of the installable
package and must not be used in production.**

```python
from examples.reference_connector.memory import InMemoryReferenceConnector

connector = InMemoryReferenceConnector(
    data={"orders": [{"id": 1, "tenant_id": "acme", "total": 99.99}]},
    signing_key=key,
    expected_audience="my-service",
)
result = connector.execute(authorized)
```

---

## Implementing a production connector

### What the connector must do

1. **Verify** the `AuthorizedExecution` signature via `CapabilityVerifier.verify()`.
2. **Check** expiry and audience — `CapabilityVerifier` handles this for you.
3. **Translate** `capability.selected_fields` and `capability.filter_constraints()`
   into your backend's native query language (SQL, API call, SDK call, etc.).
4. **Do not** add fields or relax predicates — the capability is the policy ceiling.
5. **Return** a `ConnectorResult`; do not return raw backend objects.

### What the connector must NOT do

- Execute any operation without first calling `CapabilityVerifier.verify()`.
- Pass `capability.filter_constraints()` verbatim to a database as raw SQL.
  Always parameterize or use your ORM's typed API.
- Accept an `AuthorizedExecution` that it did not receive directly from
  `DataFenceBoundary.authorize()` via a trusted channel.

### PostgreSQL sketch

```python
import psycopg
from datafence.core.capability import AuthorizedExecution, CapabilityVerifier
from datafence.connectors import ConnectorResult

class PostgresConnector:
    def __init__(self, conn_string: str, signing_key: bytes, audience: str) -> None:
        self._verifier = CapabilityVerifier(signing_key, expected_audience=audience)
        self._conn = psycopg.connect(conn_string)

    def execute(self, capability: AuthorizedExecution) -> ConnectorResult:
        self._verifier.verify(capability)   # raises on failure

        cols = ", ".join(f'"{f}"' for f in capability.selected_fields)
        where_clauses = []
        params: list = []
        for pred in capability.filter_constraints():
            where_clauses.append(f'"{pred["field"]}" {pred["operator"]} %s')
            params.append(pred["value"])

        sql = f'SELECT {cols} FROM "{capability.resource}"'
        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)
        sql += f" LIMIT {capability.limit}"

        with self._conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

        return ConnectorResult(
            rows=rows, row_count=len(rows), execution_id=capability.execution_id
        )
```

---

## Security checklist for connector authors

- [ ] Call `CapabilityVerifier.verify()` before any database operation.
- [ ] Use parameterized queries — never interpolate predicate values into SQL.
- [ ] Quote all identifiers (`resource`, field names) with your driver's quoting API.
- [ ] Do not add columns or relax the row limit.
- [ ] Store or log `execution_id` for audit correlation.
- [ ] Rotate the shared signing key periodically; update both boundary and connector.

---

## Further reading

- [Architecture](architecture.md) — the full security model
- [examples/reference_connector/](../examples/reference_connector/) — in-memory reference
- [examples/basic/](../examples/basic/) — end-to-end quickstart
