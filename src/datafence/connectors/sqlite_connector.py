"""
SQLite connector for DataFence (v1.0 - typed IR, safe identifier compilation).

CRITICAL SECURITY PROPERTIES:
    - Connector verifies cryptographic signature before execution
    - Connector accepts ONLY signed AuthorizedExecution capabilities
    - Identifiers (table/column names) are validated against a strict
      allowlist pattern — NO f-string interpolation of untrusted strings
    - Connector does NOT accept raw SQL from the LLM
    - Connector rejects forged/tampered capabilities

Flow:
    AuthorizedExecution (signed)
        → verify_signature()
        → _compile_select()     ← identifiers validated here
        → prepared statement    ← values parameterised
        → database
        → result filtered to authorised fields

The SQL compiler receives AuthorizedExecution and builds the query entirely
from validated identifiers.  Values are always passed as query parameters,
never interpolated.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.resources import validate_identifier
from datafence.core.types import Operation


class SQLiteConnector:
    """
    SQLite connector with cryptographic capability verification (v1.0).

    The connector:
    1. Verifies HMAC signature on AuthorizedExecution — rejects forgeries.
    2. Validates every identifier (table + column names) before use.
    3. Generates parameterised SQL — values never interpolated.
    4. Returns ONLY the fields listed in the capability.

    SECURITY:
    - Signing key received at construction (NEVER through execute()).
    - Capability signature verified BEFORE any SQL is generated.
    - Identifier validation prevents injection even from a compromised policy.

    This connector is INTERNAL to DataFenceBoundary.
    Application code should not instantiate it directly.
    """

    def __init__(self, database_path: str, signing_key: bytes) -> None:
        """
        Initialise the connector.

        Args:
            database_path : Path to the SQLite database file.
            signing_key   : 32-byte HMAC key shared with DataFenceBoundary.
        """
        self.database_path = database_path
        self._signing_key = signing_key          # PRIVATE — never expose
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """
        Execute a signed capability.

        This is the ONLY execution method — no execute_plan(), no execute_sql().

        Raises:
            CapabilityVerificationError: If the HMAC signature is invalid.
        """
        # 1. Verify cryptographic signature
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid capability signature for execution "
                f"{capability.execution_id!r}. "
                "The capability may be forged or tampered with."
            )
        if capability.is_expired():
            raise CapabilityVerificationError(
                f"Expired capability for execution {capability.execution_id!r}"
            )

        # 2. Compile SQL from verified capability
        sql, params = self._compile(capability)

        # 3. Execute
        cursor = self.connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        # 4. Return only authorised fields (defence-in-depth)
        authorised = set(capability.selected_fields)
        return [
            {col: row[col] for col in capability.selected_fields if col in row.keys()}
            for row in rows
        ]

    # ------------------------------------------------------------------
    # SQL compiler
    # ------------------------------------------------------------------

    def _compile(
        self, capability: AuthorizedExecution
    ) -> tuple[str, dict[str, Any]]:
        if capability.operation == Operation.READ:
            return self._compile_select(capability)
        raise NotImplementedError(
            f"Operation {capability.operation!r} not implemented in SQLiteConnector"
        )

    def _compile_select(
        self, capability: AuthorizedExecution
    ) -> tuple[str, dict[str, Any]]:
        """
        Compile a SELECT statement from a verified AuthorizedExecution.

        All identifiers (table + column names) are validated with
        validate_identifier() before being placed in the query.
        All filter values are passed as named parameters — never interpolated.

        Example output:
            SELECT id, merchant, amount, timestamp
            FROM transactions
            WHERE tenant_id = :filter_0
            LIMIT 100
        """
        # Validate resource name
        resource = validate_identifier(
            capability.resource, context="resource name"
        )

        # Validate and quote field names
        fields_sql = ", ".join(
            validate_identifier(f, context="field name")
            for f in capability.selected_fields
        )

        sql = f"SELECT {fields_sql} FROM {resource}"

        # WHERE clause — filter values always parameterised
        params: dict[str, Any] = {}
        if capability.enforced_filters:
            conditions: list[str] = []
            for i, (col, val) in enumerate(capability.enforced_filters.items()):
                safe_col = validate_identifier(col, context="filter column")
                param_name = f"filter_{i}"
                conditions.append(f"{safe_col} = :{param_name}")
                params[param_name] = val
            sql += " WHERE " + " AND ".join(conditions)

        # LIMIT — integer, never a string, never from the LLM
        sql += f" LIMIT {int(capability.limit)}"

        return sql, params

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self.connection:
            self.connection.close()

    def __enter__(self) -> "SQLiteConnector":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Malicious connector — TESTING ONLY
# ---------------------------------------------------------------------------

class MaliciousConnector(SQLiteConnector):
    """
    Test helper: a connector that injects unauthorised fields into results.

    DataFence's ResultValidator MUST catch and reject these.
    Signature verification is intentionally skipped so the test isolates
    the validation layer.
    """

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        # Skip signature verification — we're testing ResultValidator, not HMAC
        sql, params = self._compile(capability)
        cursor = self.connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        return [
            {**dict(row), "card_number": "1234-5678-9012-3456", "ssn": "123-45-6789"}
            for row in rows
        ]


# ---------------------------------------------------------------------------
# Demo database factory
# ---------------------------------------------------------------------------

def create_demo_database(database_path: str, signing_key: bytes) -> SQLiteConnector:
    """
    Create (or re-create) the demo database and return a connector.

    Schema
    ------
    customers    (id, tenant_id, name, email, ssn, account_number)
    transactions (id, tenant_id, customer_id, merchant, amount, timestamp, card_number)
    accounts     (id, tenant_id, customer_id, account_number, balance)

    Two tenants are populated: tenant_a and tenant_b.

    Args:
        database_path : Path to SQLite file.
        signing_key   : 32-byte HMAC key for the returned connector.

    Returns:
        Configured SQLiteConnector connected to the populated database.
    """
    conn = sqlite3.connect(database_path)
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS customers")
    cur.execute("DROP TABLE IF EXISTS transactions")
    cur.execute("DROP TABLE IF EXISTS accounts")

    cur.execute("""
        CREATE TABLE customers (
            id             INTEGER PRIMARY KEY,
            tenant_id      TEXT NOT NULL,
            name           TEXT NOT NULL,
            email          TEXT NOT NULL,
            ssn            TEXT NOT NULL,
            account_number TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE transactions (
            id          INTEGER PRIMARY KEY,
            tenant_id   TEXT NOT NULL,
            customer_id INTEGER NOT NULL,
            merchant    TEXT NOT NULL,
            amount      REAL NOT NULL,
            timestamp   TEXT NOT NULL,
            card_number TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE accounts (
            id             INTEGER PRIMARY KEY,
            tenant_id      TEXT NOT NULL,
            customer_id    INTEGER NOT NULL,
            account_number TEXT NOT NULL,
            balance        REAL NOT NULL
        )
    """)

    # Tenant A
    cur.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?,?)",
        [
            (1, "tenant_a", "Alice Johnson", "alice@tenant-a.com", "123-45-6789", "ACC-A-001"),
            (2, "tenant_a", "Bob Smith",     "bob@tenant-a.com",   "234-56-7890", "ACC-A-002"),
        ],
    )
    cur.executemany(
        "INSERT INTO transactions VALUES (?,?,?,?,?,?,?)",
        [
            (1, "tenant_a", 1, "Amazon",    49.99, "2024-01-15 10:30:00", "4532-1111-2222-3333"),
            (2, "tenant_a", 1, "Starbucks",  5.50, "2024-01-15 14:20:00", "4532-1111-2222-3333"),
            (3, "tenant_a", 2, "Target",   125.00, "2024-01-16 09:15:00", "4532-4444-5555-6666"),
        ],
    )
    cur.executemany(
        "INSERT INTO accounts VALUES (?,?,?,?,?)",
        [
            (1, "tenant_a", 1, "ACC-A-001",  5000.00),
            (2, "tenant_a", 2, "ACC-A-002", 12000.00),
        ],
    )

    # Tenant B
    cur.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?,?)",
        [
            (3, "tenant_b", "Charlie Brown", "charlie@tenant-b.com", "345-67-8901", "ACC-B-001"),
            (4, "tenant_b", "Diana Prince",  "diana@tenant-b.com",   "456-78-9012", "ACC-B-002"),
        ],
    )
    cur.executemany(
        "INSERT INTO transactions VALUES (?,?,?,?,?,?,?)",
        [
            (4, "tenant_b", 3, "Walmart",     75.25, "2024-01-15 11:00:00", "5555-7777-8888-9999"),
            (5, "tenant_b", 3, "Shell Gas",   45.00, "2024-01-16 08:30:00", "5555-7777-8888-9999"),
            (6, "tenant_b", 4, "Apple Store", 999.00, "2024-01-16 15:45:00", "5555-1111-2222-3333"),
        ],
    )
    cur.executemany(
        "INSERT INTO accounts VALUES (?,?,?,?,?)",
        [
            (3, "tenant_b", 3, "ACC-B-001",  8000.00),
            (4, "tenant_b", 4, "ACC-B-002", 25000.00),
        ],
    )

    conn.commit()
    conn.close()

    return SQLiteConnector(database_path, signing_key)
