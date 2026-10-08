"""
SQLite reference connector — for examples and tests only.

This file lives under ``examples/reference_connector/`` to make clear it is
NOT part of DataFence core.  DataFence does not own database connectors.

DataFence issues a signed ``AuthorizedExecution`` via
``DataFenceBoundary.authorize()``.  This connector receives that capability,
verifies it, and translates it into a SQLite query — demonstrating the full
customer-connector contract.

SECURITY PROPERTIES:
    - Verifies HMAC signature before any SQL is generated.
    - Accepts ONLY signed AuthorizedExecution capabilities.
    - All identifiers validated — no f-string interpolation of untrusted names.
    - All filter values passed as named query parameters, never interpolated.
    - Never executes raw SQL from the LLM.
    - Rejects forged, tampered, or expired capabilities.

For production use, re-implement this pattern in your own codebase using
your existing database/API layer.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.resources import validate_identifier
from datafence.core.types import Operation


class SQLiteConnector:
    """
    SQLite connector demonstrating the DataFence capability contract.

    Steps:
    1. Verify HMAC signature → reject forgeries.
    2. Validate identifiers → prevent injection.
    3. Build parameterised SQL → values never interpolated.
    4. Return ONLY the fields listed in the capability.
    """

    def __init__(
        self,
        database_path: str,
        signing_key: bytes,
        expected_audience: str = "datafence",
    ) -> None:
        self.database_path = database_path
        self._signing_key = signing_key
        self._expected_audience = expected_audience
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """Execute a signed capability against SQLite."""
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid signature on capability {capability.execution_id!r}"
            )
        if capability.is_expired():
            raise CapabilityVerificationError(f"Expired capability {capability.execution_id!r}")
        if capability.audience != self._expected_audience:
            raise CapabilityVerificationError("Capability audience mismatch")

        sql, params = self._compile(capability)
        cursor = self.connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [
            {col: row[col] for col in capability.selected_fields if col in row.keys()}
            for row in rows
        ]

    def _compile(self, capability: AuthorizedExecution) -> tuple[str, dict[str, Any]]:
        if capability.operation == Operation.READ:
            return self._compile_select(capability)
        raise NotImplementedError(f"Operation {capability.operation!r} not implemented")

    def _compile_select(self, capability: AuthorizedExecution) -> tuple[str, dict[str, Any]]:
        resource = validate_identifier(capability.resource, context="resource name")
        fields_sql = ", ".join(
            validate_identifier(f, context="field name") for f in capability.selected_fields
        )
        sql = f"SELECT {fields_sql} FROM {resource}"
        params: dict[str, Any] = {}
        constraints = capability.filter_constraints()
        if constraints:
            conditions: list[str] = []
            for i, constraint in enumerate(constraints):
                col = constraint["field"]
                operator = constraint["operator"]
                val = constraint.get("value")
                safe_col = validate_identifier(col, context="filter column")
                param_name = f"filter_{i}"
                if operator in {"IS NULL", "IS NOT NULL"}:
                    conditions.append(f"{safe_col} {operator}")
                elif operator in {"IN", "NOT IN"}:
                    values = list(val) if isinstance(val, (list, tuple, set)) else [val]
                    names = []
                    for idx, item in enumerate(values):
                        name = f"{param_name}_{idx}"
                        names.append(f":{name}")
                        params[name] = item
                    conditions.append(f"{safe_col} {operator} ({', '.join(names)})")
                else:
                    if operator not in {"=", "!=", "<", "<=", ">", ">="}:
                        raise ValueError(f"Unsupported operator: {operator!r}")
                    conditions.append(f"{safe_col} {operator} :{param_name}")
                    params[param_name] = val
            sql += " WHERE " + " AND ".join(conditions)
        sql += f" LIMIT {int(capability.limit)}"
        return sql, params

    def close(self) -> None:
        if self.connection:
            self.connection.close()

    def __enter__(self) -> SQLiteConnector:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def create_demo_database(
    database_path: str,
    signing_key: bytes,
    expected_audience: str = "datafence",
) -> SQLiteConnector:
    """
    Create a demo SQLite database with sample banking data and return a connector.

    Schema: customers, transactions, accounts (two tenants: tenant_a, tenant_b).
    """
    conn = sqlite3.connect(database_path)
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS customers")
    cur.execute("DROP TABLE IF EXISTS transactions")
    cur.execute("DROP TABLE IF EXISTS accounts")
    cur.execute("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL,
            name TEXT NOT NULL, email TEXT NOT NULL,
            ssn TEXT NOT NULL, account_number TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL,
            customer_id INTEGER NOT NULL, merchant TEXT NOT NULL,
            amount REAL NOT NULL, timestamp TEXT NOT NULL, card_number TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL,
            customer_id INTEGER NOT NULL, account_number TEXT NOT NULL, balance REAL NOT NULL
        )
    """)
    cur.executemany(
        "INSERT INTO customers VALUES (?,?,?,?,?,?)",
        [
            (1, "tenant_a", "Alice Johnson", "alice@a.com", "123-45-6789", "ACC-A-001"),
            (2, "tenant_a", "Bob Smith", "bob@a.com", "234-56-7890", "ACC-A-002"),
            (3, "tenant_b", "Charlie Brown", "charlie@b.com", "345-67-8901", "ACC-B-001"),
            (4, "tenant_b", "Diana Prince", "diana@b.com", "456-78-9012", "ACC-B-002"),
        ],
    )
    cur.executemany(
        "INSERT INTO transactions VALUES (?,?,?,?,?,?,?)",
        [
            (1, "tenant_a", 1, "Amazon", 49.99, "2024-01-15 10:30:00", "4532-xxxx"),
            (2, "tenant_a", 1, "Starbucks", 5.50, "2024-01-15 14:20:00", "4532-xxxx"),
            (3, "tenant_a", 2, "Target", 125.00, "2024-01-16 09:15:00", "4532-yyyy"),
            (4, "tenant_b", 3, "Walmart", 75.25, "2024-01-15 11:00:00", "5555-xxxx"),
            (5, "tenant_b", 3, "Shell Gas", 45.00, "2024-01-16 08:30:00", "5555-xxxx"),
            (6, "tenant_b", 4, "Apple Store", 999.00, "2024-01-16 15:45:00", "5555-yyyy"),
        ],
    )
    cur.executemany(
        "INSERT INTO accounts VALUES (?,?,?,?,?)",
        [
            (1, "tenant_a", 1, "ACC-A-001", 5000.00),
            (2, "tenant_a", 2, "ACC-A-002", 12000.00),
            (3, "tenant_b", 3, "ACC-B-001", 8000.00),
            (4, "tenant_b", 4, "ACC-B-002", 25000.00),
        ],
    )
    conn.commit()
    conn.close()
    return SQLiteConnector(database_path, signing_key, expected_audience)
