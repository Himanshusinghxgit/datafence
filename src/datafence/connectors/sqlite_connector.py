"""
SQLite connector for DataFence (v0.4 - Hardened).

CRITICAL SECURITY PROPERTIES (v0.4):
    - Connector verifies cryptographic signature before execution
    - Connector accepts ONLY signed AuthorizedExecution capabilities
    - Connector does NOT accept raw SQL from the LLM
    - Connector rejects forged/tampered capabilities
    
Flow:
    AuthorizedExecution (signed) → verify_signature() → generate_sql() → prepared_statement → database

The database executes DataFence's authorized SQL, not the LLM's SQL.

SECURITY IMPROVEMENTS:
- HMAC signature verification prevents forgery
- Defense in depth: API design + cryptography
- Legacy execute_plan() kept for backward compatibility (deprecated)
"""

import sqlite3
from typing import Any

from datafence.core.types import ExecutionPlan, Operation
from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError


class SQLiteConnector:
    """
    SQLite connector that enforces cryptographic capabilities (v0.4 - Hardened).
    
    The connector:
    1. Verifies HMAC signature on AuthorizedExecution
    2. Rejects forged/tampered capabilities
    3. Generates SQL from the capability (not from LLM)
    4. Uses prepared statements with parameters
    5. Returns ONLY the fields in the capability
    
    SECURITY:
    - Signing key is received at construction (NEVER passed through public API)
    - Capability signature is verified BEFORE execution
    - Invalid signature = SecurityError (no data returned)
    
    IMPORTANT: This connector is INTERNAL to DataFenceBoundary.
    It should NOT be instantiated directly by application code.
    """

    def __init__(self, database_path: str, signing_key: bytes):
        """
        Initialize SQLite connector.
        
        Args:
            database_path: Path to SQLite database
            signing_key: Secret key for capability verification (32 bytes)
        
        SECURITY: The signing_key should come from DataFenceBoundary.
        The application should never handle or see this key.
        """
        self.database_path = database_path
        self._signing_key = signing_key  # PRIVATE - never expose
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row  # Return rows as dicts

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """
        Execute a signed capability (v0.4 - Hardened).
        
        This is the ONLY execution method. No execute_plan(), no execute_sql().
        
        SECURITY:
        - Verifies HMAC signature before execution
        - Rejects forged capabilities
        - Capability specifies EXACTLY what is authorized
        - SQL is generated from the capability (not from LLM)
        - Prepared statements prevent injection
        - Only authorized fields are returned
        
        Args:
            capability: Signed AuthorizedExecution
        
        Returns:
            Query results
        
        Raises:
            CapabilityVerificationError: If signature is invalid
        """
        # SECURITY CHECK: Verify cryptographic signature
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Invalid capability signature for execution {capability.execution_id}. "
                "The capability may be forged or tampered with."
            )
        
        # Generate SQL from verified capability
        sql, params = self._generate_sql_from_capability(capability)

        # Execute with prepared statement
        cursor = self.connection.cursor()
        cursor.execute(sql, params)

        # Fetch results
        rows = cursor.fetchall()

        # Convert to list of dicts, ensuring ONLY authorized fields
        results = []
        for row in rows:
            # Only include fields from the capability
            filtered_row = {
                field: row[field]
                for field in capability.selected_fields
                if field in row.keys()
            }
            results.append(filtered_row)

        return results

    def _generate_sql_from_capability(
        self,
        capability: AuthorizedExecution,
    ) -> tuple[str, dict[str, Any]]:
        """
        Generate SQL from AuthorizedExecution capability.
        
        The SQL is constructed from the capability, NOT from LLM input.
        """
        if capability.operation == Operation.READ:
            return self._generate_select_from_capability(capability)
        elif capability.operation == Operation.INSERT:
            raise NotImplementedError("INSERT not implemented in demo")
        elif capability.operation == Operation.UPDATE:
            raise NotImplementedError("UPDATE not implemented in demo")
        elif capability.operation == Operation.DELETE:
            raise NotImplementedError("DELETE not implemented in demo")
        else:
            raise ValueError(f"Unknown operation: {capability.operation}")

    def _generate_select_from_capability(
        self,
        capability: AuthorizedExecution,
    ) -> tuple[str, dict[str, Any]]:
        """
        Generate SELECT statement from capability.
        
        The LLM may have requested:
            SELECT * FROM transactions
        
        But DataFence generates:
            SELECT id, merchant, amount, timestamp
            FROM transactions
            WHERE tenant_id = :tenant_id
            LIMIT 100
        
        based on the verified capability.
        """
        # SELECT clause - ONLY authorized fields
        fields = ", ".join(capability.selected_fields)
        sql = f"SELECT {fields} FROM {capability.resource}"

        # WHERE clause - enforced filters
        params = {}
        if capability.enforced_filters:
            conditions = []
            for i, (key, value) in enumerate(capability.enforced_filters.items()):
                param_name = f"filter_{i}"
                conditions.append(f"{key} = :{param_name}")
                params[param_name] = value

            sql += " WHERE " + " AND ".join(conditions)

        # LIMIT clause - enforced limit
        sql += f" LIMIT {capability.limit}"

        return sql, params


    def close(self):
        """Close database connection."""
        if self.connection:
            self.connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class MaliciousConnector(SQLiteConnector):
    """
    A malicious connector for testing result validation.
    
    This connector attempts to return unauthorized fields.
    DataFence's result validation MUST catch this.
    
    NOTE: This is for TESTING ONLY. In v0.4, it bypasses signature
    verification to test result validation.
    """

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, Any]]:
        """
        Execute capability but attempt to return unauthorized fields.
        
        This tests whether DataFence's result validation works.
        
        IMPORTANT: For testing, we skip signature verification
        to isolate the result validation test.
        """
        # Generate SQL (skip signature verification for this test)
        sql, params = self._generate_sql_from_capability(capability)
        cursor = self.connection.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()

        # MALICIOUS: Add unauthorized fields
        results = []
        for row in rows:
            malicious_row = dict(row)
            # Add fields that weren't authorized
            malicious_row["card_number"] = "1234-5678-9012-3456"
            malicious_row["ssn"] = "123-45-6789"
            results.append(malicious_row)

        return results


def create_demo_database(database_path: str, signing_key: bytes) -> SQLiteConnector:
    """
    Create the demo database for the killer demo.
    
    Args:
        database_path: Path to SQLite database file
        signing_key: Signing key for capability verification (32 bytes)
    
    Returns:
        Configured SQLiteConnector
    
    Schema:
    - customers (id, tenant_id, name, email, ssn, account_number)
    - transactions (id, tenant_id, customer_id, merchant, amount, timestamp, card_number)
    - accounts (id, tenant_id, customer_id, account_number, balance)
    """
    conn = sqlite3.connect(database_path)
    cursor = conn.cursor()

    # Drop existing tables
    cursor.execute("DROP TABLE IF EXISTS customers")
    cursor.execute("DROP TABLE IF EXISTS transactions")
    cursor.execute("DROP TABLE IF EXISTS accounts")

    # Create customers table
    cursor.execute("""
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            ssn TEXT NOT NULL,
            account_number TEXT NOT NULL
        )
    """)

    # Create transactions table
    cursor.execute("""
        CREATE TABLE transactions (
            id INTEGER PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            customer_id INTEGER NOT NULL,
            merchant TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp TEXT NOT NULL,
            card_number TEXT NOT NULL
        )
    """)

    # Create accounts table
    cursor.execute("""
        CREATE TABLE accounts (
            id INTEGER PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            customer_id INTEGER NOT NULL,
            account_number TEXT NOT NULL,
            balance REAL NOT NULL
        )
    """)

    # Insert tenant_a data
    cursor.execute("""
        INSERT INTO customers (id, tenant_id, name, email, ssn, account_number)
        VALUES
            (1, 'tenant_a', 'Alice Johnson', 'alice@tenant-a.com', '123-45-6789', 'ACC-A-001'),
            (2, 'tenant_a', 'Bob Smith', 'bob@tenant-a.com', '234-56-7890', 'ACC-A-002')
    """)

    cursor.execute("""
        INSERT INTO transactions (id, tenant_id, customer_id, merchant, amount, timestamp, card_number)
        VALUES
            (1, 'tenant_a', 1, 'Amazon', 49.99, '2024-01-15 10:30:00', '4532-1111-2222-3333'),
            (2, 'tenant_a', 1, 'Starbucks', 5.50, '2024-01-15 14:20:00', '4532-1111-2222-3333'),
            (3, 'tenant_a', 2, 'Target', 125.00, '2024-01-16 09:15:00', '4532-4444-5555-6666')
    """)

    cursor.execute("""
        INSERT INTO accounts (id, tenant_id, customer_id, account_number, balance)
        VALUES
            (1, 'tenant_a', 1, 'ACC-A-001', 5000.00),
            (2, 'tenant_a', 2, 'ACC-A-002', 12000.00)
    """)

    # Insert tenant_b data
    cursor.execute("""
        INSERT INTO customers (id, tenant_id, name, email, ssn, account_number)
        VALUES
            (3, 'tenant_b', 'Charlie Brown', 'charlie@tenant-b.com', '345-67-8901', 'ACC-B-001'),
            (4, 'tenant_b', 'Diana Prince', 'diana@tenant-b.com', '456-78-9012', 'ACC-B-002')
    """)

    cursor.execute("""
        INSERT INTO transactions (id, tenant_id, customer_id, merchant, amount, timestamp, card_number)
        VALUES
            (4, 'tenant_b', 3, 'Walmart', 75.25, '2024-01-15 11:00:00', '5555-7777-8888-9999'),
            (5, 'tenant_b', 3, 'Shell Gas', 45.00, '2024-01-16 08:30:00', '5555-7777-8888-9999'),
            (6, 'tenant_b', 4, 'Apple Store', 999.00, '2024-01-16 15:45:00', '5555-1111-2222-3333')
    """)

    cursor.execute("""
        INSERT INTO accounts (id, tenant_id, customer_id, account_number, balance)
        VALUES
            (3, 'tenant_b', 3, 'ACC-B-001', 8000.00),
            (4, 'tenant_b', 4, 'ACC-B-002', 25000.00)
    """)

    conn.commit()
    conn.close()

    return SQLiteConnector(database_path, signing_key)
