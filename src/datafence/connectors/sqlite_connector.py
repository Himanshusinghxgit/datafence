"""
SQLite connector for DataFence.

CRITICAL SECURITY PROPERTY:
    This connector accepts ONLY ExecutionPlan.
    It does NOT accept raw SQL from the LLM.
    
Flow:
    ExecutionPlan → generate_sql() → prepared_statement → database

The database executes DataFence's authorized SQL, not the LLM's SQL.
"""

import sqlite3
from typing import Any

from datafence.core.types import ExecutionPlan, Operation


class SQLiteConnector:
    """
    SQLite connector that enforces ExecutionPlan.
    
    The connector:
    1. Accepts ONLY ExecutionPlan (not raw SQL)
    2. Generates SQL from the plan
    3. Uses prepared statements with parameters
    4. Returns ONLY the fields in the plan
    """

    def __init__(self, database_path: str):
        self.database_path = database_path
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row  # Return rows as dicts

    def execute_plan(self, plan: ExecutionPlan) -> list[dict[str, Any]]:
        """
        Execute an ExecutionPlan.
        
        SECURITY:
        - Plan specifies EXACTLY what is authorized
        - SQL is generated from the plan (not from LLM)
        - Prepared statements prevent injection
        - Only authorized fields are returned
        """
        # Generate SQL from ExecutionPlan
        sql, params = self._generate_sql(plan)

        # Execute with prepared statement
        cursor = self.connection.cursor()
        cursor.execute(sql, params)

        # Fetch results
        rows = cursor.fetchall()

        # Convert to list of dicts, ensuring ONLY authorized fields
        results = []
        for row in rows:
            # Only include fields from the plan
            filtered_row = {
                field: row[field]
                for field in plan.selected_fields
                if field in row.keys()
            }
            results.append(filtered_row)

        return results

    def _generate_sql(self, plan: ExecutionPlan) -> tuple[str, dict[str, Any]]:
        """
        Generate SQL from ExecutionPlan.
        
        The SQL is constructed from the plan, NOT from LLM input.
        
        Returns:
            (sql_string, parameters)
        """
        if plan.operation == Operation.READ:
            return self._generate_select(plan)
        elif plan.operation == Operation.INSERT:
            raise NotImplementedError("INSERT not implemented in demo")
        elif plan.operation == Operation.UPDATE:
            raise NotImplementedError("UPDATE not implemented in demo")
        elif plan.operation == Operation.DELETE:
            raise NotImplementedError("DELETE not implemented in demo")
        else:
            raise ValueError(f"Unknown operation: {plan.operation}")

    def _generate_select(self, plan: ExecutionPlan) -> tuple[str, dict[str, Any]]:
        """
        Generate SELECT statement from ExecutionPlan.
        
        The LLM may have requested:
            SELECT * FROM transactions
        
        But DataFence generates:
            SELECT id, merchant, amount, timestamp
            FROM transactions
            WHERE tenant_id = :tenant_id
            LIMIT 100
        
        based on the ExecutionPlan.
        """
        # SELECT clause - ONLY authorized fields
        fields = ", ".join(plan.selected_fields)
        sql = f"SELECT {fields} FROM {plan.resource}"

        # WHERE clause - enforced filters
        params = {}
        if plan.enforced_filters:
            conditions = []
            for i, (key, value) in enumerate(plan.enforced_filters.items()):
                param_name = f"filter_{i}"
                conditions.append(f"{key} = :{param_name}")
                params[param_name] = value

            sql += " WHERE " + " AND ".join(conditions)

        # LIMIT clause - enforced limit
        sql += f" LIMIT {plan.limit}"

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
    """

    def execute_plan(self, plan: ExecutionPlan) -> list[dict[str, Any]]:
        """
        Execute plan but attempt to return unauthorized fields.
        
        This tests whether DataFence's result validation works.
        """
        # Execute normally
        sql, params = self._generate_sql(plan)
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


def create_demo_database(database_path: str) -> SQLiteConnector:
    """
    Create the demo database for the killer demo.
    
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

    return SQLiteConnector(database_path)
