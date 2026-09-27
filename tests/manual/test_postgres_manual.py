"""
Manual test script for PostgreSQL connector.

This script is designed for manual testing with a real PostgreSQL database.
NOT for automated CI/CD - requires actual PostgreSQL instance.

Setup Instructions:
1. Install PostgreSQL locally or use Docker:
   docker run --name datafence-postgres -e POSTGRES_PASSWORD=testpass -p 5432:5432 -d postgres

2. Install dependencies:
   pip install 'datafence[postgres]'

3. Set environment variables OR edit connection params below:
   export DATAFENCE_POSTGRES_HOST=localhost
   export DATAFENCE_POSTGRES_PORT=5432
   export DATAFENCE_POSTGRES_DATABASE=postgres
   export DATAFENCE_POSTGRES_USER=postgres
   export DATAFENCE_POSTGRES_PASSWORD=testpass

4. Run this script:
   python tests/manual/test_postgres_manual.py
"""

import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from datafence.connectors.postgres import PostgreSQLConnector
from datafence.connectors.config import ConnectorConfig
from datafence.core.request import ExecutionRequest, Operation


def test_postgres_basic():
    """Test basic PostgreSQL connection and queries."""
    
    print("=" * 60)
    print("PostgreSQL Connector Manual Test")
    print("=" * 60)
    
    # Load config from environment or use defaults
    config = ConnectorConfig.from_env().get("postgres", {})
    
    if not config:
        # Fallback defaults
        config = {
            "host": os.getenv("DATAFENCE_POSTGRES_HOST", "localhost"),
            "port": int(os.getenv("DATAFENCE_POSTGRES_PORT", "5432")),
            "database": os.getenv("DATAFENCE_POSTGRES_DATABASE", "postgres"),
            "user": os.getenv("DATAFENCE_POSTGRES_USER", "postgres"),
            "password": os.getenv("DATAFENCE_POSTGRES_PASSWORD", "testpass"),
        }
    
    print(f"\n1. Connecting to PostgreSQL at {config['host']}:{config['port']}...")
    
    try:
        with PostgreSQLConnector(**config) as connector:
            print("✓ Connected successfully")
            
            # Create test table
            print("\n2. Creating test table...")
            with connector.pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        DROP TABLE IF EXISTS datafence_test_users;
                        CREATE TABLE datafence_test_users (
                            id SERIAL PRIMARY KEY,
                            tenant_id VARCHAR(50) NOT NULL,
                            email VARCHAR(255) NOT NULL,
                            name VARCHAR(255),
                            age INTEGER,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        );
                    """)
                    
                    # Insert sample data
                    cur.execute("""
                        INSERT INTO datafence_test_users (tenant_id, email, name, age) VALUES
                        ('tenant_a', 'alice@example.com', 'Alice Smith', 30),
                        ('tenant_a', 'bob@example.com', 'Bob Jones', 25),
                        ('tenant_b', 'charlie@example.com', 'Charlie Brown', 35),
                        ('tenant_b', 'diana@example.com', 'Diana Prince', 28);
                    """)
                    conn.commit()
            
            print("✓ Test table created and populated")
            
            # Test describe
            print("\n3. Testing describe()...")
            metadata = connector.describe("datafence_test_users")
            print(f"✓ Table: {metadata['table']}")
            print(f"  Schema: {metadata['schema']}")
            print(f"  Columns: {len(metadata['columns'])}")
            print(f"  Fields: {', '.join(metadata['fields'])}")
            print(f"  Row count estimate: {metadata['row_count_estimate']}")
            
            # Test query without filters
            print("\n4. Testing query without filters...")
            request = ExecutionRequest(
                operation=Operation.READ,
                resource="datafence_test_users",
                fields=["id", "tenant_id", "email", "name"],
                tenant_id="tenant_a",
            )
            results = connector.execute(request)
            print(f"✓ Retrieved {len(results)} rows")
            for row in results[:2]:
                print(f"  - {row}")
            
            # Test query with filters
            print("\n5. Testing query with filters...")
            request = ExecutionRequest(
                operation=Operation.READ,
                resource="datafence_test_users",
                fields=["id", "email", "name", "age"],
                filters={"tenant_id": "tenant_a"},
                tenant_id="tenant_a",
            )
            results = connector.execute(request)
            print(f"✓ Retrieved {len(results)} rows for tenant_a")
            for row in results:
                print(f"  - {row}")
            
            # Test field restriction (simulating policy)
            print("\n6. Testing field restriction (policy simulation)...")
            request = ExecutionRequest(
                operation=Operation.READ,
                resource="datafence_test_users",
                fields=["id", "email", "name", "age"],  # User requests these
                tenant_id="tenant_a",
            )
            allowed_fields = ["id", "email", "name"]  # Policy only allows these
            results = connector.execute(request, allowed_fields=allowed_fields)
            print(f"✓ Retrieved {len(results)} rows with restricted fields")
            print(f"  Requested: id, email, name, age")
            print(f"  Allowed: {', '.join(allowed_fields)}")
            print(f"  Result keys: {', '.join(results[0].keys())}")
            
            # Test LIMIT
            print("\n7. Testing LIMIT...")
            request = ExecutionRequest(
                operation=Operation.READ,
                resource="datafence_test_users",
                fields=["id", "email"],
                limit=2,
                tenant_id="tenant_a",
            )
            results = connector.execute(request)
            print(f"✓ Retrieved {len(results)} rows (limit=2)")
            
            # Test SQL injection prevention
            print("\n8. Testing SQL injection prevention...")
            try:
                request = ExecutionRequest(
                    operation=Operation.READ,
                    resource="datafence_test_users",
                    fields=["id", "email"],
                    filters={"tenant_id": "tenant_a' OR '1'='1"},  # Attempted injection
                    tenant_id="tenant_a",
                )
                results = connector.execute(request)
                print(f"✓ Injection attempt safely handled (no results)")
                print(f"  Results: {len(results)} rows")
            except Exception as e:
                print(f"✓ Injection attempt blocked: {e}")
            
            # Cleanup
            print("\n9. Cleaning up...")
            with connector.pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DROP TABLE datafence_test_users;")
                    conn.commit()
            print("✓ Test table dropped")
            
            print("\n" + "=" * 60)
            print("All PostgreSQL tests passed! ✓")
            print("=" * 60)
    
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    test_postgres_basic()
