"""
Manual test script for Snowflake connector.

Setup:
1. Install: pip install 'datafence[snowflake]'
2. Set:
   export DATAFENCE_SNOWFLAKE_ACCOUNT=your_account
   export DATAFENCE_SNOWFLAKE_USER=your_user
   export DATAFENCE_SNOWFLAKE_PASSWORD=your_password
   export DATAFENCE_SNOWFLAKE_DATABASE=your_database
   export DATAFENCE_SNOWFLAKE_WAREHOUSE=your_warehouse
3. Run: python tests/manual/test_snowflake_manual.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from datafence.connectors.snowflake import SnowflakeConnector
from datafence.core.request import ExecutionRequest, Operation


def test_snowflake():
    print("=" * 60)
    print("Snowflake Connector Manual Test")
    print("=" * 60)
    
    config = {
        "account": os.getenv("DATAFENCE_SNOWFLAKE_ACCOUNT"),
        "user": os.getenv("DATAFENCE_SNOWFLAKE_USER"),
        "password": os.getenv("DATAFENCE_SNOWFLAKE_PASSWORD"),
        "database": os.getenv("DATAFENCE_SNOWFLAKE_DATABASE"),
        "warehouse": os.getenv("DATAFENCE_SNOWFLAKE_WAREHOUSE"),
        "schema": os.getenv("DATAFENCE_SNOWFLAKE_SCHEMA", "PUBLIC"),
    }
    
    if not all([config["account"], config["user"], config["password"], config["database"]]):
        print("✗ Missing required env vars")
        sys.exit(1)
    
    print(f"\nConnecting to Snowflake account: {config['account']}")
    
    try:
        with SnowflakeConnector(**config) as connector:
            print("✓ Connected")
            
            table_name = os.getenv("TEST_TABLE_NAME", "YOUR_TABLE")
            
            print(f"\n1. Describing table: {table_name}")
            metadata = connector.describe(table_name)
            print(f"✓ Table: {metadata['table']}")
            print(f"  Columns: {len(metadata['columns'])}")
            for col in metadata['columns'][:5]:
                print(f"  - {col['name']}: {col['type']}")
            
            print(f"\n2. Querying table (LIMIT 5)...")
            request = ExecutionRequest(
                operation=Operation.READ,
                resource=table_name,
                limit=5,
                tenant_id="test",
            )
            results = connector.execute(request)
            print(f"✓ Retrieved {len(results)} rows")
            if results:
                print(f"  Sample: {results[0]}")
            
            print("\n" + "=" * 60)
            print("Snowflake tests passed! ✓")
            print("=" * 60)
    
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    test_snowflake()
