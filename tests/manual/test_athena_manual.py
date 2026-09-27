"""
Manual test script for Amazon Athena connector.

Setup:
1. Install: pip install 'datafence[athena]'
2. Set AWS credentials (one of):
   - AWS_PROFILE=your-profile
   - AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
3. Set:
   export DATAFENCE_ATHENA_DATABASE=your_database
   export DATAFENCE_ATHENA_S3_OUTPUT=s3://your-bucket/results/
   export DATAFENCE_ATHENA_REGION=us-east-1
4. Run: python tests/manual/test_athena_manual.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from datafence.connectors.athena import AthenaConnector
from datafence.core.request import ExecutionRequest, Operation


def test_athena():
    print("=" * 60)
    print("Athena Connector Manual Test")
    print("=" * 60)
    
    config = {
        "database": os.getenv("DATAFENCE_ATHENA_DATABASE"),
        "s3_output_location": os.getenv("DATAFENCE_ATHENA_S3_OUTPUT"),
        "region_name": os.getenv("DATAFENCE_ATHENA_REGION", "us-east-1"),
    }
    
    if not config["database"] or not config["s3_output_location"]:
        print("✗ Missing required env vars: DATAFENCE_ATHENA_DATABASE, DATAFENCE_ATHENA_S3_OUTPUT")
        sys.exit(1)
    
    print(f"\nConnecting to Athena database: {config['database']}")
    
    try:
        with AthenaConnector(**config) as connector:
            print("✓ Connected")
            
            # List tables (replace 'your_table' with actual table)
            table_name = os.getenv("TEST_TABLE_NAME", "your_table")
            
            print(f"\n1. Describing table: {table_name}")
            metadata = connector.describe(table_name)
            print(f"✓ Columns: {len(metadata['columns'])}")
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
            print("Athena tests passed! ✓")
            print("=" * 60)
    
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    test_athena()
