"""
REST API example.

Demonstrates running DataFence as a REST API service.
"""

import requests
import json

# Sample request for the API
sample_request = {
    "actor": {"id": "agent:banking-assistant", "tenant_id": "acme"},
    "operation": "read",
    "resource": "transactions",
    "fields": ["id", "amount", "merchant", "timestamp"],
    "filters": {"customer_id": "cust_123"},
    "limit": 10,
}


def example_client():
    """Example API client."""
    print("=" * 60)
    print("DataFence REST API Client Example")
    print("=" * 60)

    base_url = "http://localhost:8000"
    api_key = "your-api-key-here"  # Replace with actual key if auth enabled

    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    # 1. Health check
    print("\n1. Health check...")
    try:
        response = requests.get(f"{base_url}/health")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.json()}")
    except Exception as e:
        print(f"   ⚠️  Error: {e}")
        print("   Make sure API server is running: python -m datafence.api policy.yaml")
        return

    # 2. Get policy info
    print("\n2. Get policy information...")
    try:
        response = requests.get(f"{base_url}/policy", headers=headers)
        if response.status_code == 200:
            print(f"   Policy: {response.json()}")
        else:
            print(f"   Error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"   Error: {e}")

    # 3. Execute query
    print("\n3. Execute query...")
    try:
        response = requests.post(
            f"{base_url}/execute", headers=headers, json=sample_request
        )

        if response.status_code == 200:
            result = response.json()
            print(f"   Success: {result['success']}")
            print(f"   Verified: {result['verified']}")
            if result["data"]:
                print(f"   Rows: {result['row_count']}")
                print(f"   Sample: {result['data'][0]}")
        else:
            print(f"   Error: {response.status_code}")
            print(f"   Details: {response.json()}")
    except Exception as e:
        print(f"   Error: {e}")

    # 4. Describe resource
    print("\n4. Describe resource...")
    try:
        response = requests.post(
            f"{base_url}/describe",
            headers=headers,
            json={"resource": "transactions"},
        )

        if response.status_code == 200:
            metadata = response.json()["metadata"]
            print(f"   Resource: {metadata.get('resource')}")
            print(f"   Fields: {metadata.get('fields')}")
        else:
            print(f"   Error: {response.status_code}")
    except Exception as e:
        print(f"   Error: {e}")


def example_server():
    """Example of starting the API server."""
    print("\n" + "=" * 60)
    print("DataFence REST API Server Example")
    print("=" * 60)

    print("""
To start the DataFence API server:

1. Basic (no authentication):
   python -m datafence.api policy.yaml

2. With custom port:
   python -m datafence.api policy.yaml --port 8080

3. With API key authentication:
   python -m datafence.api policy.yaml --api-key secret-key-123

4. Using the Python API:
   from datafence import DataFence
   from datafence.api import run_api
   
   fence = DataFence.from_yaml("policy.yaml", connector)
   run_api(fence, port=8000, api_keys={"secret-key-123"})

5. With FastAPI directly:
   from datafence.api import create_api
   import uvicorn
   
   fence = DataFence.from_yaml("policy.yaml", connector)
   app = create_api(fence, api_keys={"secret-key-123"})
   uvicorn.run(app, host="0.0.0.0", port=8000)

API Endpoints:
- GET  /health                     - Health check
- GET  /policy                     - Get policy info
- GET  /policy/resources/{name}    - Get resource policy
- POST /execute                    - Execute query
- POST /describe                   - Describe resource

OpenAPI docs available at:
- http://localhost:8000/docs       - Interactive Swagger UI
- http://localhost:8000/redoc      - ReDoc documentation
""")


if __name__ == "__main__":
    example_server()

    print("\n" + "=" * 60)
    print("\nTo test the client, first start the server then uncomment:")
    print("# example_client()")

    print("\n" + "=" * 60)
    print("✓ Examples complete")
