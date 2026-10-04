"""
DataFence REST API integration example.

Demonstrates:
  A. How to start the DataFence authorization API server.
  B. How an HTTP client calls /authorize to obtain a signed capability.
  C. How the client then passes that capability to its own connector.

Architecture::

    HTTP client (AI agent / application)
        │  POST /authorize  {"resource": ..., "fields": [...]}
        │  Authorization: Bearer <session-token>   ← trusted identity source
        ▼
    DataFence API server
        │  resolves Principal from Bearer token (server-side)
        │  DataFenceBoundary.authorize(principal, intent)
        ▼
    Response: signed AuthorizedExecution (JSON)
        │
        ▼  client passes capability to its own data service
    Customer-owned connector → enterprise data

DataFence returns an authorization capability.
DataFence does NOT return database rows.

Requirements:
    pip install 'datafence[api]' requests
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Part 1 — Starting the server
# ---------------------------------------------------------------------------

SERVER_SETUP = """
Starting the DataFence authorization API
-----------------------------------------

1. Minimal (no auth, development only):

       datafence api

   or:

       python -m datafence.cli api

2. With a policy YAML file:

       datafence api --policy policies/basic.yaml

3. In Python, wiring your own boundary and principal resolver:

       from secrets import token_bytes
       from datafence import DataFenceBoundary, DataFencePolicyEngine, ResourceRegistry
       from datafence.api import build_app
       import uvicorn

       # Build your boundary
       registry = ResourceRegistry()
       # ... register resources ...
       engine = DataFencePolicyEngine(policy, registry=registry)
       signing_key = token_bytes(32)   # store this securely
       boundary = DataFenceBoundary.create(engine, registry, signing_key)

       # Wire a principal resolver — maps Bearer tokens to Principal objects
       from datafence.core.principal import Principal

       def my_resolver(token: str) -> Principal:
           user = your_auth_service.verify_token(token)
           return Principal(id=f"user:{user.id}", tenant_id=user.tenant_id)

       app = build_app(boundary=boundary, principal_resolver=my_resolver)
       uvicorn.run(app, host="0.0.0.0", port=8000)

API endpoints (v1):
    GET  /health                   — liveness check
    GET  /describe/{resource}      — resource schema
    POST /authorize                — obtain a signed capability
    POST /verify                   — verify a capability (optional)

OpenAPI docs: http://localhost:8000/docs
"""


# ---------------------------------------------------------------------------
# Part 2 — HTTP client example
# ---------------------------------------------------------------------------

def example_http_client() -> None:
    """
    Demonstrate calling the DataFence /authorize endpoint.

    Expects the server to be running on localhost:8000.
    Start it with:  datafence api
    """
    print("=" * 60)
    print("DataFence API — HTTP client example")
    print("=" * 60)
    print("(Start the server first: datafence api)")

    try:
        import requests
    except ImportError:
        print("⚠️  requests not installed: pip install requests")
        return

    base_url = "http://localhost:8000"
    # Bearer token is validated server-side; DataFence never trusts body identity.
    headers = {"Authorization": "Bearer your-session-token"}

    # 1. Health check
    print("\n1. Health check...")
    try:
        r = requests.get(f"{base_url}/health", timeout=3)
        print(f"   Status: {r.status_code}  {r.json()}")
    except requests.exceptions.ConnectionError:
        print("   ⚠️  Server not running — start with: datafence api")
        print("   Skipping remaining client steps.")
        return
    except Exception as exc:
        print(f"   ⚠️  {exc}")
        return

    # 2. POST /authorize — get a signed capability, NOT data rows
    print("\n2. POST /authorize ...")
    intent_body = {
        "resource": "orders",
        "fields": ["id", "total", "status"],
        "filters": {"status": "shipped"},
        "limit": 10,
    }
    try:
        r = requests.post(f"{base_url}/authorize", headers=headers, json=intent_body)
        if r.status_code == 200:
            cap = r.json()
            print(f"   status         : {cap.get('status')}")
            print(f"   execution_id   : {cap.get('execution_id')}")
            print(f"   resource       : {cap.get('resource')}")
            print(f"   authorized fields: {cap.get('fields')}")
            print(f"   predicates     : {cap.get('predicates')}")
            print(f"   limit          : {cap.get('limit')}")
            print(f"   expires_at     : {cap.get('expires_at')}")
            print()
            print("   → Pass this capability to your connector.")
            print("     The API does NOT return data rows.")
        elif r.status_code == 403:
            body = r.json()
            print(f"   DENIED — reasons: {body.get('reasons')}")
        else:
            print(f"   HTTP {r.status_code}: {r.text}")
    except Exception as exc:
        print(f"   ⚠️  {exc}")

    # 3. Describe a resource
    print("\n3. GET /describe/orders ...")
    try:
        r = requests.get(f"{base_url}/describe/orders", headers=headers)
        if r.status_code == 200:
            print(f"   {r.json()}")
        else:
            print(f"   HTTP {r.status_code}")
    except Exception as exc:
        print(f"   ⚠️  {exc}")


# ---------------------------------------------------------------------------
# Part 3 — Security notes
# ---------------------------------------------------------------------------

SECURITY_NOTES = """
Security contract for API integrators
---------------------------------------

DO:
  • Send the user's session token in Authorization: Bearer <token>.
    The API resolves Principal from this token server-side.
  • Treat the returned capability JSON as an opaque authorization artifact.
  • Pass the capability to your own connector for data retrieval.
  • Verify the capability signature in your connector before executing.

DO NOT:
  • Include actor/principal fields in the request body — they are ignored.
    Identity comes from the transport token, never from the body.
  • Store the signed capability longer than its expires_at timestamp.
  • Return the raw capability to the AI agent — it is for your connector only.
  • Expect the API to return database rows — it only returns authorization.
"""


if __name__ == "__main__":
    print(SERVER_SETUP)
    example_http_client()
    print(SECURITY_NOTES)
    print("=" * 60)
    print("✓ Example complete")
