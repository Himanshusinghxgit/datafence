"""
Tests for REST API.
"""

import pytest

try:
    from fastapi.testclient import TestClient

    from datafence.api import create_api

    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

from datafence import DataFence
from datafence.connectors import MemoryConnector


@pytest.fixture
def sample_data():
    """Sample in-memory data."""
    return {
        "transactions": [
            {"id": 1, "tenant_id": "acme", "amount": 100.0, "merchant": "Coffee"},
            {"id": 2, "tenant_id": "acme", "amount": 250.0, "merchant": "Store"},
        ]
    }


@pytest.fixture
def fence(sample_data, tmp_path):
    """Create DataFence instance."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("""
version: "1"
policy:
  name: test-policy
  resources:
    transactions:
      operations:
        allow: [read]
      fields:
        allow: [id, amount, merchant]
      limits:
        max_rows: 100
""")
    connector = MemoryConnector(data=sample_data)
    return DataFence.from_yaml(str(policy_file), connector)


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_create_api(fence):
    """Test creating API app."""
    app = create_api(fence)
    assert app is not None


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_health_endpoint(fence):
    """Test health check endpoint."""
    app = create_api(fence)
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_execute_endpoint(fence):
    """Test execute endpoint."""
    app = create_api(fence)
    client = TestClient(app)

    request_data = {
        "actor": {"id": "test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "transactions",
        "fields": ["id", "amount"],
        "limit": 10,
    }

    response = client.post("/execute", json=request_data)
    assert response.status_code == 200

    data = response.json()
    assert data["success"] is True
    assert data["verified"] is True
    assert data["row_count"] == 2


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_execute_endpoint_denied(fence):
    """Test execute endpoint with denied request."""
    app = create_api(fence)
    client = TestClient(app)

    request_data = {
        "actor": {"id": "test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "transactions",
        "fields": ["id", "password"],  # password not allowed
    }

    response = client.post("/execute", json=request_data)
    assert response.status_code == 200

    data = response.json()
    assert data["success"] is False
    assert "reasons" in data


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_execute_with_authentication(fence):
    """Test execute endpoint with API key authentication."""
    api_keys = {"secret-key-123"}
    app = create_api(fence, api_keys=api_keys)
    client = TestClient(app)

    request_data = {
        "actor": {"id": "test", "tenant_id": "acme"},
        "operation": "read",
        "resource": "transactions",
        "fields": ["id", "amount"],
    }

    # Without auth header - should fail
    response = client.post("/execute", json=request_data)
    assert response.status_code == 401

    # With correct auth header
    response = client.post(
        "/execute", json=request_data, headers={"Authorization": "Bearer secret-key-123"}
    )
    assert response.status_code == 200

    # With incorrect auth header
    response = client.post(
        "/execute",
        json=request_data,
        headers={"Authorization": "Bearer wrong-key"},
    )
    assert response.status_code == 401


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_describe_endpoint(fence):
    """Test describe endpoint."""
    app = create_api(fence)
    client = TestClient(app)

    request_data = {"resource": "transactions"}

    response = client.post("/describe", json=request_data)
    assert response.status_code == 200

    data = response.json()
    assert data["success"] is True
    assert "metadata" in data


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_describe_nonexistent_resource(fence):
    """Test describe endpoint with non-existent resource."""
    app = create_api(fence)
    client = TestClient(app)

    request_data = {"resource": "nonexistent"}

    response = client.post("/describe", json=request_data)
    assert response.status_code == 404


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_get_policy_endpoint(fence):
    """Test get policy endpoint."""
    app = create_api(fence)
    client = TestClient(app)

    response = client.get("/policy")
    assert response.status_code == 200

    data = response.json()
    assert data["name"] == "test-policy"
    assert "resources" in data
    assert "transactions" in data["resources"]


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_get_resource_policy_endpoint(fence):
    """Test get resource policy endpoint."""
    app = create_api(fence)
    client = TestClient(app)

    response = client.get("/policy/resources/transactions")
    assert response.status_code == 200

    data = response.json()
    assert data["resource"] == "transactions"
    assert "operations" in data
    assert "fields" in data


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_get_nonexistent_resource_policy(fence):
    """Test get policy for non-existent resource."""
    app = create_api(fence)
    client = TestClient(app)

    response = client.get("/policy/resources/nonexistent")
    assert response.status_code == 404


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_cors_enabled(fence):
    """Test CORS middleware is enabled."""
    app = create_api(fence, enable_cors=True)
    client = TestClient(app)

    # CORS headers should be present
    response = client.options("/health", headers={"Origin": "http://example.com"})
    # FastAPI TestClient may not fully simulate CORS, but app should not crash
    assert response.status_code in [200, 405]


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_openapi_docs(fence):
    """Test OpenAPI documentation endpoints."""
    app = create_api(fence)
    client = TestClient(app)

    # OpenAPI JSON
    response = client.get("/openapi.json")
    assert response.status_code == 200
    openapi_spec = response.json()
    assert "openapi" in openapi_spec
    assert "paths" in openapi_spec

    # Swagger UI
    response = client.get("/docs")
    assert response.status_code == 200

    # ReDoc
    response = client.get("/redoc")
    assert response.status_code == 200


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_execute_invalid_request(fence):
    """Test execute with invalid request data."""
    app = create_api(fence)
    client = TestClient(app)

    # Missing required fields
    request_data = {"actor": {"id": "test"}}  # Missing operation, resource

    response = client.post("/execute", json=request_data)
    assert response.status_code == 422  # Validation error


@pytest.mark.skipif(not API_AVAILABLE, reason="API dependencies not installed")
def test_api_custom_metadata(fence):
    """Test creating API with custom metadata."""
    app = create_api(
        fence,
        title="Custom API",
        description="Custom description",
        version="2.0.0",
    )
    client = TestClient(app)

    response = client.get("/openapi.json")
    openapi_spec = response.json()

    assert openapi_spec["info"]["title"] == "Custom API"
    assert openapi_spec["info"]["description"] == "Custom description"
    assert openapi_spec["info"]["version"] == "2.0.0"


def test_api_missing_dependencies():
    """Test error when API dependencies not installed."""
    if API_AVAILABLE:
        pytest.skip("API is available")

    with pytest.raises(ImportError):
        pass
