"""
Example customer-owned connector for the basic DataFence example.

This demonstrates the contract:
    DataFence authorizes → AuthorizedExecution
    Customer connector verifies + executes → ConnectorResult

In a real application, this would be your existing data-access layer
(PostgreSQL, Snowflake, an internal API, etc.).  DataFence does not
know or care what lives behind this connector.

This example uses InMemoryReferenceConnector for simplicity.
"""


from examples.reference_connector.memory import InMemoryReferenceConnector


def create_example_connector(
    signing_key: bytes,
    audience: str = "datafence",
) -> InMemoryReferenceConnector:
    """Create an in-memory connector pre-populated with example data."""
    data = {
        "orders": [
            {"id": 1, "tenant_id": "acme", "customer_id": 10, "total": 150.00, "status": "shipped", "created_at": "2026-01-10"},
            {"id": 2, "tenant_id": "acme", "customer_id": 11, "total": 75.50, "status": "pending", "created_at": "2026-01-11"},
            {"id": 3, "tenant_id": "globex", "customer_id": 20, "total": 999.00, "status": "shipped", "created_at": "2026-01-12"},
        ],
        "documents": [
            {"id": 1, "tenant_id": "acme", "title": "Q1 Report", "status": "published", "created_at": "2026-02-01", "internal_notes": "REDACTED"},
            {"id": 2, "tenant_id": "acme", "title": "Contract Draft", "status": "draft", "created_at": "2026-02-05", "internal_notes": "CONFIDENTIAL"},
            {"id": 3, "tenant_id": "globex", "title": "Globex Filing", "status": "published", "created_at": "2026-02-07", "internal_notes": "CONFIDENTIAL"},
        ],
        "customers": [
            {"id": 10, "tenant_id": "acme", "name": "Alice", "email": "alice@acme.example", "ssn": "HIDDEN"},
            {"id": 11, "tenant_id": "acme", "name": "Bob", "email": "bob@acme.example", "ssn": "HIDDEN"},
            {"id": 20, "tenant_id": "globex", "name": "Charlie", "email": "charlie@globex.example", "ssn": "HIDDEN"},
        ],
    }
    return InMemoryReferenceConnector(data, signing_key=signing_key, expected_audience=audience)
