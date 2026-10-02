"""
DataConnector — minimal protocol for customer-owned connectors.

The customer backend implements this interface (or an equivalent) to receive
AuthorizedExecution capabilities from DataFenceBoundary and translate them
into operations against the customer's data source.

The connector is responsible for:
    1. Receiving AuthorizedExecution from the application.
    2. Verifying the DataFence capability (signature, expiry, audience).
    3. Translating the authorized typed IR into the appropriate backend call.
    4. Executing it using the customer's existing data-access layer.
    5. Returning results to the application.

DataFence is NOT responsible for any of those steps.

Example implementation sketch::

    class MyPostgresConnector:
        def __init__(self, signing_key: bytes, conn_string: str) -> None:
            self._verifier = CapabilityVerifier(signing_key, expected_audience="my-service")
            self._db = psycopg.connect(conn_string)

        def execute(self, capability: AuthorizedExecution) -> ConnectorResult:
            self._verifier.verify(capability)   # raises on failure
            sql, params = self._compile(capability)
            rows = self._db.execute(sql, params).fetchall()
            return ConnectorResult(rows=rows, row_count=len(rows), execution_id=capability.execution_id)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from datafence.core.capability import AuthorizedExecution


@dataclass
class ConnectorResult:
    """
    Result returned by a customer connector after executing an AuthorizedExecution.

    Fields
    ------
    rows         : List of row dicts (field → value).
    row_count    : Number of rows returned.
    execution_id : Echoed from the capability for correlation/audit.
    metadata     : Optional additional metadata from the connector.
    """

    rows: list[dict[str, Any]]
    row_count: int
    execution_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class DataConnector(Protocol):
    """
    Minimal protocol that customer-owned connectors should satisfy.

    Any class with an ``execute(capability)`` method satisfies this protocol.
    DataFence itself never instantiates a DataConnector.

    The connector must:
    - Verify the capability's HMAC signature before executing.
    - Verify the capability has not expired.
    - Verify the capability audience matches the connector's identity.
    - Translate the capability's typed IR (not raw SQL from the agent).
    """

    def execute(self, capability: AuthorizedExecution) -> ConnectorResult:
        """Execute a verified AuthorizedExecution and return results."""
        ...
