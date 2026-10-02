"""
DataFence connector interface and reference implementations.

IMPORTANT: DataFence does NOT own database connectors.
---------------------------------------------------------
DataFenceBoundary.authorize() returns an AuthorizedExecution capability.
The *customer's* existing backend connector receives that capability,
verifies its signature, and translates it into the appropriate database call.

DataFence never constructs a connector, never holds database credentials,
and never executes SQL.

What this package provides
---------------------------
- ``DataConnector``          : Minimal Protocol that any connector should satisfy.
- ``InMemoryReferenceConnector``: A simple in-memory connector for tests/examples only.

Production connectors (PostgreSQL, Snowflake, Athena, …) are in
``datafence/connectors/<name>_connector.py`` and are reference implementations
demonstrating the contract — not DataFence core components.  Production
applications should implement the connector in their own codebase using
their existing data-access layer.
"""

from datafence.connectors.protocol import ConnectorResult, DataConnector

__all__ = ["DataConnector", "ConnectorResult"]
