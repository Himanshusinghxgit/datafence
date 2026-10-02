"""
DataFence connector contract and in-memory reference implementation.

What this package provides
--------------------------
``DataConnector``               : Minimal protocol any customer connector should satisfy.
``ConnectorResult``             : Standard result type returned by a connector.
``InMemoryReferenceConnector``  : In-memory connector for tests and quickstart examples.

What DataFence does NOT provide
---------------------------------
DataFence does not own production database connectors.

For production use, implement the ``DataConnector`` protocol in your own
codebase using your existing data-access layer.  Reference implementations
for SQLite, PostgreSQL, Snowflake, and Athena live in:

    examples/reference_connector/

Do NOT use those in production — they exist only for demonstrations.
"""

from datafence.connectors.memory_connector import InMemoryReferenceConnector
from datafence.connectors.protocol import ConnectorResult, DataConnector

__all__ = ["DataConnector", "ConnectorResult", "InMemoryReferenceConnector"]
