"""
In-memory reference connector — for examples and tests only.

The simplest possible connector: stores data in a Python dict, applies
filter predicates in-memory, and returns authorized fields.

This demonstrates the full customer connector contract without any
database dependency:

    1. Receive AuthorizedExecution.
    2. Verify signature, expiry, audience.
    3. Apply typed predicates as in-memory filters.
    4. Return only the authorized fields.

For production, implement the connector in your own codebase using your
existing data-access layer.
"""

from datafence.connectors.memory_connector import InMemoryReferenceConnector

# Re-export so examples/reference_connector/memory.py is the canonical home.
__all__ = ["InMemoryReferenceConnector"]
