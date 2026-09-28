"""
DataFence data connectors.

v0.5 connector architecture
----------------------------
All v0.5 connectors accept ONLY signed AuthorizedExecution capabilities.
They verify the HMAC signature before execution and validate all SQL
identifiers.  They never accept raw SQL or the legacy ExecutionRequest.

v0.5 (production-path) connectors
----------------------------------
  SQLiteConnector           — reference implementation, fully integrated
  PostgreSQLConnector       — requires: pip install datafence[postgres]
  AthenaConnector           — requires: pip install datafence[athena]
  SnowflakeConnector        — requires: pip install datafence[snowflake]

Legacy connectors (v0.1–v0.4, DEPRECATED)
------------------------------------------
  connectors.sqlite         — old interface, lacks capability signatures
  connectors.postgres       — old interface, lacks capability signatures
  connectors.athena         — old interface, lacks capability signatures
  connectors.snowflake      — old interface, lacks capability signatures

These legacy connectors are NOT imported here.  They remain in the package
only for direct import by code that explicitly depends on the old interface.
"""

# v0.5 reference connector (always available — no extra deps)
from datafence.connectors.sqlite_connector import (
    MaliciousConnector,
    SQLiteConnector,
    create_demo_database,
)

# v0.5 optional connectors (gracefully absent if deps not installed)
try:
    from datafence.connectors.postgres_connector import PostgreSQLConnector
except ImportError:
    PostgreSQLConnector = None  # type: ignore[assignment,misc]

try:
    from datafence.connectors.athena_connector import AthenaConnector
except ImportError:
    AthenaConnector = None  # type: ignore[assignment,misc]

try:
    from datafence.connectors.snowflake_connector import SnowflakeConnector
except ImportError:
    SnowflakeConnector = None  # type: ignore[assignment,misc]

__all__ = [
    # v0.5
    "SQLiteConnector",
    "MaliciousConnector",
    "create_demo_database",
    "PostgreSQLConnector",
    "AthenaConnector",
    "SnowflakeConnector",
]
