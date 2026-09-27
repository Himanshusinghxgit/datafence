"""Data connectors."""

from datafence.connectors.base import DataConnector
from datafence.connectors.memory import MemoryConnector
from datafence.connectors.sqlite import SQLiteConnector

# Optional connectors (require extra dependencies)
try:
    from datafence.connectors.postgres import PostgreSQLConnector
except ImportError:
    PostgreSQLConnector = None

try:
    from datafence.connectors.athena import AthenaConnector
except ImportError:
    AthenaConnector = None

try:
    from datafence.connectors.snowflake import SnowflakeConnector
except ImportError:
    SnowflakeConnector = None

__all__ = [
    "DataConnector",
    "MemoryConnector",
    "SQLiteConnector",
    "PostgreSQLConnector",
    "AthenaConnector",
    "SnowflakeConnector",
]
