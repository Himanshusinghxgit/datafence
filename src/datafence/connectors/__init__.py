"""
Connector contract for customer-owned data access layers.

DataFence defines the contract but does not provide production database
connectors or execute customer data queries.
"""

from datafence.connectors.protocol import ConnectorResult, DataConnector

__all__ = ["DataConnector", "ConnectorResult"]
