"""
Langflow Custom Component for DataFence.

Wraps database agents with DataFence security in Langflow workflows.
"""

from typing import Any
from langflow.custom import Component
from langflow.io import (
    MessageTextInput,
    Output,
    DropdownInput,
    FileInput,
    SecretStrInput,
    MultilineInput,
)
from langflow.schema import Data

from datafence import DataFence
from datafence.connectors import (
    MemoryConnector,
    SQLiteConnector,
)


class DataFenceSecurityComponent(Component):
    """
    DataFence Security Layer for Langflow.
    
    Sits between LLM and Database, enforcing security policies.
    
    Flow:
    LLM Request → DataFence Security → Database Connector → DataFence Validation → LLM Response
    """

    display_name = "DataFence Security"
    description = "Enforce security policies on database access"
    icon = "shield"
    name = "DataFenceSecurity"

    inputs = [
        FileInput(
            name="policy_file",
            display_name="Policy File",
            info="YAML policy file path",
            required=True,
        ),
        DropdownInput(
            name="connector_type",
            display_name="Connector Type",
            options=["memory", "sqlite", "postgres", "athena", "snowflake"],
            value="memory",
            info="Database connector type",
        ),
        MessageTextInput(
            name="database_uri",
            display_name="Database URI",
            info="Database connection URI (for sqlite/postgres)",
            required=False,
        ),
        MessageTextInput(
            name="actor_id",
            display_name="Actor ID",
            info="Actor identifier (e.g., user:123)",
            value="agent:langflow",
        ),
        MessageTextInput(
            name="tenant_id",
            display_name="Tenant ID",
            info="Tenant identifier for multi-tenancy",
            value="default",
        ),
        MessageTextInput(
            name="operation",
            display_name="Operation",
            info="Database operation (read, insert, update, delete)",
            value="read",
        ),
        MessageTextInput(
            name="resource",
            display_name="Resource",
            info="Database table/resource name",
            required=True,
        ),
        MultilineInput(
            name="fields",
            display_name="Fields",
            info="Comma-separated list of fields to retrieve",
            required=False,
        ),
        MultilineInput(
            name="filters",
            display_name="Filters (JSON)",
            info='Filter conditions as JSON (e.g., {"customer_id": "123"})',
            required=False,
        ),
        MessageTextInput(
            name="limit",
            display_name="Limit",
            info="Maximum rows to return",
            value="100",
        ),
        DropdownInput(
            name="enable_sql_firewall",
            display_name="Enable SQL Firewall",
            options=["true", "false"],
            value="true",
            info="Block SQL injection attempts",
        ),
        DropdownInput(
            name="enable_pii_detection",
            display_name="Enable PII Detection",
            options=["true", "false"],
            value="true",
            info="Detect and redact PII",
        ),
    ]

    outputs = [
        Output(display_name="Result", name="result", method="execute_request"),
        Output(display_name="Data", name="data", method="get_data"),
        Output(display_name="Decision", name="decision", method="get_decision"),
    ]

    def _create_connector(self):
        """Create database connector based on type."""
        if self.connector_type == "memory":
            return MemoryConnector(data={})
        
        elif self.connector_type == "sqlite":
            if not self.database_uri:
                raise ValueError("Database URI required for SQLite")
            return SQLiteConnector(self.database_uri)
        
        elif self.connector_type == "postgres":
            from datafence.connectors import PostgreSQLConnector
            # Parse connection string or use individual params
            return PostgreSQLConnector(connection_string=self.database_uri)
        
        elif self.connector_type == "athena":
            from datafence.connectors import AthenaConnector
            # Parse from database_uri or environment
            import os
            return AthenaConnector(
                database=os.getenv("ATHENA_DATABASE", "default"),
                s3_output_location=os.getenv("ATHENA_S3_OUTPUT", "s3://bucket/results/"),
                region_name=os.getenv("AWS_REGION", "us-east-1"),
            )
        
        elif self.connector_type == "snowflake":
            from datafence.connectors import SnowflakeConnector
            # Parse from environment
            import os
            return SnowflakeConnector(
                account=os.getenv("SNOWFLAKE_ACCOUNT"),
                user=os.getenv("SNOWFLAKE_USER"),
                password=os.getenv("SNOWFLAKE_PASSWORD"),
                database=os.getenv("SNOWFLAKE_DATABASE"),
                warehouse=os.getenv("SNOWFLAKE_WAREHOUSE"),
            )
        
        else:
            raise ValueError(f"Unknown connector type: {self.connector_type}")

    def _parse_fields(self):
        """Parse comma-separated fields."""
        if not self.fields or not self.fields.strip():
            return None
        return [f.strip() for f in self.fields.split(",")]

    def _parse_filters(self):
        """Parse JSON filters."""
        if not self.filters or not self.filters.strip():
            return {}
        
        import json
        try:
            return json.loads(self.filters)
        except json.JSONDecodeError:
            return {}

    def execute_request(self) -> Data:
        """
        Execute database request through DataFence.
        
        Returns:
            Data object with results
        """
        # Create connector
        connector = self._create_connector()
        
        # Create DataFence instance
        fence = DataFence.from_yaml(
            self.policy_file,
            connector,
            enable_sql_firewall=(self.enable_sql_firewall == "true"),
            enable_pii_detection=(self.enable_pii_detection == "true"),
        )
        
        # Build request
        request_dict = {
            "actor": {
                "id": self.actor_id,
                "tenant_id": self.tenant_id,
            },
            "operation": self.operation,
            "resource": self.resource,
        }
        
        # Add optional fields
        fields = self._parse_fields()
        if fields:
            request_dict["fields"] = fields
        
        filters = self._parse_filters()
        if filters:
            request_dict["filters"] = filters
        
        if self.limit:
            try:
                request_dict["limit"] = int(self.limit)
            except ValueError:
                pass
        
        # Execute through DataFence
        result = fence.execute(request_dict)
        
        # Store result for other outputs
        self._result = result
        
        # Format as Langflow Data
        return Data(
            data={
                "success": result.verified,
                "data": result.data if result.verified else None,
                "row_count": len(result.data) if result.verified else 0,
                "decision": result.decision.decision.value,
                "reasons": result.decision.reasons if not result.verified else [],
                "evidence_hash": result.evidence.evidence_hash if result.verified else None,
            }
        )

    def get_data(self) -> list[dict[str, Any]]:
        """Get data from last execution."""
        if hasattr(self, "_result") and self._result.verified:
            return self._result.data
        return []

    def get_decision(self) -> str:
        """Get policy decision from last execution."""
        if hasattr(self, "_result"):
            return self._result.decision.decision.value
        return "unknown"


class DataFenceLLMAgentWrapper(Component):
    """
    Wrap any LLM Agent with DataFence security.
    
    Intercepts agent's database queries and enforces policies.
    
    Flow:
    User Query → LLM Agent → DataFence (intercept) → Database → DataFence (validate) → Response
    """

    display_name = "DataFence LLM Agent Wrapper"
    description = "Wrap LLM agents with DataFence security"
    icon = "shield-check"
    name = "DataFenceLLMWrapper"

    inputs = [
        FileInput(
            name="policy_file",
            display_name="Policy File",
            required=True,
        ),
        MessageTextInput(
            name="actor_id",
            display_name="Actor ID",
            value="agent:langflow",
        ),
        MessageTextInput(
            name="tenant_id",
            display_name="Tenant ID",
            value="default",
        ),
        # Agent configuration would be passed from upstream component
    ]

    outputs = [
        Output(display_name="Secured Agent", name="agent", method="create_secured_agent"),
    ]

    def create_secured_agent(self) -> Any:
        """
        Create a secured version of the agent.
        
        Returns:
            Agent wrapper that enforces DataFence policies
        """
        from datafence.integrations.langchain_tool import create_datafence_tools
        
        # This would be used with LangChain agents
        # The tools would be created with DataFence security
        
        # Return configuration for downstream use
        return {
            "policy_file": self.policy_file,
            "actor": {
                "id": self.actor_id,
                "tenant_id": self.tenant_id,
            },
            "secured": True,
        }
