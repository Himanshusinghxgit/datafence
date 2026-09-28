"""
Connector configuration helpers.

Utilities for loading connector configurations from environment variables,
config files, and connection strings.
"""

import os
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import yaml

from datafence.errors import ConfigurationError


class ConnectorConfig:
    """
    Helper for loading connector configurations.

    Supports:
    - Environment variables
    - YAML config files
    - Connection strings (URLs)
    - Direct parameters
    """

    @staticmethod
    def from_env(prefix: str = "DATAFENCE") -> dict[str, Any]:
        """
        Load configuration from environment variables.

        Environment variables:
            PostgreSQL:
                DATAFENCE_POSTGRES_HOST
                DATAFENCE_POSTGRES_PORT
                DATAFENCE_POSTGRES_DATABASE
                DATAFENCE_POSTGRES_USER
                DATAFENCE_POSTGRES_PASSWORD

            Athena:
                DATAFENCE_ATHENA_DATABASE
                DATAFENCE_ATHENA_S3_OUTPUT
                DATAFENCE_ATHENA_REGION
                DATAFENCE_ATHENA_WORKGROUP
                AWS_ACCESS_KEY_ID (standard AWS)
                AWS_SECRET_ACCESS_KEY (standard AWS)
                AWS_PROFILE (standard AWS)

            Snowflake:
                DATAFENCE_SNOWFLAKE_ACCOUNT
                DATAFENCE_SNOWFLAKE_USER
                DATAFENCE_SNOWFLAKE_PASSWORD
                DATAFENCE_SNOWFLAKE_DATABASE
                DATAFENCE_SNOWFLAKE_SCHEMA
                DATAFENCE_SNOWFLAKE_WAREHOUSE

        Args:
            prefix: Environment variable prefix

        Returns:
            Configuration dictionary
        """
        config: dict[str, Any] = {}

        # PostgreSQL
        if os.getenv(f"{prefix}_POSTGRES_HOST"):
            config["postgres"] = {
                "host": os.getenv(f"{prefix}_POSTGRES_HOST", "localhost"),
                "port": int(os.getenv(f"{prefix}_POSTGRES_PORT", "5432")),
                "database": os.getenv(f"{prefix}_POSTGRES_DATABASE"),
                "user": os.getenv(f"{prefix}_POSTGRES_USER"),
                "password": os.getenv(f"{prefix}_POSTGRES_PASSWORD"),
            }

        # Athena
        if os.getenv(f"{prefix}_ATHENA_DATABASE"):
            config["athena"] = {
                "database": os.getenv(f"{prefix}_ATHENA_DATABASE"),
                "s3_output_location": os.getenv(f"{prefix}_ATHENA_S3_OUTPUT"),
                "region_name": os.getenv(f"{prefix}_ATHENA_REGION", "us-east-1"),
                "workgroup": os.getenv(f"{prefix}_ATHENA_WORKGROUP", "primary"),
            }
            # AWS credentials (standard env vars)
            if os.getenv("AWS_PROFILE"):
                config["athena"]["profile_name"] = os.getenv("AWS_PROFILE")
            elif os.getenv("AWS_ACCESS_KEY_ID"):
                config["athena"]["aws_access_key_id"] = os.getenv("AWS_ACCESS_KEY_ID")
                config["athena"]["aws_secret_access_key"] = os.getenv(
                    "AWS_SECRET_ACCESS_KEY"
                )

        # Snowflake
        if os.getenv(f"{prefix}_SNOWFLAKE_ACCOUNT"):
            config["snowflake"] = {
                "account": os.getenv(f"{prefix}_SNOWFLAKE_ACCOUNT"),
                "user": os.getenv(f"{prefix}_SNOWFLAKE_USER"),
                "password": os.getenv(f"{prefix}_SNOWFLAKE_PASSWORD"),
                "database": os.getenv(f"{prefix}_SNOWFLAKE_DATABASE"),
                "schema": os.getenv(f"{prefix}_SNOWFLAKE_SCHEMA", "PUBLIC"),
                "warehouse": os.getenv(f"{prefix}_SNOWFLAKE_WAREHOUSE"),
            }

        return config

    @staticmethod
    def from_yaml(path: str | Path) -> dict[str, Any]:
        """
        Load configuration from YAML file.

        Example YAML:
            postgres:
              host: localhost
              port: 5432
              database: mydb
              user: myuser
              password: mypassword

            athena:
              database: mydatabase
              s3_output_location: s3://my-bucket/results/
              region_name: us-east-1

            snowflake:
              account: myaccount
              user: myuser
              password: mypassword
              database: MYDB
              warehouse: COMPUTE_WH

        Args:
            path: Path to YAML config file

        Returns:
            Configuration dictionary

        Raises:
            ConfigurationError: If file not found or invalid
        """
        path = Path(path)

        if not path.exists():
            raise ConfigurationError(f"Config file not found: {path}")

        try:
            with open(path, "r") as f:
                config = yaml.safe_load(f)

            if not isinstance(config, dict):
                raise ConfigurationError("Config file must contain a dictionary")

            return config

        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML: {e}") from e
        except Exception as e:
            raise ConfigurationError(f"Failed to load config: {e}") from e

    @staticmethod
    def from_connection_string(connection_string: str) -> dict[str, Any]:
        """
        Parse connection string into configuration.

        Supports:
            PostgreSQL: postgresql://user:pass@host:port/database
            Athena: athena://database?s3_output=s3://bucket/path&region=us-east-1
            Snowflake: snowflake://user:pass@account/database?warehouse=WH&schema=PUBLIC

        Args:
            connection_string: Database connection URL

        Returns:
            Configuration dictionary

        Raises:
            ConfigurationError: If connection string invalid
        """
        try:
            parsed = urlparse(connection_string)

            if parsed.scheme == "postgresql":
                return {
                    "postgres": {
                        "host": parsed.hostname or "localhost",
                        "port": parsed.port or 5432,
                        "database": parsed.path.lstrip("/"),
                        "user": parsed.username,
                        "password": parsed.password,
                    }
                }

            elif parsed.scheme == "athena":
                query_params = parse_qs(parsed.query)
                return {
                    "athena": {
                        "database": parsed.hostname or parsed.path.lstrip("/"),
                        "s3_output_location": query_params.get("s3_output", [None])[0],
                        "region_name": query_params.get("region", ["us-east-1"])[0],
                        "workgroup": query_params.get("workgroup", ["primary"])[0],
                    }
                }

            elif parsed.scheme == "snowflake":
                query_params = parse_qs(parsed.query)
                return {
                    "snowflake": {
                        "account": parsed.hostname,
                        "user": parsed.username,
                        "password": parsed.password,
                        "database": parsed.path.lstrip("/").split("/")[0]
                        if parsed.path
                        else None,
                        "warehouse": query_params.get("warehouse", [None])[0],
                        "schema": query_params.get("schema", ["PUBLIC"])[0],
                    }
                }

            else:
                raise ConfigurationError(f"Unsupported connection string scheme: {parsed.scheme}")

        except Exception as e:
            raise ConfigurationError(f"Failed to parse connection string: {e}") from e

    @staticmethod
    def create_connector(connector_type: str, config: dict[str, Any]) -> Any:
        """
        Create connector from configuration.

        Args:
            connector_type: Type of connector ('postgres', 'athena', 'snowflake')
            config: Configuration dictionary

        Returns:
            Connector instance

        Raises:
            ConfigurationError: If connector type unknown or config invalid
        """
        if connector_type == "postgres":
            from datafence.connectors.postgres import PostgreSQLConnector

            return PostgreSQLConnector(**config)

        elif connector_type == "athena":
            from datafence.connectors.athena import AthenaConnector

            return AthenaConnector(**config)

        elif connector_type == "snowflake":
            from datafence.connectors.snowflake import SnowflakeConnector

            return SnowflakeConnector(**config)

        else:
            raise ConfigurationError(f"Unknown connector type: {connector_type}")


# Convenience function
def load_connector_config(
    path: str | Path | None = None, connection_string: str | None = None
) -> dict[str, Any]:
    """
    Load connector configuration from various sources.

    Priority:
    1. Connection string (if provided)
    2. Config file (if provided)
    3. Environment variables

    Args:
        path: Path to YAML config file
        connection_string: Database connection URL

    Returns:
        Configuration dictionary
    """
    if connection_string:
        return ConnectorConfig.from_connection_string(connection_string)

    if path:
        return ConnectorConfig.from_yaml(path)

    return ConnectorConfig.from_env()
