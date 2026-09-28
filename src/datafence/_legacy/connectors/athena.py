"""
DEPRECATED (v0.1-v0.4) Athena connector — legacy interface.

⚠️  Use datafence.connectors.athena_connector.AthenaConnector instead.
    That connector accepts signed AuthorizedExecution capabilities and
    verifies HMAC before executing any query.
"""

import warnings
warnings.warn(
    "datafence.connectors.athena (v0.1-v0.4 legacy) is deprecated. "
    "Use datafence.connectors.athena_connector.AthenaConnector instead.",
    DeprecationWarning,
    stacklevel=2,
)

from typing import Any
from time import sleep

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    boto3 = None
    ClientError = None
    BotoCoreError = None

from datafence.connectors.base import DataConnector
from datafence.core.request import ExecutionRequest, Operation
from datafence.errors import ConnectorError, ValidationError


class AthenaConnector(DataConnector):
    """
    Amazon Athena connector for querying data lakes.

    Features:
    - Query S3 data with SQL
    - Automatic result pagination
    - Query execution tracking
    - S3 result location management
    - AWS credentials from environment/profile

    Example:
        connector = AthenaConnector(
            database="mydatabase",
            s3_output_location="s3://my-bucket/query-results/",
            region_name="us-east-1"
        )
    """

    def __init__(
        self,
        database: str,
        s3_output_location: str,
        region_name: str = "us-east-1",
        workgroup: str = "primary",
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
        profile_name: str | None = None,
        poll_interval: float = 1.0,
        max_wait_time: float = 300.0,
    ):
        """
        Initialize Athena connector.

        Args:
            database: Athena database name
            s3_output_location: S3 path for query results (e.g., s3://bucket/path/)
            region_name: AWS region
            workgroup: Athena workgroup
            aws_access_key_id: AWS access key (optional, uses env/profile if not provided)
            aws_secret_access_key: AWS secret key (optional)
            profile_name: AWS profile name (optional)
            poll_interval: Seconds between query status checks
            max_wait_time: Maximum seconds to wait for query completion

        Raises:
            ImportError: If boto3 not installed
            ConnectorError: If AWS credentials invalid
        """
        if boto3 is None:
            raise ImportError(
                "boto3 is not installed. Install with: pip install 'datafence[athena]'"
            )

        self.database = database
        self.s3_output_location = s3_output_location
        self.workgroup = workgroup
        self.poll_interval = poll_interval
        self.max_wait_time = max_wait_time

        # Create boto3 session
        session_kwargs = {"region_name": region_name}
        if profile_name:
            session_kwargs["profile_name"] = profile_name
        elif aws_access_key_id and aws_secret_access_key:
            session_kwargs["aws_access_key_id"] = aws_access_key_id
            session_kwargs["aws_secret_access_key"] = aws_secret_access_key

        try:
            self.session = boto3.Session(**session_kwargs)
            self.client = self.session.client("athena")
            self.s3_client = self.session.client("s3")
        except Exception as e:
            raise ConnectorError(f"Failed to create AWS session: {e}") from e

    def execute(
        self, request: ExecutionRequest, allowed_fields: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """
        Execute query against Athena.

        Args:
            request: Execution request
            allowed_fields: Allowed fields from policy

        Returns:
            Query results as list of dicts

        Raises:
            ConnectorError: If query fails
            ValidationError: If operation not supported
        """
        if request.operation != Operation.READ:
            raise ValidationError(
                f"Athena connector only supports READ operations, got: {request.operation}"
            )

        # Build query
        query = self._build_query(request, allowed_fields)

        # Execute query
        try:
            # Start query execution
            response = self.client.start_query_execution(
                QueryString=query,
                QueryExecutionContext={"Database": self.database},
                ResultConfiguration={"OutputLocation": self.s3_output_location},
                WorkGroup=self.workgroup,
            )

            query_execution_id = response["QueryExecutionId"]

            # Wait for query to complete
            self._wait_for_query_completion(query_execution_id)

            # Get results
            results = self._get_query_results(query_execution_id)

            return results

        except (ClientError, BotoCoreError) as e:
            raise ConnectorError(f"Athena query failed: {e}") from e
        except Exception as e:
            raise ConnectorError(f"Unexpected error: {e}") from e

    def describe(self, resource: str) -> dict[str, Any]:
        """
        Describe an Athena table.

        Args:
            resource: Table name (can include database: database.table)

        Returns:
            Table metadata

        Raises:
            ConnectorError: If table doesn't exist
        """
        try:
            # Parse database and table
            if "." in resource:
                database, table = resource.split(".", 1)
            else:
                database = self.database
                table = resource

            # Get table metadata
            response = self.client.get_table_metadata(
                CatalogName="AwsDataCatalog", DatabaseName=database, TableName=table
            )

            table_metadata = response["TableMetadata"]

            columns = [
                {"name": col["Name"], "type": col["Type"], "comment": col.get("Comment", "")}
                for col in table_metadata.get("Columns", [])
            ]

            return {
                "resource": resource,
                "database": database,
                "table": table,
                "columns": columns,
                "fields": [col["name"] for col in columns],
                "location": table_metadata.get("Parameters", {}).get("location"),
                "table_type": table_metadata.get("TableType"),
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityNotFoundException":
                raise ConnectorError(f"Table '{resource}' not found")
            raise ConnectorError(f"Failed to describe table '{resource}': {e}") from e

    def _build_query(
        self, request: ExecutionRequest, allowed_fields: list[str] | None
    ) -> str:
        """
        Build SQL query for Athena.

        Args:
            request: Execution request
            allowed_fields: Allowed fields

        Returns:
            SQL query string
        """
        # Determine fields
        if allowed_fields:
            fields = allowed_fields
        elif request.fields:
            fields = request.fields
        else:
            fields = ["*"]

        # Build SELECT clause
        select_clause = ", ".join(fields) if fields != ["*"] else "*"

        # Start query
        query = f"SELECT {select_clause} FROM {request.resource}"

        # Build WHERE clause
        if request.filters:
            conditions = []
            for key, value in request.filters.items():
                # Simple string escaping (Athena uses single quotes)
                if isinstance(value, str):
                    escaped_value = value.replace("'", "''")
                    conditions.append(f"{key} = '{escaped_value}'")
                else:
                    conditions.append(f"{key} = {value}")

            query += " WHERE " + " AND ".join(conditions)

        # Add LIMIT
        if request.limit:
            query += f" LIMIT {request.limit}"

        return query

    def _wait_for_query_completion(self, query_execution_id: str) -> None:
        """
        Wait for query to complete.

        Args:
            query_execution_id: Athena query execution ID

        Raises:
            ConnectorError: If query fails or times out
        """
        elapsed = 0.0

        while elapsed < self.max_wait_time:
            response = self.client.get_query_execution(
                QueryExecutionId=query_execution_id
            )

            status = response["QueryExecution"]["Status"]["State"]

            if status == "SUCCEEDED":
                return
            elif status in ("FAILED", "CANCELLED"):
                reason = response["QueryExecution"]["Status"].get(
                    "StateChangeReason", "Unknown"
                )
                raise ConnectorError(f"Query {status.lower()}: {reason}")

            # Still running, wait and check again
            sleep(self.poll_interval)
            elapsed += self.poll_interval

        raise ConnectorError(
            f"Query timed out after {self.max_wait_time} seconds"
        )

    def _get_query_results(self, query_execution_id: str) -> list[dict[str, Any]]:
        """
        Get query results with pagination.

        Args:
            query_execution_id: Athena query execution ID

        Returns:
            List of result rows as dicts
        """
        results = []
        next_token = None

        while True:
            # Get page of results
            kwargs = {"QueryExecutionId": query_execution_id, "MaxResults": 1000}
            if next_token:
                kwargs["NextToken"] = next_token

            response = self.client.get_query_results(**kwargs)

            # First row is headers
            rows = response["ResultSet"]["Rows"]

            if not results and rows:
                # Extract column names from first row
                headers = [col["VarCharValue"] for col in rows[0]["Data"]]
                rows = rows[1:]  # Skip header row

                # Convert remaining rows to dicts
                for row in rows:
                    row_dict = {}
                    for i, col in enumerate(row["Data"]):
                        # Get value (may be empty)
                        value = col.get("VarCharValue")
                        row_dict[headers[i]] = value
                    results.append(row_dict)
            else:
                # Subsequent pages don't have headers
                if results:  # We have headers from first page
                    headers = list(results[0].keys())
                    for row in rows:
                        row_dict = {}
                        for i, col in enumerate(row["Data"]):
                            value = col.get("VarCharValue")
                            row_dict[headers[i]] = value
                        results.append(row_dict)

            # Check for more pages
            next_token = response.get("NextToken")
            if not next_token:
                break

        return results

    def close(self) -> None:
        """Close connector (no-op for Athena)."""
        pass

    def __enter__(self) -> "AthenaConnector":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
