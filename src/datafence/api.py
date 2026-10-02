"""
REST API wrapper for DataFence.

Provides HTTP API for DataFence with authentication and rate limiting.
"""

from typing import Any

try:
    import uvicorn
    from fastapi import Depends, FastAPI, HTTPException, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel, Field
except ImportError:
    FastAPI = None
    HTTPException = None
    HTTPBearer = None
    BaseModel = object
    Field = None

from datafence import DataFence
from datafence.errors import DataFenceError


# Request/Response models
class ExecuteRequest(BaseModel):
    """Request to execute a query."""

    actor: dict[str, Any] = Field(..., description="Actor information")
    operation: str = Field(..., description="Operation type (read, insert, update, delete)")
    resource: str = Field(..., description="Resource name")
    fields: list[str] | None = Field(None, description="Fields to retrieve")
    filters: dict[str, Any] | None = Field(None, description="Filter conditions")
    limit: int | None = Field(None, description="Maximum rows")
    context: dict[str, Any] | None = Field(None, description="Additional context")


class ExecuteResponse(BaseModel):
    """Response from execute."""

    success: bool = Field(..., description="Whether request was successful")
    verified: bool = Field(..., description="Whether result was verified")
    data: list[dict[str, Any]] | None = Field(None, description="Query results")
    row_count: int | None = Field(None, description="Number of rows returned")
    decision: str = Field(..., description="Policy decision")
    reasons: list[str] | None = Field(None, description="Reasons for denial")
    evidence_hash: str | None = Field(None, description="Evidence hash")
    timestamp: str | None = Field(None, description="Execution timestamp")


class DescribeRequest(BaseModel):
    """Request to describe a resource."""

    resource: str = Field(..., description="Resource name")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = Field(..., description="Service status")
    version: str = Field(..., description="DataFence version")


def create_api(
    fence: DataFence,
    api_keys: set[str] | None = None,
    enable_cors: bool = True,
    title: str = "DataFence API",
    description: str = "Secure data access API with policy enforcement",
    version: str = "1.0.0",
) -> Any:
    """
    Create FastAPI application for DataFence.

    Args:
        fence: Configured DataFence instance
        api_keys: Set of valid API keys (if None, no auth required)
        enable_cors: Enable CORS middleware
        title: API title
        description: API description
        version: API version

    Returns:
        FastAPI application

    Example:
        fence = DataFence.from_yaml("policy.yaml", connector)
        app = create_api(fence, api_keys={"secret-key-1", "secret-key-2"})
        uvicorn.run(app, host="0.0.0.0", port=8000)
    """
    if FastAPI is None:
        raise ImportError("fastapi required. Install with: pip install 'datafence[api]'")

    app = FastAPI(title=title, description=description, version=version)

    # CORS
    if enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Authentication
    security = HTTPBearer(auto_error=False) if api_keys else None

    def verify_api_key(
        credentials: HTTPAuthorizationCredentials | None = Depends(security),  # noqa: B008
    ) -> None:
        """Verify API key."""
        if api_keys:
            if not credentials or credentials.credentials not in api_keys:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing API key",
                    headers={"WWW-Authenticate": "Bearer"},
                )

    @app.get("/health", response_model=HealthResponse, tags=["Health"])
    async def health():
        """Health check endpoint."""
        return HealthResponse(status="healthy", version=version)

    @app.post(
        "/execute",
        response_model=ExecuteResponse,
        tags=["Data"],
        dependencies=[Depends(verify_api_key)] if api_keys else [],
    )
    async def execute(request: ExecuteRequest):
        """
        Execute a data request with policy enforcement.

        Validates the request against policies, executes the query,
        and returns results with evidence.
        """
        try:
            # Convert to dict for DataFence
            request_dict = {
                "actor": request.actor,
                "operation": request.operation,
                "resource": request.resource,
            }

            if request.fields:
                request_dict["fields"] = request.fields
            if request.filters:
                request_dict["filters"] = request.filters
            if request.limit:
                request_dict["limit"] = request.limit
            if request.context:
                request_dict["context"] = request.context

            # Execute through DataFence
            result = fence.execute(request_dict)

            # Format response
            return ExecuteResponse(
                success=result.verified,
                verified=result.verified,
                data=result.data if result.verified else None,
                row_count=len(result.data) if result.verified else None,
                decision=result.decision.decision.value,
                reasons=result.decision.reasons if not result.verified else None,
                evidence_hash=result.evidence.evidence_hash if result.verified else None,
                timestamp=result.evidence.timestamp if result.verified else None,
            )

        except DataFenceError as e:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            ) from e

    @app.post(
        "/describe",
        tags=["Metadata"],
        dependencies=[Depends(verify_api_key)] if api_keys else [],
    )
    async def describe(request: DescribeRequest):
        """
        Describe a resource (table metadata).

        Returns column information and metadata.
        """
        try:
            metadata = fence.connector.describe(request.resource)
            return {"success": True, "metadata": metadata}

        except DataFenceError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            ) from e

    @app.get(
        "/policy",
        tags=["Policy"],
        dependencies=[Depends(verify_api_key)] if api_keys else [],
    )
    async def get_policy():
        """
        Get current policy information.

        Returns policy name, version, and resource list.
        """
        if not fence.policy:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No policy loaded")

        return {
            "name": fence.policy.name,
            "description": getattr(fence.policy, "description", None),
            "resources": list(fence.policy.resources.keys()),
        }

    @app.get(
        "/policy/resources/{resource_name}",
        tags=["Policy"],
        dependencies=[Depends(verify_api_key)] if api_keys else [],
    )
    async def get_resource_policy(resource_name: str):
        """
        Get policy for a specific resource.

        Returns allowed operations, fields, and limits.
        """
        if not fence.policy or resource_name not in fence.policy.resources:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Resource '{resource_name}' not found in policy",
            )

        resource_config = fence.policy.resources[resource_name]

        return {
            "resource": resource_name,
            "operations": resource_config.operations,
            "fields": resource_config.fields,
            "limits": getattr(resource_config, "limits", None),
        }

    return app


def run_api(
    fence: DataFence,
    host: str = "0.0.0.0",
    port: int = 8000,
    api_keys: set[str] | None = None,
    **kwargs,
):
    """
    Run DataFence API server.

    Args:
        fence: Configured DataFence instance
        host: Host to bind to
        port: Port to bind to
        api_keys: Set of valid API keys
        **kwargs: Additional arguments for uvicorn.run

    Example:
        fence = DataFence.from_yaml("policy.yaml", connector)
        run_api(fence, port=8000, api_keys={"my-secret-key"})
    """
    if uvicorn is None:
        raise ImportError("uvicorn required. Install with: pip install 'datafence[api]'")

    app = create_api(fence, api_keys=api_keys)
    uvicorn.run(app, host=host, port=port, **kwargs)


# CLI integration
def main():
    """CLI entry point for running API server."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m datafence.api <policy_file> [--port PORT] [--api-key KEY]")
        sys.exit(1)

    policy_file = sys.argv[1]

    # Parse options
    port = 8000
    api_keys = set()

    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == "--api-key" and i + 1 < len(sys.argv):
            api_keys.add(sys.argv[i + 1])
            i += 2
        else:
            i += 1

    # Create connector (simple memory for demo)
    from datafence.connectors import MemoryConnector

    connector = MemoryConnector(data={})

    # Load DataFence
    fence = DataFence.from_yaml(policy_file, connector)

    print(f"Starting DataFence API server on port {port}")
    print(f"Policy: {policy_file}")
    print(f"Authentication: {'Enabled' if api_keys else 'Disabled'}")

    run_api(fence, port=port, api_keys=api_keys if api_keys else None)


if __name__ == "__main__":
    main()
