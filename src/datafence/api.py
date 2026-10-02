"""Authenticated REST adapter for the canonical DataFence boundary."""

from collections.abc import Callable
from typing import Any

try:
    from fastapi import Depends, FastAPI, HTTPException, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover
    FastAPI = None
    HTTPException = None
    HTTPBearer = None
    BaseModel = object
    Field = None

from datafence.core.boundary import DataFenceBoundary
from datafence.core.types import Actor, AllowedRequest, Intent, Operation


class ExecuteRequest(BaseModel):
    operation: str = Field(...)
    resource: str = Field(...)
    fields: list[str] | None = None
    filters: dict[str, Any] | None = None
    limit: int | None = None


class ExecuteResponse(BaseModel):
    success: bool
    verified: bool
    data: list[dict[str, Any]] | None = None
    row_count: int | None = None
    decision: str
    reasons: list[str] | None = None
    evidence_hash: str | None = None
    timestamp: str | None = None


class DescribeRequest(BaseModel):
    resource: str


class HealthResponse(BaseModel):
    status: str
    version: str


def create_api(
    boundary: DataFenceBoundary,
    principal_resolver: Callable[[HTTPAuthorizationCredentials], Actor],
    enable_cors: bool = True,
    title: str = "DataFence API",
    description: str = "Authenticated policy-enforced data access",
    version: str = "1.0.0",
) -> Any:
    """Create an API; identity is resolved from bearer credentials only."""
    if FastAPI is None:
        raise ImportError("fastapi required. Install with: pip install 'datafence[api]'")
    app = FastAPI(title=title, description=description, version=version)
    if enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[],
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )
    bearer = HTTPBearer(auto_error=True)

    def principal(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> Actor:  # noqa: B008
        try:
            actor = principal_resolver(credentials)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed"
            ) from exc
        if not isinstance(actor, Actor):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed"
            )
        return actor

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="healthy", version=version)

    @app.post("/execute", response_model=ExecuteResponse)
    async def execute(
        request: ExecuteRequest,
        actor: Actor = Depends(principal),  # noqa: B008
    ) -> ExecuteResponse:  # noqa: B008
        try:
            result = boundary.execute(
                actor,
                Intent(
                    resource=request.resource,
                    operation=Operation(request.operation.lower()),
                    fields=request.fields,
                    filters=request.filters or {},
                    limit=request.limit,
                ),
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid request"
            ) from exc
        if isinstance(result, AllowedRequest):
            return ExecuteResponse(
                success=True,
                verified=True,
                data=result.execution_result.data,
                row_count=result.execution_result.row_count,
                decision="allow",
                evidence_hash=result.evidence.evidence_hash,
                timestamp=result.evidence.timestamp.isoformat(),
            )
        return ExecuteResponse(
            success=False,
            verified=False,
            decision="deny",
            reasons=result.decision.reasons,
            evidence_hash=result.evidence.evidence_hash,
            timestamp=result.evidence.timestamp.isoformat(),
        )

    @app.post("/describe")
    async def describe(request: DescribeRequest, _: Actor = Depends(principal)) -> dict[str, Any]:  # noqa: B008
        resource = boundary._registry.get(request.resource)
        if resource is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")
        return {
            "success": True,
            "metadata": {
                "name": resource.name,
                "fields": resource.field_names(),
                "description": resource.description,
            },
        }

    @app.get("/policy")
    async def policy(_: Actor = Depends(principal)) -> dict[str, Any]:  # noqa: B008
        engine = boundary.policy_engine
        return {
            "name": engine.policy_name,
            "version": engine.policy_version,
            "resources": boundary._registry.all_resources(),
        }

    return app


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit("Configure a boundary and call create_api() from an application entrypoint")
