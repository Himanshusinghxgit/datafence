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
from datafence.core.types import Actor, Intent, Operation
from datafence.errors import DataFenceError


class ExecuteRequest(BaseModel):
    operation: str = Field(...)
    resource: str = Field(...)
    fields: list[str] | None = None
    filters: dict[str, Any] | None = None
    limit: int | None = None


class AuthorizeResponse(BaseModel):
    authorized: bool
    execution_id: str | None = None
    resource: str | None = None
    operation: str | None = None
    fields: list[str] | None = None
    predicates: list[dict[str, Any]] | None = None
    limit: int | None = None
    reasons: list[str] | None = None


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

    @app.post("/authorize", response_model=AuthorizeResponse)
    async def authorize(
        request: ExecuteRequest,
        actor: Actor = Depends(principal),  # noqa: B008
    ) -> AuthorizeResponse:  # noqa: B008
        try:
            capability = boundary.authorize(
                actor,
                Intent(
                    resource=request.resource,
                    operation=Operation(request.operation.lower()),
                    fields=request.fields,
                    filters=request.filters or {},
                    limit=request.limit,
                ),
            )
        except DataFenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Authorization denied"
            ) from exc
        return AuthorizeResponse(
            authorized=True,
            execution_id=capability.execution_id,
            resource=capability.resource,
            operation=capability.operation.value,
            fields=capability.selected_fields,
            predicates=capability.filter_constraints(),
            limit=capability.limit,
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
