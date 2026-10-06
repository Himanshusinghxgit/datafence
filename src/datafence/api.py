"""
Authenticated REST adapter for the canonical DataFence boundary.

Endpoints
---------
GET  /health                       Liveness check.
POST /authorize                    Authorize an intent; returns a portable capability token.
GET  /describe/{resource}          Describe a registered resource's schema.
GET  /policy                       Return policy name and version (not full resource detail).

Security model
--------------
The Principal is resolved from the HTTP Bearer token by the caller-supplied
``principal_resolver``.  Request bodies are untrusted Intent only.
The response to a successful /authorize includes the signed CapabilityToken
so the caller can transport it to their connector for verification without
needing a DataFence runtime object.

CORS is configured conservatively (no origins by default).  Callers should
set ``allowed_origins`` explicitly for their deployment.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

try:
    from fastapi import Depends, FastAPI, HTTPException, Path, status
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from pydantic import BaseModel, Field, field_validator
except ImportError:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment,misc]
    HTTPException = None  # type: ignore[assignment,misc]
    HTTPBearer = None  # type: ignore[assignment,misc]
    BaseModel = object  # type: ignore[assignment,misc]
    Field = None  # type: ignore[assignment]
    field_validator = None  # type: ignore[assignment]
    Path = None  # type: ignore[assignment]

from datafence.core.boundary import DataFenceBoundary
from datafence.core.capability import CapabilityToken
from datafence.core.principal import Principal
from datafence.core.types import Intent, Operation
from datafence.errors import DataFenceError

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class AuthorizationRequest(BaseModel):  # type: ignore[misc]
    """Untrusted Intent from the AI agent or API caller.

    v0.1 only supports READ operations.
    """

    operation: str = Field(
        default="read",
        description="Operation type. v0.1 supports 'read' only.",
    )
    resource: str = Field(..., description="Resource name to access.")
    fields: list[str] | None = Field(None, description="Fields to return.")
    filters: dict[str, Any] | None = Field(None, description="Agent-supplied row filters.")
    limit: int | None = Field(None, ge=1, description="Maximum rows (bounded by policy).")

    if field_validator is not None:
        @field_validator("operation")
        @classmethod
        def _validate_operation(cls, v: str) -> str:
            if v.lower() != "read":
                raise ValueError(
                    f"Operation {v!r} is not supported in v0.1. "
                    "Only 'read' is supported."
                )
            return "read"

        @field_validator("resource")
        @classmethod
        def _validate_resource(cls, v: str) -> str:
            if not v or not v.strip():
                raise ValueError("resource cannot be empty")
            return v


class AuthorizeResponse(BaseModel):  # type: ignore[misc]
    """
    Successful authorization response.

    ``token`` is a portable signed CapabilityToken that the caller can
    transport to their connector for verification via
    ``CapabilityVerifier.verify_token(token)``.

    The raw HMAC signature is embedded in the token (hex-encoded).
    """

    status: str = "authorized"
    token: str = Field(..., description="Signed portable CapabilityToken (JSON string).")
    execution_id: str
    resource: str
    operation: str
    fields: list[str]
    predicates: list[dict[str, Any]]
    limit: int
    expires_at: str | None = None
    audience: str
    obligations: dict[str, Any] = Field(default_factory=dict)


class DenyResponse(BaseModel):  # type: ignore[misc]
    status: str = "denied"
    reasons: list[str]


class HealthResponse(BaseModel):  # type: ignore[misc]
    status: str
    version: str


class DescribeResponse(BaseModel):  # type: ignore[misc]
    resource: str
    fields: list[str]
    tenant_key: str | None = None
    description: str = ""


class PolicyInfoResponse(BaseModel):  # type: ignore[misc]
    """
    High-level policy information.  Does NOT expose the full resource policy detail
    to prevent policy enumeration attacks.
    """

    name: str
    version: str
    resource_count: int


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_api(
    boundary: DataFenceBoundary,
    principal_resolver: Callable[[Any], Principal],
    enable_cors: bool = True,
    allowed_origins: list[str] | None = None,
    title: str = "DataFence Authorization API",
    description: str = "Authenticated authorization boundary for AI agent data access",
    version: str = "0.1.0",
) -> Any:
    """
    Create a DataFence authorization API.

    Args:
        boundary           : Configured DataFenceBoundary.
        principal_resolver : Callable that maps Bearer credentials → Principal.
                             Must raise on invalid credentials.
        enable_cors        : Whether to add CORS middleware.
        allowed_origins    : Explicit list of allowed CORS origins.
                             Defaults to [] (deny all) if not specified.
        title              : API title shown in OpenAPI docs.
        version            : API version string.

    Returns:
        FastAPI application instance.

    Raises:
        ImportError: If fastapi is not installed (pip install 'datafence[api]').
    """
    if FastAPI is None:
        raise ImportError("fastapi required. Install with: pip install 'datafence[api]'")

    app = FastAPI(title=title, description=description, version=version)

    if enable_cors:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins or [],
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    bearer = HTTPBearer(auto_error=True)

    def _resolve_principal(
        credentials: HTTPAuthorizationCredentials = Depends(bearer),  # noqa: B008
    ) -> Principal:
        try:
            principal = principal_resolver(credentials)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        if not isinstance(principal, Principal):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return principal

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse, tags=["Health"])
    async def health() -> HealthResponse:
        """Liveness check."""
        return HealthResponse(status="healthy", version=version)

    @app.post(
        "/authorize",
        response_model=AuthorizeResponse,
        responses={403: {"model": DenyResponse}, 401: {}, 422: {}},
        tags=["Authorization"],
    )
    async def authorize(
        request: AuthorizationRequest,
        principal: Principal = Depends(_resolve_principal),  # noqa: B008
    ) -> AuthorizeResponse:
        """
        Authorize an intent and return a portable signed capability token.

        The ``token`` field in the response is a ``CapabilityToken`` JSON string
        that the caller must transport to their connector for verification:

            capability = CapabilityVerifier(key, expected_audience).verify_token(token)
            result = my_connector.execute(capability)
        """
        try:
            op = Operation(request.operation.lower())
            if op != Operation.READ:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Operation {request.operation!r} is not supported in v0.1. Only 'read' is supported.",
                )
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown operation: {request.operation!r}. Only 'read' is supported.",
            ) from None

        try:
            capability = boundary.authorize(
                principal,
                Intent(
                    resource=request.resource,
                    operation=op,
                    fields=request.fields,
                    filters=request.filters or {},
                    limit=request.limit,
                ),
            )
        except DataFenceError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"status": "denied", "reasons": [str(exc)]},
            ) from exc
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authorization failed",
            ) from None

        token_str = CapabilityToken.encode(capability)
        expires_iso = (
            capability.expires_at.isoformat() if capability.expires_at else None
        )
        return AuthorizeResponse(
            token=token_str,
            execution_id=capability.execution_id,
            resource=capability.resource,
            operation=capability.operation.value,
            fields=list(capability.selected_fields),
            predicates=capability.filter_constraints(),
            limit=capability.limit,
            expires_at=expires_iso,
            audience=capability.audience,
            obligations=dict(capability.obligations or {}),
        )

    @app.get(
        "/describe/{resource}",
        response_model=DescribeResponse,
        responses={401: {}, 404: {}},
        tags=["Schema"],
    )
    async def describe(
        resource: str = Path(..., description="Resource name"),  # noqa: B008
        _: Principal = Depends(_resolve_principal),  # noqa: B008
    ) -> DescribeResponse:
        """Describe the schema of a registered resource."""
        res_def = boundary.registry.get(resource)
        if res_def is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Resource {resource!r} not found",
            )
        return DescribeResponse(
            resource=res_def.name,
            fields=res_def.field_names(),
            tenant_key=res_def.tenant_key(),
            description=res_def.description,
        )

    @app.get(
        "/policy",
        response_model=PolicyInfoResponse,
        responses={401: {}},
        tags=["Policy"],
    )
    async def policy_info(
        _: Principal = Depends(_resolve_principal),  # noqa: B008
    ) -> PolicyInfoResponse:
        """
        Return high-level policy information.

        Does NOT expose full resource policy detail to prevent enumeration.
        """
        engine = boundary.policy_engine
        resource_count = len(boundary.registry.all_resources())
        return PolicyInfoResponse(
            name=getattr(engine, "policy_name", "unknown"),
            version=getattr(engine, "policy_version", "unknown"),
            resource_count=resource_count,
        )

    return app


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(
        "Configure a boundary and call create_api() from an application entrypoint"
    )
