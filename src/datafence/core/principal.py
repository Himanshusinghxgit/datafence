"""
DataFence Principal model (Phase 1).

A Principal is an authenticated identity provided by the host application.
DataFence does NOT authenticate principals — that is the application's job.

The host application authenticates the user/agent via its own IAM layer and
then constructs an AuthenticatedPrincipal to pass to DataFence.

    [App IAM]  →  authenticate()  →  AuthenticatedPrincipal
                                           ↓
                                      DataFence
                                           ↓
                                      authorization

This is distinct from the legacy Actor concept (which had no authentication
framing).  AuthenticatedPrincipal makes the trust boundary explicit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Principal:
    """
    An authenticated principal (user, service account, AI agent).

    Fields
    ------
    id : str
        Stable identifier (e.g. "user:alice", "service:reporting-agent").
    tenant_id : str
        Tenant / organisation the principal belongs to.
        Used for mandatory row-level isolation.
    roles : tuple[str, ...]
        Roles granted to this principal (e.g. ("finance:read", "audit:read")).
        Policy rules can match on roles.
    attributes : dict[str, Any]
        Arbitrary key/value context (e.g. {"department": "finance", "region": "us-east"}).
        Policy rules can reference attributes for fine-grained decisions.

    Notes
    -----
    - Frozen (immutable) — cannot be altered after construction.
    - The application MUST validate/authenticate before constructing this.
    - DataFence trusts the principal as provided; it never re-authenticates.
    """

    id: str
    tenant_id: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Principal.id cannot be empty")
        if not self.tenant_id:
            raise ValueError("Principal.tenant_id cannot be empty")

    # ------------------------------------------------------------------
    # Convenience helpers used by policy evaluation
    # ------------------------------------------------------------------

    def has_role(self, role: str) -> bool:
        """Return True if this principal holds *role*."""
        return role in self.roles

    def has_any_role(self, *roles: str) -> bool:
        """Return True if this principal holds any of *roles*."""
        return any(r in self.roles for r in roles)

    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Return the value of attribute *key*, or *default*."""
        return self.attributes.get(key, default)

    # ------------------------------------------------------------------
    # Backward compat — Actor alias
    # ------------------------------------------------------------------

    @classmethod
    def from_actor(cls, actor: Any) -> "Principal":
        """
        Construct a Principal from a legacy Actor dataclass.

        Allows the v0.4 Actor (id, tenant_id, metadata) to be used
        anywhere a Principal is expected without changing call-sites.
        """
        return cls(
            id=actor.id,
            tenant_id=actor.tenant_id,
            attributes=getattr(actor, "metadata", {}),
        )


# Backward-compat alias so existing code that creates Actor(...) still works
# when imported from this module.
Actor = Principal  # type alias — Actor is just a Principal with no roles
