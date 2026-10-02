"""
DataFence Principal model.

A Principal is an authenticated identity supplied by the host application.
DataFence does NOT authenticate principals — that is the application's responsibility.

Trust boundary:

    [App Authentication]
            ↓
      Principal (trusted)
            ↓
      DataFenceBoundary.authorize()

The LLM/agent supplies Intent (untrusted).
The application supplies Principal (trusted).
These two inputs must never be confused.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Principal:
    """
    An authenticated principal (user, service account, or AI agent identity).

    The application MUST authenticate the user before constructing this object.
    DataFence trusts the Principal as given and never re-authenticates it.

    The AI/LLM must NOT be able to choose or modify:
      - ``id``
      - ``tenant_id``
      - ``roles``
      - ``attributes``

    Fields
    ------
    id : str
        Stable identifier (e.g. ``"user:alice"``, ``"service:report-agent"``).
    tenant_id : str
        Tenant the principal belongs to. Used for mandatory row-level isolation.
    roles : tuple[str, ...]
        Roles granted by the application (e.g. ``("finance:read", "audit:read")``).
        Policy rules can match on roles.
    attributes : dict[str, Any]
        Arbitrary key/value context (e.g. ``{"department": "finance"}``).
        Policy rules can reference attributes for fine-grained decisions.
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
    # Convenience helpers
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
    # Legacy compatibility
    # ------------------------------------------------------------------

    @property
    def metadata(self) -> dict[str, Any]:
        """Alias for attributes — backward compatibility with Actor.metadata."""
        return self.attributes


# ---------------------------------------------------------------------------
# Backward-compatibility alias
# ---------------------------------------------------------------------------
# The v0.3/v0.4 codebase used the name "Actor".  Both names now refer to the
# same class.  New code should use Principal.
Actor = Principal
