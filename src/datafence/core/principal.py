"""
DataFence Principal model.

A Principal is an authenticated identity supplied by the host application.
DataFence does NOT authenticate principals — that is the application's
responsibility.

Trust boundary::

    [App Authentication]
            ↓
      Principal (trusted)
            ↓
      DataFenceBoundary.authorize()

The LLM/agent supplies Intent (untrusted).
The application supplies Principal (trusted).
These two inputs must never be confused.

Deep immutability
-----------------
``Principal`` is a frozen dataclass.  ``roles`` is stored as a
``tuple[str, ...]`` and ``attributes`` is stored via a read-only proxy
(``types.MappingProxyType``).  Neither can be mutated after construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
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
        Policy rules can match on roles.  Roles are included in the HMAC
        canonical representation so that tampering is detected.
    attributes : MappingProxyType
        Arbitrary key/value context (e.g. ``{"department": "finance"}``).
        Policy rules can reference attributes for fine-grained decisions.
        Stored as an immutable mapping proxy.
    """

    id: str
    tenant_id: str
    roles: tuple[str, ...] = field(default_factory=tuple)
    attributes: Any = field(default_factory=dict)  # coerced to MappingProxyType in __post_init__

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Principal.id cannot be empty")
        if not self.tenant_id:
            raise ValueError("Principal.tenant_id cannot be empty")
        # Coerce roles to tuple for deep immutability
        if not isinstance(self.roles, tuple):
            object.__setattr__(self, "roles", tuple(self.roles))
        # Coerce attributes to an immutable mapping proxy
        if not isinstance(self.attributes, MappingProxyType):
            object.__setattr__(
                self, "attributes", MappingProxyType(dict(self.attributes))
            )

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
    # Backward-compatibility property
    # ------------------------------------------------------------------

    @property
    def metadata(self) -> Any:
        """Alias for ``attributes`` — backward compatibility with older code."""
        return self.attributes
