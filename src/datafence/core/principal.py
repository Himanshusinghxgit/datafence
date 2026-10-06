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

import math
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

# ---------------------------------------------------------------------------
# Attribute validation and deep-freeze helpers
# ---------------------------------------------------------------------------

def _validate_json_compatible_attrs(attrs: dict, path: str = "attributes") -> None:
    """
    Validate that ``attrs`` contains only JSON-compatible types.

    Called at Principal construction so that signing never encounters a
    surprise ``TypeError`` from ``json.dumps``.

    Allowed leaf types: str, int, float (finite), bool, None.
    Rejected: non-finite float, bytes, object(), datetime, set, …
    """
    for k, v in attrs.items():
        if not isinstance(k, str):
            raise ValueError(
                f"Principal.{path} key must be str, got {type(k).__name__!r}"
            )
        _validate_json_value(v, f"{path}.{k}")


def _validate_json_value(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(
                f"Principal.{path}: non-finite float {value!r} is not JSON-serialisable"
            )
        return
    if isinstance(value, (str, int)):
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(
                    f"Principal.{path} key must be str, got {type(k).__name__!r}"
                )
            _validate_json_value(v, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _validate_json_value(item, f"{path}[{i}]")
        return
    raise ValueError(
        f"Principal.{path}: value of type {type(value).__name__!r} "
        "is not JSON-serialisable"
    )


def _deep_freeze_attrs(value: Any) -> Any:
    """Recursively make attribute values immutable."""
    if isinstance(value, MappingProxyType):
        return MappingProxyType({k: _deep_freeze_attrs(v) for k, v in value.items()})
    if isinstance(value, dict):
        return MappingProxyType({k: _deep_freeze_attrs(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze_attrs(item) for item in value)
    if isinstance(value, set):
        return frozenset(value)
    return value


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
        # Coerce attributes to an immutable mapping proxy with deep-frozen values.
        # Validate JSON-compatibility now so signing never raises a surprise TypeError.
        raw_attrs = self.attributes
        if isinstance(raw_attrs, MappingProxyType):
            # Re-validate even if already proxied
            _validate_json_compatible_attrs(dict(raw_attrs))
            frozen_attrs = _deep_freeze_attrs(raw_attrs)
        else:
            if not isinstance(raw_attrs, dict):
                raise ValueError("Principal.attributes must be a dict")
            _validate_json_compatible_attrs(raw_attrs)
            frozen_attrs = _deep_freeze_attrs(raw_attrs)
        object.__setattr__(self, "attributes", frozen_attrs)

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
