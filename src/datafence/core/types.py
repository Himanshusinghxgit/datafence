"""
Core DataFence types.

These are the first-class types that cross the DataFence security boundary.

Ownership model
---------------
DataFence owns:
    Operation   — what operation is being requested
    Intent      — the untrusted request from an AI agent / application
    Request     — internal pairing of Principal + Intent for evaluation

DataFence does NOT own:
    ConnectorResult  — owned by the customer connector
    Database rows    — owned by the customer backend

Historical note: ExecutionPlan, ExecutionResult, Evidence, AllowedRequest,
and DeniedRequest were v0.3 objects that implied the boundary executed
database operations. They have been removed. The canonical output of
DataFenceBoundary is AuthorizedExecution (see capability.py).

Principal / Actor
-----------------
The Principal type lives in datafence.core.principal.
"Actor" is a backward-compatibility alias for Principal defined there.
This module re-exports both names for convenience.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

# Re-export so callers can import from either module.
from datafence.core.principal import Actor, Principal  # noqa: F401


class Operation(Enum):
    """Enterprise data operations."""

    READ = "read"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"


class Decision(Enum):
    """Binary policy decision (kept for audit helper backward-compatibility)."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Intent:
    """
    Untrusted request from an AI agent or application.

    Intent is WHAT the LLM/agent proposes.
    It is untrusted input — treat it as potentially attacker-controlled.

    DataFence validates and authorizes the Intent before producing an
    AuthorizedExecution. The LLM never receives the signing key and
    cannot manufacture a valid capability.

    Fields
    ------
    resource  : The resource the agent wants to access (e.g. ``"transactions"``).
    operation : The operation the agent wants to perform.
    fields    : Optional list of fields to return. DataFence restricts
                these to only the fields the policy allows.
    filters   : Optional dict of ``{field: value}`` filters the agent requests.
                Policy-enforced filters override or supplement these.
    limit     : Optional maximum number of rows. Capped by policy.
    """

    resource: str
    operation: Operation
    fields: list[str] | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    limit: int | None = None


@dataclass(frozen=True)
class Request:
    """
    Normalized pairing of a trusted Principal with an untrusted Intent.

    Created internally by DataFenceBoundary before policy evaluation.
    External callers pass Principal + Intent to boundary.authorize().
    """

    request_id: str
    timestamp: datetime
    actor: Principal  # named "actor" for internal consistency; type is Principal
    intent: Intent

    @staticmethod
    def create(principal: Principal, intent: Intent) -> Request:
        """Create a new Request with a unique ID and current UTC timestamp."""
        return Request(
            request_id=f"req_{uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc),
            actor=principal,
            intent=intent,
        )
