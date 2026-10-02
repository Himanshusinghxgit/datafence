"""
Core DataFence types.

These are the first-class types that cross the DataFence security boundary.

Ownership model
---------------
DataFence owns:
    Operation  — what operation is being requested
    Actor      — who the authenticated principal is
    Intent     — the untrusted request from an AI agent / application
    Request    — Actor + Intent combined for evaluation

DataFence does NOT own:
    ConnectorResult   — owned by the customer connector
    ExecutionResult   — owned by the customer backend
    Evidence          — owned by the customer audit layer

Historical note: ExecutionPlan, ExecutionResult, Evidence, AllowedRequest,
and DeniedRequest were v0.3 objects that implied the boundary executed
database operations. They have been removed. The canonical output of
DataFenceBoundary is now AuthorizedExecution (see capability.py).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class Operation(Enum):
    """Enterprise data operations."""

    READ = "read"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"


class Decision(Enum):
    """Binary policy decision (kept for backward-compatibility in audit helpers)."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Actor:
    """
    Authenticated principal making the request.

    This represents WHO is making the request.

    The Actor is provided by the host application's authentication layer.
    DataFence trusts the Actor as given and never re-authenticates it.
    The AI/LLM must never be able to select or modify the Actor.

    Fields
    ------
    id        : Stable identifier (e.g. "user:alice", "service:reporting-agent").
    tenant_id : Tenant / organisation the principal belongs to.
                Used for mandatory row-level isolation.
    metadata  : Arbitrary key/value context (e.g. {"department": "finance"}).
                Policy rules can reference metadata for fine-grained decisions.
    """

    id: str
    tenant_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("Actor.id cannot be empty")
        if not self.tenant_id:
            raise ValueError("Actor.tenant_id cannot be empty")

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Return the value of a metadata attribute, or *default*."""
        return self.metadata.get(key, default)


@dataclass(frozen=True)
class Intent:
    """
    Untrusted request from an AI agent or application.

    Intent is what the LLM/agent PROPOSES.
    It is UNTRUSTED input — treat it as attacker-controlled.

    DataFence validates and authorizes the Intent before producing
    an AuthorizedExecution. The LLM never receives the signing key
    and cannot manufacture a valid capability.

    Fields
    ------
    resource  : The resource the agent wants to access (e.g. "transactions").
    operation : The operation the agent wants to perform.
    fields    : Optional list of fields to return. DataFence will restrict
                these to only the fields the policy allows.
    filters   : Optional dict of {field: value} filters the agent requests.
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
    Normalized pairing of a trusted Actor with an untrusted Intent.

    Created internally by DataFenceBoundary before policy evaluation.
    External callers pass Actor + Intent to boundary.authorize().
    """

    request_id: str
    timestamp: datetime
    actor: Actor
    intent: Intent

    @staticmethod
    def create(actor: Actor, intent: Intent) -> "Request":
        """Create a new request with a unique ID and current UTC timestamp."""
        return Request(
            request_id=f"req_{uuid4().hex[:16]}",
            timestamp=datetime.now(timezone.utc),
            actor=actor,
            intent=intent,
        )
