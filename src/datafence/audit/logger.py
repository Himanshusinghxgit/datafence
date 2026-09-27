"""
Audit logging functionality.
"""

import logging
import uuid
from typing import Protocol

from datafence.audit.models import AuditEvent
from datafence.core.context import RequestContext
from datafence.core.decision import Decision
from datafence.core.request import ExecutionRequest


class AuditLogger(Protocol):
    """Protocol for audit loggers."""

    def log(self, event: AuditEvent) -> None:
        """Log an audit event."""
        ...


class ConsoleAuditLogger:
    """
    Simple console audit logger.

    Writes JSON audit events to stdout.
    """

    def __init__(self, logger: logging.Logger | None = None):
        """
        Initialize console audit logger.

        Args:
            logger: Python logger to use (creates one if not provided)
        """
        self.logger = logger or logging.getLogger("datafence.audit")

    def log(self, event: AuditEvent) -> None:
        """
        Log audit event to console.

        Args:
            event: Audit event to log
        """
        # Convert to JSON
        event_json = event.model_dump_json()
        self.logger.info(f"AUDIT: {event_json}")


class MemoryAuditLogger:
    """
    In-memory audit logger for testing.

    Stores events in a list.
    """

    def __init__(self) -> None:
        """Initialize memory audit logger."""
        self.events: list[AuditEvent] = []

    def log(self, event: AuditEvent) -> None:
        """
        Log audit event to memory.

        Args:
            event: Audit event to log
        """
        self.events.append(event)

    def clear(self) -> None:
        """Clear all logged events."""
        self.events.clear()


def create_audit_event(
    request: ExecutionRequest,
    context: RequestContext,
    decision: Decision,
    row_count: int = 0,
    request_id: str | None = None,
) -> AuditEvent:
    """
    Create an audit event from request and decision.

    Args:
        request: Execution request
        context: Request context
        decision: Policy decision
        row_count: Number of rows returned
        request_id: Optional request identifier

    Returns:
        Audit event
    """
    # Handle operation value (could be enum or string)
    op_value = request.operation.value if hasattr(request.operation, "value") else request.operation

    return AuditEvent(
        event_id=str(uuid.uuid4()),
        request_id=request_id,
        session_id=context.session_id,
        actor_id=str(context.actor),
        actor_type=context.actor.type.value,
        tenant_id=context.tenant_id or request.tenant_id,
        operation=op_value,
        resource=request.resource,
        decision=decision.status,
        policy_name=decision.policy_name,
        policy_version=decision.policy_version,
        reason="; ".join(decision.reasons) if decision.reasons else None,
        row_count=row_count,
    )
