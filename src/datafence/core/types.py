"""
Core DataFence Types.

These are first-class types representing the security boundary.
Not dictionaries.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4


class Operation(Enum):
    """Database operations."""

    READ = "read"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"


class Decision(Enum):
    """Policy decision."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Actor:
    """
    Actor making the request.
    
    This represents WHO is making the request.
    The actor identity CANNOT be changed by the LLM.
    """

    id: str
    tenant_id: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.id:
            raise ValueError("Actor ID cannot be empty")
        if not self.tenant_id:
            raise ValueError("Actor tenant_id cannot be empty")


@dataclass(frozen=True)
class Intent:
    """
    Untrusted request from AI agent.
    
    This is what the LLM PROPOSES.
    It is UNTRUSTED input.
    """

    resource: str
    operation: Operation
    fields: Optional[list[str]] = None
    filters: dict[str, Any] = field(default_factory=dict)
    limit: Optional[int] = None
    raw_sql: Optional[str] = None  # If LLM generated SQL, store but DON'T execute


@dataclass(frozen=True)
class Request:
    """
    Normalized request for policy evaluation.
    
    This combines the untrusted Intent with the trusted Actor.
    """

    request_id: str
    timestamp: datetime
    actor: Actor
    intent: Intent

    @staticmethod
    def create(actor: Actor, intent: Intent) -> "Request":
        """Create a new request with unique ID and timestamp."""
        return Request(
            request_id=f"req_{uuid4().hex[:16]}",
            timestamp=datetime.utcnow(),
            actor=actor,
            intent=intent,
        )


@dataclass(frozen=True)
class PolicyDecision:
    """
    Policy evaluation result.
    
    This represents WHAT the policy says about the request.
    """

    decision: Decision
    reasons: list[str] = field(default_factory=list)
    policy_version: str = "default"
    matched_policies: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionPlan:
    """
    Authorized execution plan — DESCRIPTIVE / AUDIT OBJECT ONLY.

    THIS IS NOT THE EXECUTION CAPABILITY.
    
    ExecutionPlan documents WHAT DataFence decided (for audit / evidence trails).
    The EXECUTABLE artifact is AuthorizedExecution (see capability.py).

    ExecutionPlan is created INTERNALLY by DataFenceBoundary after a successful
    AuthorizedExecution.  External code MUST NOT construct ExecutionPlan directly
    and pass it to a connector — connectors reject it.  Use DataFenceBoundary.execute().

    Role in the pipeline:
        Intent (untrusted)
            ↓  policy evaluation
        AuthorizedExecution (signed, executable)  ← what the connector receives
            ↓  connector executes
        ExecutionResult
            ↓  boundary wraps for caller
        AllowedRequest.execution_plan  ← this field holds an ExecutionPlan (audit copy)

    So every AllowedRequest carries an ExecutionPlan for evidence/logging, but
    the connector never sees it.
    """

    execution_id: str
    actor: Actor
    resource: str
    operation: Operation
    
    # What fields are authorized
    selected_fields: list[str]
    
    # What filters are enforced by policy
    enforced_filters: dict[str, Any]
    
    # Limits
    limit: int
    
    # Policy provenance
    policy_version: str
    policy_decisions: list[str] = field(default_factory=list)
    
    # Timestamp
    created_at: datetime = field(default_factory=datetime.utcnow)

    @staticmethod
    def create(
        actor: Actor,
        resource: str,
        operation: Operation,
        selected_fields: list[str],
        enforced_filters: dict[str, Any],
        limit: int,
        policy_version: str,
        policy_decisions: list[str],
    ) -> "ExecutionPlan":
        """Create an authorized execution plan."""
        return ExecutionPlan(
            execution_id=f"exec_{uuid4().hex[:16]}",
            actor=actor,
            resource=resource,
            operation=operation,
            selected_fields=selected_fields,
            enforced_filters=enforced_filters,
            limit=limit,
            policy_version=policy_version,
            policy_decisions=policy_decisions,
        )

    def __post_init__(self):
        """Validate execution plan."""
        if not self.resource:
            raise ValueError("ExecutionPlan must have a resource")
        if not self.selected_fields:
            raise ValueError("ExecutionPlan must have selected_fields")
        if self.limit <= 0:
            raise ValueError("ExecutionPlan limit must be positive")


@dataclass(frozen=True)
class ExecutionResult:
    """
    Result of executing an ExecutionPlan.
    
    This includes:
    - The data returned
    - Verification that it matches the plan
    - Evidence of policy compliance
    """

    execution_id: str
    plan: ExecutionPlan
    data: list[dict[str, Any]]
    row_count: int
    verified: bool
    verification_errors: list[str] = field(default_factory=list)
    executed_at: datetime = field(default_factory=datetime.utcnow)

    @staticmethod
    def create_verified(
        plan: ExecutionPlan,
        data: list[dict[str, Any]],
    ) -> "ExecutionResult":
        """Create a verified execution result."""
        return ExecutionResult(
            execution_id=plan.execution_id,
            plan=plan,
            data=data,
            row_count=len(data),
            verified=True,
            verification_errors=[],
        )

    @staticmethod
    def create_failed(
        plan: ExecutionPlan,
        errors: list[str],
    ) -> "ExecutionResult":
        """Create a failed execution result."""
        return ExecutionResult(
            execution_id=plan.execution_id,
            plan=plan,
            data=[],
            row_count=0,
            verified=False,
            verification_errors=errors,
        )


@dataclass(frozen=True)
class Evidence:
    """
    Evidence of policy compliance.
    
    This proves that the request was authorized and executed correctly.
    """

    execution_id: str
    request_id: str
    actor_id: str
    tenant_id: str
    resource: str
    operation: str
    policy_version: str
    decision: Decision
    timestamp: datetime
    
    # For allowed requests
    execution_plan: Optional[ExecutionPlan] = None
    row_count: Optional[int] = None
    
    # For denied requests
    denial_reasons: list[str] = field(default_factory=list)

    @staticmethod
    def create_allowed(
        request: Request,
        plan: ExecutionPlan,
        result: ExecutionResult,
    ) -> "Evidence":
        """Create evidence for an allowed request."""
        return Evidence(
            execution_id=plan.execution_id,
            request_id=request.request_id,
            actor_id=request.actor.id,
            tenant_id=request.actor.tenant_id,
            resource=plan.resource,
            operation=plan.operation.value,
            policy_version=plan.policy_version,
            decision=Decision.ALLOW,
            timestamp=datetime.utcnow(),
            execution_plan=plan,
            row_count=result.row_count,
        )

    @staticmethod
    def create_denied(
        request: Request,
        policy_decision: PolicyDecision,
    ) -> "Evidence":
        """Create evidence for a denied request."""
        return Evidence(
            execution_id=f"denied_{uuid4().hex[:16]}",
            request_id=request.request_id,
            actor_id=request.actor.id,
            tenant_id=request.actor.tenant_id,
            resource=request.intent.resource,
            operation=request.intent.operation.value,
            policy_version=policy_decision.policy_version,
            decision=Decision.DENY,
            timestamp=datetime.utcnow(),
            denial_reasons=policy_decision.reasons,
        )


@dataclass(frozen=True)
class AuditEvent:
    """
    Auditable event.
    
    Every request (allowed or denied) produces an audit event.
    """

    event_id: str
    timestamp: datetime
    actor_id: str
    tenant_id: str
    resource: str
    operation: str
    decision: Decision
    
    # For allowed requests
    execution_id: Optional[str] = None
    row_count: Optional[int] = None
    
    # For denied requests
    denial_reasons: list[str] = field(default_factory=list)
    
    # Policy information
    policy_version: str = "default"

    @staticmethod
    def from_evidence(evidence: Evidence) -> "AuditEvent":
        """Create audit event from evidence."""
        return AuditEvent(
            event_id=f"audit_{uuid4().hex[:16]}",
            timestamp=evidence.timestamp,
            actor_id=evidence.actor_id,
            tenant_id=evidence.tenant_id,
            resource=evidence.resource,
            operation=evidence.operation,
            decision=evidence.decision,
            execution_id=evidence.execution_id if evidence.decision == Decision.ALLOW else None,
            row_count=evidence.row_count,
            denial_reasons=evidence.denial_reasons,
            policy_version=evidence.policy_version,
        )


@dataclass(frozen=True)
class DeniedRequest:
    """
    A denied request.
    
    This is returned when policy denies the request.
    The connector NEVER receives the request.
    """

    request_id: str
    actor: Actor
    resource: str
    operation: Operation
    decision: PolicyDecision
    evidence: Evidence
    audit_event: AuditEvent


@dataclass(frozen=True)
class AllowedRequest:
    """
    An allowed request.
    
    This contains the ExecutionPlan and the result after execution.
    """

    request_id: str
    actor: Actor
    execution_plan: ExecutionPlan
    execution_result: ExecutionResult
    evidence: Evidence
    audit_event: AuditEvent
