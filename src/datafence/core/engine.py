"""
DataFence execution engine.

The central enforcement boundary between AI and data.
"""

import uuid
from pathlib import Path
from typing import Any

from datafence.audit.logger import AuditLogger, ConsoleAuditLogger, create_audit_event
from datafence.connectors.base import DataConnector
from datafence.core.context import RequestContext
from datafence.core.decision import DecisionStatus
from datafence.core.request import ExecutionRequest
from datafence.core.result import ExecutionResult
from datafence.errors import PolicyDeniedError, ValidationError
from datafence.policy.evaluator import PolicyEvaluator
from datafence.policy.loader import load_policy, load_policy_dict
from datafence.policy.models import Policy
from datafence.provenance.hashing import hash_dict, hash_query
from datafence.provenance.models import Evidence, Provenance
from datafence.security.pii import PIIScanner, RedactionStrategy
from datafence.security.sql_firewall import SQLFirewall, QueryRisk


class DataFence:
    """
    DataFence execution engine.

    The deterministic security boundary between AI agents and enterprise data.

    Architecture:
        Request → Normalize → Authenticate → Policy → Execute → Validate → Result
    """

    def __init__(
        self,
        policy: Policy,
        connector: DataConnector,
        audit_logger: AuditLogger | None = None,
        fail_closed: bool = True,
        enable_sql_firewall: bool = True,
        enable_pii_detection: bool = False,
        pii_redaction_strategy: RedactionStrategy = RedactionStrategy.MASK,
    ):
        """
        Initialize DataFence engine.

        Args:
            policy: Security policy to enforce
            connector: Data connector for execution
            audit_logger: Audit logger (creates console logger if not provided)
            fail_closed: If True, deny on security failures (recommended)
            enable_sql_firewall: Enable SQL query validation and dangerous operation blocking
            enable_pii_detection: Enable PII detection and redaction in results
            pii_redaction_strategy: Strategy for PII redaction
        """
        self.policy = policy
        self.connector = connector
        self.audit_logger = audit_logger or ConsoleAuditLogger()
        self.fail_closed = fail_closed
        self.evaluator = PolicyEvaluator(policy)

        # Security features
        self.enable_sql_firewall = enable_sql_firewall
        self.enable_pii_detection = enable_pii_detection

        if enable_sql_firewall:
            self.sql_firewall = SQLFirewall(
                allow_write=False,  # Default to read-only
                allow_ddl=False,
                allow_subqueries=True,
                allow_unions=True,
                block_comments=True,
            )
        else:
            self.sql_firewall = None

        if enable_pii_detection:
            self.pii_scanner = PIIScanner(default_strategy=pii_redaction_strategy)
        else:
            self.pii_scanner = None

    @classmethod
    def from_yaml(
        cls,
        policy_path: str | Path,
        connector: DataConnector,
        audit_logger: AuditLogger | None = None,
        fail_closed: bool = True,
        enable_sql_firewall: bool = True,
        enable_pii_detection: bool = False,
        pii_redaction_strategy: RedactionStrategy = RedactionStrategy.MASK,
    ) -> "DataFence":
        """
        Create DataFence from YAML policy file.

        Args:
            policy_path: Path to policy YAML file
            connector: Data connector
            audit_logger: Audit logger
            fail_closed: Fail-closed mode
            enable_sql_firewall: Enable SQL query firewall
            enable_pii_detection: Enable PII detection and redaction
            pii_redaction_strategy: PII redaction strategy

        Returns:
            DataFence instance
        """
        policy = load_policy(policy_path)
        return cls(
            policy,
            connector,
            audit_logger,
            fail_closed,
            enable_sql_firewall,
            enable_pii_detection,
            pii_redaction_strategy,
        )

    @classmethod
    def from_dict(
        cls,
        policy_dict: dict[str, Any],
        connector: DataConnector,
        audit_logger: AuditLogger | None = None,
        fail_closed: bool = True,
        enable_sql_firewall: bool = True,
        enable_pii_detection: bool = False,
        pii_redaction_strategy: RedactionStrategy = RedactionStrategy.MASK,
    ) -> "DataFence":
        """
        Create DataFence from policy dictionary.

        Args:
            policy_dict: Policy dictionary
            connector: Data connector
            audit_logger: Audit logger
            fail_closed: Fail-closed mode
            enable_sql_firewall: Enable SQL query firewall
            enable_pii_detection: Enable PII detection and redaction
            pii_redaction_strategy: PII redaction strategy

        Returns:
            DataFence instance
        """
        policy = load_policy_dict(policy_dict)
        return cls(
            policy,
            connector,
            audit_logger,
            fail_closed,
            enable_sql_firewall,
            enable_pii_detection,
            pii_redaction_strategy,
        )

    def execute(
        self, request: dict[str, Any] | ExecutionRequest, raise_on_deny: bool = False
    ) -> ExecutionResult:
        """
        Execute a request through the security boundary.

        This is the main entry point for all data access.

        Args:
            request: Execution request (dict or ExecutionRequest)
            raise_on_deny: If True, raise PolicyDeniedError on denial

        Returns:
            ExecutionResult with data, decision, provenance, and evidence

        Raises:
            PolicyDeniedError: If raise_on_deny=True and request is denied
        """
        # Generate request ID
        request_id = str(uuid.uuid4())

        # 1. Normalize request
        if isinstance(request, dict):
            exec_request = ExecutionRequest(**request)
        else:
            exec_request = request

        # 2. Create context
        context = RequestContext(
            actor=exec_request.actor,
            tenant_id=exec_request.tenant_id,
            metadata={},
        )

        # 3. SQL Firewall validation (if enabled and raw_query present)
        if self.sql_firewall and exec_request.raw_query:
            try:
                self.sql_firewall.check_or_block(exec_request.raw_query)
            except ValidationError as e:
                # SQL firewall blocked the query - create denial decision
                from datafence.core.decision import Decision

                decision = Decision(
                    status=DecisionStatus.DENY,
                    reasons=[f"SQL firewall: {str(e)}"],
                    policy_name=self.policy.name,
                    policy_version=self.policy.version,
                )

                result = ExecutionResult(
                    data=None,
                    row_count=0,
                    decision=decision,
                    verified=False,
                    provenance=None,
                    evidence=None,
                    request_id=request_id,
                    metadata={"sql_firewall_blocked": True},
                )

                audit_event = create_audit_event(
                    exec_request, context, decision, row_count=0, request_id=request_id
                )
                self.audit_logger.log(audit_event)

                if raise_on_deny:
                    raise PolicyDeniedError(
                        f"SQL firewall blocked query: {str(e)}", reasons=[str(e)]
                    ) from e

                return result

        # 4. Evaluate policy
        decision = self.evaluator.evaluate(exec_request, context)

        # 5. Check decision
        if decision.status != DecisionStatus.ALLOW:
            # Create denied result
            result = ExecutionResult(
                data=None,
                row_count=0,
                decision=decision,
                verified=False,
                provenance=None,
                evidence=None,
                request_id=request_id,
            )

            # Log audit event
            audit_event = create_audit_event(
                exec_request, context, decision, row_count=0, request_id=request_id
            )
            self.audit_logger.log(audit_event)

            # Raise if requested
            if raise_on_deny:
                raise PolicyDeniedError(
                    f"Request denied: {decision.reasons[0] if decision.reasons else 'policy violation'}",
                    reasons=decision.reasons,
                )

            return result

        # 5. Execute through connector
        try:
            allowed_fields = self.evaluator.get_allowed_fields(exec_request.resource)
            data = self.connector.execute(exec_request, allowed_fields)

            # Handle different return types
            if isinstance(data, list):
                row_count = len(data)
            else:
                row_count = 1

            # 6. PII detection and redaction (if enabled)
            if self.pii_scanner and data:
                if isinstance(data, list):
                    data = [
                        self.pii_scanner.redact_dict(record) if isinstance(record, dict) else record
                        for record in data
                    ]
                elif isinstance(data, dict):
                    data = self.pii_scanner.redact_dict(data)

        except Exception as e:
            # Execution failed - fail closed if configured
            if self.fail_closed:
                result = ExecutionResult(
                    data=None,
                    row_count=0,
                    decision=decision,
                    verified=False,
                    provenance=None,
                    evidence=None,
                    request_id=request_id,
                    metadata={"error": str(e)},
                )

                # Log audit event
                audit_event = create_audit_event(
                    exec_request, context, decision, row_count=0, request_id=request_id
                )
                self.audit_logger.log(audit_event)

                if raise_on_deny:
                    raise PolicyDeniedError(f"Execution failed: {e}", reasons=[str(e)]) from e

                return result
            else:
                raise

        # 6. Generate provenance
        provenance = Provenance(
            source=self.connector.__class__.__name__,
            resource=exec_request.resource,
            policy_name=self.policy.name,
            policy_version=self.policy.version,
            query_hash=self._get_query_hash(exec_request),
            actor=str(context.actor),
            tenant_id=context.tenant_id,
        )

        # 7. Generate evidence
        evidence = Evidence(
            verified=True,
            request_id=request_id,
            policy_name=self.policy.name,
            policy_version=self.policy.version,
            request_hash=hash_dict(exec_request.model_dump()),
            query_hash=self._get_query_hash(exec_request),
            result_hash=None,  # Could hash result metadata
            checks=[check.name for check in decision.checks if check.passed],
        )

        # 8. Create result
        result = ExecutionResult(
            data=data,
            row_count=row_count,
            decision=decision,
            verified=True,
            provenance=provenance,
            evidence=evidence,
            request_id=request_id,
        )

        # 9. Log audit event
        audit_event = create_audit_event(
            exec_request, context, decision, row_count=row_count, request_id=request_id
        )
        self.audit_logger.log(audit_event)

        return result

    def check(self, request: dict[str, Any] | ExecutionRequest) -> ExecutionResult:
        """
        Dry-run: check if a request would be allowed without executing.

        Args:
            request: Execution request (dict or ExecutionRequest)

        Returns:
            ExecutionResult with decision but no data
        """
        # Normalize request
        if isinstance(request, dict):
            exec_request = ExecutionRequest(**request)
        else:
            exec_request = request

        # Create context
        context = RequestContext(
            actor=exec_request.actor,
            tenant_id=exec_request.tenant_id,
            metadata={},
        )

        # Evaluate policy
        decision = self.evaluator.evaluate(exec_request, context)

        # Return result without execution
        return ExecutionResult(
            data=None,
            row_count=0,
            decision=decision,
            verified=decision.status == DecisionStatus.ALLOW,
            provenance=None,
            evidence=None,
            request_id=str(uuid.uuid4()),
            metadata={"dry_run": True},
        )

    def _get_query_hash(self, request: ExecutionRequest) -> str | None:
        """Generate hash of query or request."""
        if request.raw_query:
            return hash_query(request.raw_query)
        return hash_dict(request.model_dump())
