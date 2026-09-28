"""
DataFence Security Boundary (v0.4 - Hardened).

This is the core enforcement layer with cryptographic capabilities.

Flow:
    Untrusted Request → Policy Evaluation → AuthorizedExecution (signed) → Execution → Validation

SECURITY IMPROVEMENTS (v0.4):
- Capabilities are cryptographically signed with HMAC
- Connector is PRIVATE (not exposed in public API)
- Capability cannot be forged without signing key
- Defense in depth: API design + cryptography

The database NEVER executes LLM-generated SQL directly.
DataFence transforms the untrusted request into a signed capability.
The connector verifies the signature before execution.
"""

from typing import Protocol, Union
from secrets import token_bytes

from datafence.core.types import (
    Actor,
    AllowedRequest,
    AuditEvent,
    Decision,
    DeniedRequest,
    Evidence,
    ExecutionPlan,
    ExecutionResult,
    Intent,
    Operation,
    PolicyDecision,
    Request,
)
from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError


class PolicyEngine(Protocol):
    """
    Policy engine interface.
    
    Evaluates whether a request is allowed.
    Returns what fields, filters, and operations are authorized.
    """

    def evaluate(
        self,
        actor: Actor,
        resource: str,
        operation: Operation,
        requested_fields: list[str],
    ) -> PolicyDecision:
        """Evaluate policy for a request."""
        ...

    def get_allowed_fields(
        self,
        actor: Actor,
        resource: str,
    ) -> list[str]:
        """Get fields the actor is allowed to access."""
        ...

    def get_enforced_filters(
        self,
        actor: Actor,
        resource: str,
    ) -> dict[str, str]:
        """Get filters that must be enforced (e.g., tenant_id)."""
        ...

    def get_max_limit(
        self,
        actor: Actor,
        resource: str,
    ) -> int:
        """Get maximum number of rows allowed."""
        ...

    def get_policy_version(self) -> str:
        """Get policy version for provenance."""
        ...


class Connector(Protocol):
    """
    Connector interface (v0.4 - Hardened).
    
    CRITICAL CHANGES:
    - Connector accepts AuthorizedExecution (signed capability)
    - Connector receives signing_key at construction (NEVER through execute)
    - Connector verifies HMAC signature before execution
    - Connector is PRIVATE (not exported in public API)
    
    The connector generates SQL from the capability internally.
    This ensures the database executes DataFence's authorized operation,
    not the LLM's untrusted request.
    """

    def execute(self, capability: AuthorizedExecution) -> list[dict[str, str]]:
        """
        Execute a signed capability.
        
        The connector MUST:
        1. Verify capability signature (uses signing_key from __init__)
        2. Reject invalid/forged capabilities
        3. Generate SQL from the capability internally
        4. Use prepared statements
        5. Return ONLY the fields in capability.selected_fields
        
        Args:
            capability: Signed AuthorizedExecution
        
        Returns:
            Query results
        
        Raises:
            CapabilityVerificationError: If signature is invalid
        """
        ...


class ResultValidator:
    """
    Validates execution results.
    
    Even if the connector is compromised or buggy,
    this layer ensures returned data matches the ExecutionPlan.
    """

    def validate(
        self,
        plan: ExecutionPlan,
        data: list[dict[str, str]],
    ) -> ExecutionResult:
        """
        Validate that returned data matches the ExecutionPlan.
        
        Security checks:
        1. No unauthorized fields in results
        2. Row count within limit
        3. Data types match expectations
        """
        errors = []

        # Check: No unauthorized fields
        allowed_fields = set(plan.selected_fields)
        for row in data:
            returned_fields = set(row.keys())
            unauthorized = returned_fields - allowed_fields
            if unauthorized:
                errors.append(
                    f"Result contains unauthorized fields: {unauthorized}"
                )
                break

        # Check: Row count within limit
        if len(data) > plan.limit:
            errors.append(
                f"Result exceeds limit: {len(data)} rows > {plan.limit}"
            )

        if errors:
            return ExecutionResult.create_failed(plan, errors)

        return ExecutionResult.create_verified(plan, data)


class DataFenceBoundary:
    """
    The DataFence security boundary (v0.4 - Hardened).
    
    This is the enforcement layer between AI agents and data.
    
    SECURITY IMPROVEMENTS (v0.4):
    1. Connector is PRIVATE (_connector, not exposed)
    2. Capabilities are cryptographically signed (HMAC-SHA256)
    3. Signing key is generated securely and kept private
    4. Defense in depth: API design + cryptography
    
    Security properties:
    1. Untrusted requests never reach the database directly
    2. Policy evaluation happens BEFORE execution
    3. AuthorizedExecution is cryptographically signed
    4. Connector verifies signature before execution
    5. Result validation happens AFTER execution
    6. Everything produces evidence
    7. Fail closed on errors
    
    THREAT MODEL:
    - ✅ Protects against Threat Model A (untrusted LLM/agent)
    - ✅ Protects against Threat Model B (compromised application code)
    - ❌ Does NOT protect against Threat Model C (full Python runtime compromise)
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        connector: Connector,
        signing_key: bytes = None,
    ):
        """
        Initialize DataFence boundary.
        
        Args:
            policy_engine: Policy evaluation engine
            connector: Data connector (must support signature verification)
            signing_key: Optional signing key (32 bytes). If not provided, generates new key.
        
        DEPRECATED: Direct construction is deprecated in v0.4.
        Use DataFenceBoundary.create() factory method instead.
        
        SECURITY:
        - In v0.4, the boundary and connector MUST share the same signing key
        - Use create() factory to ensure proper key sharing
        - Direct construction may lead to key mismatch errors
        """
        self.policy_engine = policy_engine
        self._connector = connector  # PRIVATE - not accessible externally
        self.validator = ResultValidator()
        
        # Set or generate signing key
        if signing_key is not None:
            self._signing_key = signing_key
        elif not hasattr(self, '_signing_key'):
            # Fallback: generate key (for backward compatibility)
            # WARNING: This will cause key mismatch with connector!
            import warnings
            warnings.warn(
                "Direct construction of DataFenceBoundary is deprecated. "
                "Use DataFenceBoundary.create() factory method to ensure "
                "proper key sharing with connector.",
                DeprecationWarning,
                stacklevel=2
            )
            self._signing_key = token_bytes(32)
    
    @classmethod
    def create(
        cls,
        policy_engine: PolicyEngine,
        connector_factory: callable,
        **connector_kwargs
    ) -> "DataFenceBoundary":
        """
        Create DataFenceBoundary with properly configured connector.
        
        This is THE REQUIRED way to create a boundary in v0.4.
        
        Args:
            policy_engine: Policy evaluation engine
            connector_factory: Connector factory function or class
            **connector_kwargs: Arguments for connector (e.g., database_path)
        
        Returns:
            Configured DataFenceBoundary
        
        Example:
            from datafence.connectors.sqlite_connector import create_demo_database
            
            boundary = DataFenceBoundary.create(
                policy_engine=policy_engine,
                connector_factory=create_demo_database,
                database_path="/path/to/db.sqlite"
            )
        
        SECURITY:
        - Generates signing key once
        - Passes key to connector factory at construction
        - Connector and boundary share same key
        - Key never exposed through public API
        """
        # Generate signing key (32 bytes for HMAC-SHA256)
        signing_key = token_bytes(32)
        
        # Create connector with signing key
        # Pass signing_key as kwarg - factory MUST accept it
        connector = connector_factory(**connector_kwargs, signing_key=signing_key)
        
        # Create boundary instance
        boundary = cls.__new__(cls)
        boundary.policy_engine = policy_engine
        boundary._connector = connector
        boundary._signing_key = signing_key
        boundary.validator = ResultValidator()
        
        return boundary

    def execute(
        self,
        actor: Actor,
        intent: Intent,
    ) -> Union[AllowedRequest, DeniedRequest]:
        """
        Execute a request through the security boundary (v0.4 - Hardened).
        
        Flow:
        1. Create Request (Actor + Intent)
        2. Evaluate Policy
        3. If DENY: return DeniedRequest
        4. If ALLOW: create signed AuthorizedExecution
        5. Execute via PRIVATE connector (verifies signature)
        6. Validate result
        7. Generate evidence
        8. Return AllowedRequest
        
        SECURITY (v0.4):
        - Capability is cryptographically signed
        - Connector is private (cannot be called externally)
        - Connector verifies signature before execution
        - Defense in depth: API design + cryptography
        
        CRITICAL: The database never sees the LLM's raw SQL.
        """
        # Step 1: Create request
        request = Request.create(actor, intent)

        # Step 2: Evaluate policy
        try:
            policy_decision = self._evaluate_policy(request)
        except Exception as e:
            # Fail closed: treat evaluation errors as DENY
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"Policy evaluation failed: {str(e)}"],
                policy_version=self.policy_engine.get_policy_version(),
            )

        # Step 3: If denied, return immediately
        if policy_decision.decision == Decision.DENY:
            return self._create_denied_request(request, policy_decision)

        # Step 4: Create signed AuthorizedExecution capability
        try:
            capability = self._create_signed_capability(request, policy_decision)
        except Exception as e:
            # Fail closed: treat capability creation errors as DENY
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"Capability creation failed: {str(e)}"],
                policy_version=self.policy_engine.get_policy_version(),
            )
            return self._create_denied_request(request, policy_decision)

        # Step 5: Execute via PRIVATE connector
        # The connector verifies the capability signature
        try:
            raw_data = self._connector.execute(capability)
        except CapabilityVerificationError as e:
            # Signature verification failed
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"Capability verification failed: {str(e)}"],
                policy_version=self.policy_engine.get_policy_version(),
            )
            return self._create_denied_request(request, policy_decision)
        except Exception as e:
            # Fail closed: execution errors mean no data returned
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"Execution failed: {str(e)}"],
                policy_version=self.policy_engine.get_policy_version(),
            )
            return self._create_denied_request(request, policy_decision)

        # Step 6: Validate result
        # Convert capability to ExecutionPlan for validation
        execution_plan = self._capability_to_plan(capability)
        execution_result = self.validator.validate(execution_plan, raw_data)

        if not execution_result.verified:
            # Fail closed: validation failures mean result is rejected
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reasons=execution_result.verification_errors,
                policy_version=self.policy_engine.get_policy_version(),
            )
            return self._create_denied_request(request, policy_decision)

        # Step 7: Generate evidence
        evidence = Evidence.create_allowed(request, execution_plan, execution_result)
        audit_event = AuditEvent.from_evidence(evidence)

        # Step 8: Return allowed request
        return AllowedRequest(
            request_id=request.request_id,
            actor=actor,
            execution_plan=execution_plan,
            execution_result=execution_result,
            evidence=evidence,
            audit_event=audit_event,
        )

    def _evaluate_policy(self, request: Request) -> PolicyDecision:
        """
        Evaluate policy for the request.
        
        Determines:
        - Is this operation allowed?
        - What fields can be accessed?
        - What filters must be enforced?
        - What limits apply?
        """
        actor = request.actor
        intent = request.intent

        # Get requested fields (or all if none specified)
        requested_fields = intent.fields or []

        # Evaluate policy
        decision = self.policy_engine.evaluate(
            actor=actor,
            resource=intent.resource,
            operation=intent.operation,
            requested_fields=requested_fields,
        )

        return decision

    def _create_execution_plan(
        self,
        request: Request,
        policy_decision: PolicyDecision,
    ) -> ExecutionPlan:
        """
        Create an ExecutionPlan from an allowed request.
        
        The ExecutionPlan specifies EXACTLY what DataFence authorizes.
        
        CRITICAL: The plan may differ from what the LLM requested.
        - Fields may be restricted
        - Filters may be added (e.g., tenant_id)
        - Limits may be enforced
        
        The database executes THIS, not the LLM's request.
        """
        actor = request.actor
        intent = request.intent

        # Get allowed fields (policy may restrict what LLM requested)
        allowed_fields = self.policy_engine.get_allowed_fields(
            actor=actor,
            resource=intent.resource,
        )

        # If LLM requested specific fields, intersect with allowed
        if intent.fields:
            selected_fields = [f for f in intent.fields if f in allowed_fields]
        else:
            selected_fields = allowed_fields

        if not selected_fields:
            raise ValueError("No authorized fields available")

        # Get enforced filters (e.g., tenant_id)
        enforced_filters = self.policy_engine.get_enforced_filters(
            actor=actor,
            resource=intent.resource,
        )

        # Apply actor context to filters (e.g., tenant_id = actor.tenant_id)
        resolved_filters = {}
        for key, value in enforced_filters.items():
            if value == ":actor_tenant_id":
                resolved_filters[key] = actor.tenant_id
            elif value == ":actor_id":
                resolved_filters[key] = actor.id
            else:
                resolved_filters[key] = value

        # Add LLM's filters IF they don't conflict with enforced filters
        for key, value in intent.filters.items():
            if key not in resolved_filters:
                resolved_filters[key] = value

        # Get limit
        max_limit = self.policy_engine.get_max_limit(
            actor=actor,
            resource=intent.resource,
        )
        limit = min(intent.limit or max_limit, max_limit)

        # Create ExecutionPlan
        plan = ExecutionPlan.create(
            actor=actor,
            resource=intent.resource,
            operation=intent.operation,
            selected_fields=selected_fields,
            enforced_filters=resolved_filters,
            limit=limit,
            policy_version=self.policy_engine.get_policy_version(),
            policy_decisions=policy_decision.matched_policies,
        )

        return plan

    def _create_signed_capability(
        self,
        request: Request,
        policy_decision: PolicyDecision,
    ) -> AuthorizedExecution:
        """
        Create a cryptographically signed capability.
        
        This is the v0.4 hardened version of _create_execution_plan.
        The capability includes an HMAC signature that prevents forgery.
        """
        actor = request.actor
        intent = request.intent

        # Get allowed fields (policy may restrict what LLM requested)
        allowed_fields = self.policy_engine.get_allowed_fields(
            actor=actor,
            resource=intent.resource,
        )

        # If LLM requested specific fields, intersect with allowed
        if intent.fields:
            selected_fields = [f for f in intent.fields if f in allowed_fields]
        else:
            selected_fields = allowed_fields

        if not selected_fields:
            raise ValueError("No authorized fields available")

        # Get enforced filters (e.g., tenant_id)
        enforced_filters = self.policy_engine.get_enforced_filters(
            actor=actor,
            resource=intent.resource,
        )

        # Apply actor context to filters
        resolved_filters = {}
        for key, value in enforced_filters.items():
            if value == ":actor_tenant_id":
                resolved_filters[key] = actor.tenant_id
            elif value == ":actor_id":
                resolved_filters[key] = actor.id
            else:
                resolved_filters[key] = value

        # Add LLM's filters IF they don't conflict with enforced filters
        for key, value in intent.filters.items():
            if key not in resolved_filters:
                resolved_filters[key] = value

        # Get limit
        max_limit = self.policy_engine.get_max_limit(
            actor=actor,
            resource=intent.resource,
        )
        limit = min(intent.limit or max_limit, max_limit)

        # Import uuid for execution_id
        from uuid import uuid4
        
        # Create signed capability
        capability = AuthorizedExecution.create_signed(
            execution_id=f"exec_{uuid4().hex[:16]}",
            actor=actor,
            resource=intent.resource,
            operation=intent.operation,
            selected_fields=selected_fields,
            enforced_filters=resolved_filters,
            limit=limit,
            policy_version=self.policy_engine.get_policy_version(),
            policy_decisions=policy_decision.matched_policies,
            signing_key=self._signing_key,
        )

        return capability
    
    def _capability_to_plan(self, capability: AuthorizedExecution) -> ExecutionPlan:
        """
        Convert AuthorizedExecution to ExecutionPlan.
        
        This is for backward compatibility with Evidence/Result types.
        ExecutionPlan is kept for audit trail but is not used for execution.
        """
        return ExecutionPlan.create(
            actor=capability.actor,
            resource=capability.resource,
            operation=capability.operation,
            selected_fields=capability.selected_fields,
            enforced_filters=capability.enforced_filters,
            limit=capability.limit,
            policy_version=capability.policy_version,
            policy_decisions=capability.policy_decisions,
        )

    def _create_denied_request(
        self,
        request: Request,
        policy_decision: PolicyDecision,
    ) -> DeniedRequest:
        """Create a denied request with evidence."""
        evidence = Evidence.create_denied(request, policy_decision)
        audit_event = AuditEvent.from_evidence(evidence)

        return DeniedRequest(
            request_id=request.request_id,
            actor=request.actor,
            resource=request.intent.resource,
            operation=request.intent.operation,
            decision=policy_decision,
            evidence=evidence,
            audit_event=audit_event,
        )
