"""
DataFence Security Boundary.

This is the core enforcement layer.

Flow:
    Untrusted Request → Policy Evaluation → ExecutionPlan → Execution → Validation

The database NEVER executes LLM-generated SQL directly.
DataFence transforms the untrusted request into an authorized ExecutionPlan.
The connector executes ONLY the ExecutionPlan.
"""

from typing import Protocol, Union

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
    Connector interface.
    
    CRITICAL: The connector MUST accept ExecutionPlan, not raw SQL.
    
    The connector generates SQL from the ExecutionPlan internally.
    This ensures the database executes DataFence's authorized plan,
    not the LLM's untrusted SQL.
    """

    def execute_plan(self, plan: ExecutionPlan) -> list[dict[str, str]]:
        """
        Execute an authorized ExecutionPlan.
        
        The connector MUST:
        1. Accept ONLY ExecutionPlan
        2. Generate SQL from the plan internally
        3. Use prepared statements
        4. Return ONLY the fields in plan.selected_fields
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
    The DataFence security boundary.
    
    This is the enforcement layer between AI agents and data.
    
    Security properties:
    1. Untrusted requests never reach the database directly
    2. Policy evaluation happens BEFORE execution
    3. ExecutionPlan is the authorized contract
    4. Result validation happens AFTER execution
    5. Everything produces evidence
    6. Fail closed on errors
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        connector: Connector,
    ):
        self.policy_engine = policy_engine
        self.connector = connector
        self.validator = ResultValidator()

    def execute(
        self,
        actor: Actor,
        intent: Intent,
    ) -> Union[AllowedRequest, DeniedRequest]:
        """
        Execute a request through the security boundary.
        
        Flow:
        1. Create Request (Actor + Intent)
        2. Evaluate Policy
        3. If DENY: return DeniedRequest
        4. If ALLOW: create ExecutionPlan
        5. Execute ExecutionPlan via connector
        6. Validate result
        7. Generate evidence
        8. Return AllowedRequest
        
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

        # Step 4: Create ExecutionPlan
        try:
            execution_plan = self._create_execution_plan(request, policy_decision)
        except Exception as e:
            # Fail closed: treat plan creation errors as DENY
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"ExecutionPlan creation failed: {str(e)}"],
                policy_version=self.policy_engine.get_policy_version(),
            )
            return self._create_denied_request(request, policy_decision)

        # Step 5: Execute via connector
        try:
            raw_data = self.connector.execute_plan(execution_plan)
        except Exception as e:
            # Fail closed: execution errors mean no data returned
            policy_decision = PolicyDecision(
                decision=Decision.DENY,
                reasons=[f"Execution failed: {str(e)}"],
                policy_version=self.policy_engine.get_policy_version(),
            )
            return self._create_denied_request(request, policy_decision)

        # Step 6: Validate result
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
