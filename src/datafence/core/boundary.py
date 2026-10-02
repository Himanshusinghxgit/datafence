"""
DataFence Security Boundary (v0.6 - Contract-Frozen Architecture).

This is the core enforcement layer with cryptographic capabilities.

Flow:
    Untrusted Request → Policy Evaluation → AuthorizedExecution (signed) → Execution → Validation

SECURITY IMPROVEMENTS:
- Capabilities are cryptographically signed with HMAC
- Connector is PRIVATE (not exposed in public API)
- Capability cannot be forged without signing key
- Defense in depth: API design + cryptography
- New DataFencePolicyEngine supported (Phase 3)
- Identifier validation in connectors (Phase 2)

The database NEVER executes LLM-generated SQL directly.
DataFence transforms the untrusted request into a signed capability.
The connector verifies the signature before execution.
"""

from collections.abc import Callable
from datetime import datetime, timedelta
from secrets import token_bytes
from typing import Any, Protocol
from uuid import uuid4

from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.policy import PolicyDecision as EnginePolicyDecision
from datafence.core.policy import PolicyEffect
from datafence.core.registry import ResourceRegistry
from datafence.core.resources import Filter
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
    PolicyDecision,
    Request,
)


class PolicyEngine(Protocol):
    """
    Policy engine interface (v0.6).

    Contract: evaluate() returns a datafence.core.policy.PolicyDecision.
    That single object carries everything needed to build a capability:
        - effect (ALLOW/DENY)
        - allowed_fields
        - enforced_filter (resolved, no actor refs)
        - row_limit
        - policy_version
        - matched_rules
        - obligations

    PolicyDecision is the sole policy output.  The boundary never consults
    secondary policy getters after evaluation.
    """

    def evaluate(self, principal: Actor, intent: Intent) -> EnginePolicyDecision:
        """
        Evaluate policy for a request.

        Must return a datafence.core.policy.PolicyDecision with:
            .effect       — PolicyEffect.ALLOW or PolicyEffect.DENY
            .reasons      — tuple of strings (populated on DENY)
            .allowed_fields, .enforced_filter, .row_limit, .policy_version
        """
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

    def __init__(self, registry: ResourceRegistry | None = None) -> None:
        self._registry = registry

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
                errors.append(f"Result contains unauthorized fields: {unauthorized}")
                break
            missing = allowed_fields - returned_fields
            if missing:
                errors.append(f"Result is missing authorized fields: {missing}")
                break

        # Check: values match the registry's declared logical types.  This is
        # deliberately conservative: unknown connector-native types are not
        # rejected, while obvious mismatches are.
        if self._registry is not None and self._registry.exists(plan.resource):
            resource = self._registry.get(plan.resource)
            assert resource is not None
            for row in data:
                for field_name in plan.selected_fields:
                    value = row.get(field_name)
                    definition = resource.fields[field_name]
                    if value is None and definition.nullable:
                        continue
                    expected = definition.data_type.lower()
                    valid = (
                        (expected in {"string", "text"} and isinstance(value, str))
                        or (
                            expected in {"integer", "int"}
                            and isinstance(value, int)
                            and not isinstance(value, bool)
                        )
                        or (
                            expected in {"decimal", "float", "number"}
                            and isinstance(value, (int, float))
                            and not isinstance(value, bool)
                        )
                        or (expected in {"boolean", "bool"} and isinstance(value, bool))
                    )
                    if expected not in {
                        "string",
                        "text",
                        "integer",
                        "int",
                        "decimal",
                        "float",
                        "number",
                        "boolean",
                        "bool",
                    }:
                        valid = True
                    if not valid:
                        errors.append(
                            f"Result field '{field_name}' has invalid type for {expected}"
                        )
                        break
                if errors:
                    break

        # Check: Row count within limit
        if len(data) > plan.limit:
            errors.append(f"Result exceeds limit: {len(data)} rows > {plan.limit}")

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
        signing_key: bytes | None = None,
        registry: ResourceRegistry | None = None,
        capability_ttl_seconds: int = 300,
        capability_audience: str = "datafence",
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
        if registry is None:
            raise ValueError("DataFenceBoundary requires a ResourceRegistry")
        policy_registry = getattr(policy_engine, "registry", None)
        if policy_registry is not None and policy_registry is not registry:
            raise ValueError("Boundary registry must match the policy engine registry")
        registry.freeze()
        if capability_ttl_seconds <= 0:
            raise ValueError("capability_ttl_seconds must be positive")
        if not capability_audience:
            raise ValueError("capability_audience cannot be empty")
        self.policy_engine = policy_engine
        self._connector = connector  # PRIVATE - not accessible externally
        self._registry = registry
        self._capability_ttl_seconds = capability_ttl_seconds
        self._capability_audience = capability_audience
        self.validator = ResultValidator(registry)

        # Set or generate signing key
        if signing_key is not None:
            self._signing_key = signing_key
        elif not hasattr(self, "_signing_key"):
            # Fallback: generate key (for backward compatibility)
            # WARNING: This will cause key mismatch with connector!
            import warnings

            warnings.warn(
                "Direct construction of DataFenceBoundary is deprecated. "
                "Use DataFenceBoundary.create() factory method to ensure "
                "proper key sharing with connector.",
                DeprecationWarning,
                stacklevel=2,
            )
            self._signing_key = token_bytes(32)

    @classmethod
    def create(
        cls,
        policy_engine: PolicyEngine,
        connector_factory: Callable[..., Connector],
        registry: ResourceRegistry | None = None,
        capability_ttl_seconds: int = 300,
        capability_audience: str = "datafence",
        **connector_kwargs: Any,
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
        if registry is None:
            raise ValueError("DataFenceBoundary.create() requires a ResourceRegistry")
        policy_registry = getattr(policy_engine, "registry", None)
        if policy_registry is not None and policy_registry is not registry:
            raise ValueError("Boundary registry must match the policy engine registry")
        registry.freeze()
        if capability_ttl_seconds <= 0:
            raise ValueError("capability_ttl_seconds must be positive")
        if not capability_audience:
            raise ValueError("capability_audience cannot be empty")

        # Generate signing key (32 bytes for HMAC-SHA256)
        signing_key = token_bytes(32)

        # Create connector with signing key
        # Pass signing_key as kwarg - factory MUST accept it
        connector = connector_factory(
            **connector_kwargs,
            signing_key=signing_key,
            expected_audience=capability_audience,
        )

        # Create boundary instance
        boundary = cls.__new__(cls)
        boundary.policy_engine = policy_engine
        boundary._connector = connector
        boundary._signing_key = signing_key
        boundary._registry = registry
        boundary._capability_ttl_seconds = capability_ttl_seconds
        boundary._capability_audience = capability_audience
        boundary.validator = ResultValidator(registry)

        return boundary

    def execute(
        self,
        actor: Actor,
        intent: Intent,
    ) -> AllowedRequest | DeniedRequest:
        """
        Execute a request through the security boundary (v0.6).

        Flow:
            1. Normalize request (actor + intent → Request)
            2. Evaluate policy ONCE → raw_decision
            3. If DENY → DeniedRequest (fail closed)
            4. Build signed AuthorizedExecution from raw_decision (no re-evaluation)
            5. Execute via PRIVATE connector (verifies HMAC before any SQL)
            6. Validate result (defense in depth)
            7. Generate Evidence
            8. Return AllowedRequest

        Security:
            - Policy evaluated exactly once; capability built from that result
            - Connector is private — external code cannot call it
            - Connector verifies HMAC signature before execution
            - Result validator catches any unauthorized fields from connector
            - Fail closed on every error path
        """
        request = Request.create(actor, intent)

        # Step 2: validate the resource before policy evaluation.  Registry
        # validation is descriptive, not authorization; policy still decides.
        try:
            self._registry.validate_intent(intent)
        except ValueError as exc:
            return self._denied(request, [str(exc)])

        # Step 3: single policy evaluation — the exact decision is passed to
        # capability construction and denial evidence.
        try:
            raw_decision = self.policy_engine.evaluate(principal=actor, intent=intent)
        except Exception as exc:
            return self._denied(request, [f"Policy evaluation failed: {exc}"])

        # A malformed or foreign decision is a deny, never an exception or
        # an implicit allow.
        if not isinstance(raw_decision, EnginePolicyDecision):
            return self._denied(request, ["Invalid policy decision"])
        if raw_decision.effect not in (PolicyEffect.ALLOW, PolicyEffect.DENY):
            return self._denied(request, ["Invalid policy decision"])

        # Step 3: check decision
        if self._is_deny(raw_decision):
            return self._denied(request, self._reasons(raw_decision), raw_decision)

        # Step 4: build signed capability from the exact decision (no re-evaluation)
        try:
            capability = self._build_capability(request, raw_decision)
        except Exception as exc:
            return self._denied(request, [f"Capability creation failed: {exc}"])

        # Step 5: execute via private connector
        try:
            raw_data = self._connector.execute(capability)
        except CapabilityVerificationError as exc:
            return self._denied(request, [f"Capability verification failed: {exc}"])
        except Exception as exc:
            return self._denied(request, [f"Execution failed: {exc}"])

        # Step 6: result validation
        execution_plan = self._capability_to_plan(capability)
        execution_result = self.validator.validate(execution_plan, raw_data)
        if not execution_result.verified:
            return self._denied(request, execution_result.verification_errors)

        # Step 7: evidence
        evidence = Evidence.create_allowed(request, execution_plan, execution_result)
        audit_event = AuditEvent.from_evidence(evidence)

        return AllowedRequest(
            request_id=request.request_id,
            actor=actor,
            execution_plan=execution_plan,
            execution_result=execution_result,
            evidence=evidence,
            audit_event=audit_event,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_deny(raw_decision: EnginePolicyDecision) -> bool:
        """Return True if raw_decision is a denial."""
        return bool(raw_decision.effect == PolicyEffect.DENY)

    @staticmethod
    def _reasons(raw_decision: Any) -> list[str]:
        """Extract denial reasons from a PolicyDecision."""
        return list(raw_decision.reasons)

    def _denied(
        self,
        request: Request,
        reasons: list[str],
        source_decision: Any | None = None,
    ) -> DeniedRequest:
        """Build a DeniedRequest with evidence."""
        # A denial produced by policy must carry the version from that same
        # PolicyDecision.  Never consult a second mutable policy API here.
        policy_version = getattr(source_decision, "policy_version", "unknown")
        pd = PolicyDecision(
            decision=Decision.DENY,
            reasons=reasons,
            policy_version=policy_version,
        )
        evidence = Evidence.create_denied(request, pd)
        return DeniedRequest(
            request_id=request.request_id,
            actor=request.actor,
            resource=request.intent.resource,
            operation=request.intent.operation,
            decision=pd,
            evidence=evidence,
            audit_event=AuditEvent.from_evidence(evidence),
        )

    def _build_capability(self, request: Request, raw_decision: Any) -> AuthorizedExecution:
        """
        Build a signed AuthorizedExecution from a DataFencePolicyDecision.

        This is the ONLY place AuthorizedExecution is created.
        The raw_decision is the exact object returned by policy_engine.evaluate()
        — no re-evaluation, no legacy helper methods.

        Contract: raw_decision must be a datafence.core.policy.PolicyDecision
        with .allowed_fields, .enforced_filter, .row_limit, .policy_version.
        """
        actor = request.actor
        intent = request.intent

        allowed_fields_list = list(raw_decision.allowed_fields)
        if intent.fields:
            selected_fields = [f for f in intent.fields if f in allowed_fields_list]
        else:
            selected_fields = allowed_fields_list

        if not selected_fields:
            raise ValueError("No authorized fields available after policy evaluation")

        # Keep the typed policy predicates intact. Policy predicates win on
        # duplicate fields; user filters can only narrow the result.
        resolved_filter = raw_decision.enforced_filter.merge(Filter.from_dict(intent.filters))
        resolved_filters = resolved_filter.to_dict()  # compatibility/audit view

        limit = raw_decision.row_limit.value
        if intent.limit:
            limit = min(intent.limit, limit)

        return AuthorizedExecution.create_signed(
            execution_id=f"exec_{uuid4().hex[:16]}",
            actor=actor,
            resource=intent.resource,
            operation=intent.operation,
            selected_fields=selected_fields,
            enforced_filters=resolved_filters,
            enforced_predicates=resolved_filter.to_constraints(),
            limit=limit,
            policy_version=raw_decision.policy_version,
            policy_decisions=list(raw_decision.matched_rules),
            signing_key=self._signing_key,
            expires_at=datetime.utcnow() + timedelta(seconds=self._capability_ttl_seconds),
            audience=self._capability_audience,
        )

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
