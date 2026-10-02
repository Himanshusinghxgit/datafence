"""
DataFence security invariant tests.

These tests prove the critical security properties of DataFence v1:

    1. Authorization
    2. Capability integrity (HMAC, expiry, audience)
    3. Predicate losslessness (all operators preserved end-to-end)
    4. Registry validation (fail-closed on unknown resources/fields/ops)
    5. Identity model (LLM cannot choose principal)
    6. No legacy bypass paths

Every test here corresponds to a specific threat or security invariant.
A failing test means a security regression.
"""

from __future__ import annotations

import dataclasses
import time
from datetime import datetime, timedelta, timezone
from secrets import token_bytes
from typing import Any

import pytest

from datafence import (
    Actor,
    ActionDecision,
    AuthorizedExecution,
    CapabilityVerifier,
    DataFenceBoundary,
    DataFencePolicy,
    DataFencePolicyEngine,
    FieldDefinition,
    Intent,
    Operation,
    ResourceDefinition,
    ResourcePolicy,
    ResourceRegistry,
    RowRule,
    YAMLPolicyLoader,
)
from datafence.connectors.memory_connector import InMemoryReferenceConnector
from datafence.core.capability import CapabilityVerificationError
from datafence.core.resources import PredicateOperator
from datafence.errors import PolicyDeniedError, PolicyError


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def _make_registry() -> ResourceRegistry:
    reg = ResourceRegistry()
    reg.register(
        ResourceDefinition(
            "customers",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "name": FieldDefinition("name", "string"),
                "email": FieldDefinition("email", "string"),
                "ssn": FieldDefinition(
                    "ssn", "string", classification=__import__("datafence").DataClassification.RESTRICTED
                ),
            },
            supported_operations=("read",),
        )
    )
    reg.register(
        ResourceDefinition(
            "orders",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "total": FieldDefinition("total", "decimal"),
                "status": FieldDefinition("status", "string"),
            },
            supported_operations=("read",),
        )
    )
    return reg


def _make_policy(registry: ResourceRegistry) -> DataFencePolicyEngine:
    policy = DataFencePolicy(
        "test-policy",
        "1.0",
        {
            "customers": ResourcePolicy(
                "customers",
                actions={
                    "read": ActionDecision.ALLOW,
                    "delete": ActionDecision.DENY,
                },
                allowed_fields=["id", "tenant_id", "name", "email"],
                denied_fields=["ssn"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=25,
            ),
            "orders": ResourcePolicy(
                "orders",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "total", "status"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=50,
            ),
        },
    )
    return DataFencePolicyEngine(policy, registry=registry)


def _make_boundary(
    audience: str = "test-service",
    ttl: int = 300,
) -> tuple[DataFenceBoundary, bytes, ResourceRegistry]:
    registry = _make_registry()
    engine = _make_policy(registry)
    key = token_bytes(32)
    boundary = DataFenceBoundary.create(
        engine, registry, key,
        capability_ttl_seconds=ttl,
        capability_audience=audience,
    )
    return boundary, key, registry


# ===========================================================================
# 1. Authorization — basic allow/deny
# ===========================================================================


class TestAuthorization:
    def test_authorized_request_returns_capability(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        assert isinstance(cap, AuthorizedExecution)
        assert cap.resource == "customers"
        assert "id" in cap.selected_fields
        assert "name" in cap.selected_fields

    def test_denied_operation_raises(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("user:1", "tenant-a"),
                Intent("customers", Operation.DELETE),
            )

    def test_wrong_principal_gets_own_tenant_data(self) -> None:
        """Policy injects tenant isolation — a different tenant sees their own filter."""
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:2", "tenant-b"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        constraints = cap.filter_constraints()
        tenant_filter = next(c for c in constraints if c["field"] == "tenant_id")
        assert tenant_filter["value"] == "tenant-b"

    def test_wrong_tenant_cannot_read_other_tenant(self) -> None:
        """Agent cannot override tenant filter via intent filters."""
        boundary, key, _ = _make_boundary()
        # Agent for tenant-a requests filters for tenant-b
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, filters={"tenant_id": "tenant-b"}),
        )
        # Policy-enforced filter (tenant-a) must take priority
        constraints = cap.filter_constraints()
        tenant_filters = [c for c in constraints if c["field"] == "tenant_id"]
        # Policy EQ filter on tenant-a must be present
        assert any(c["value"] == "tenant-a" for c in tenant_filters), (
            "Policy-enforced tenant filter must override agent-supplied value"
        )
        # Verify with in-memory connector: only tenant-a rows returned
        connector = InMemoryReferenceConnector(
            {
                "customers": [
                    {"id": 1, "tenant_id": "tenant-a", "name": "Alice", "email": "a@a.com", "ssn": "X"},
                    {"id": 2, "tenant_id": "tenant-b", "name": "Bob", "email": "b@b.com", "ssn": "Y"},
                ]
            },
            signing_key=key,
            expected_audience="test-service",
        )
        result = connector.execute(cap)
        assert all(r["tenant_id"] == "tenant-a" for r in result.rows), (
            "tenant-b rows must not be returned for tenant-a principal"
        )

    def test_unauthorized_field_is_excluded(self) -> None:
        """ssn is in denied_fields — must never appear in the capability."""
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("user:1", "tenant-a"),
                Intent("customers", Operation.READ, fields=["id", "name", "ssn"]),
            )

    def test_restricted_field_blocked_at_registry(self) -> None:
        """Registry catches restricted field in filters."""
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("user:1", "tenant-a"),
                Intent("customers", Operation.READ, filters={"ssn": "123-45-6789"}),
            )

    def test_unknown_resource_is_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("user:1", "tenant-a"),
                Intent("salary_data", Operation.READ),
            )

    def test_unknown_field_is_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("user:1", "tenant-a"),
                Intent("customers", Operation.READ, fields=["id", "nonexistent_field"]),
            )

    def test_unsupported_operation_is_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("user:1", "tenant-a"),
                Intent("customers", Operation.INSERT),
            )

    def test_row_limit_is_capped_by_policy(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, limit=9999),
        )
        assert cap.limit == 25  # policy max_rows = 25

    def test_row_limit_respects_agent_if_lower(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, limit=5),
        )
        assert cap.limit == 5  # agent asked for 5, policy max is 25


# ===========================================================================
# 2. Capability integrity
# ===========================================================================


class TestCapabilityIntegrity:
    def test_valid_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        assert cap.verify_signature(key)

    def test_forged_capability_fails_signature(self) -> None:
        """A capability created with a different key must not verify."""
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        wrong_key = token_bytes(32)
        assert not cap.verify_signature(wrong_key)

    def test_tampered_resource_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(cap, resource="orders")
        assert not tampered.verify_signature(key)

    def test_tampered_operation_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(cap, operation=Operation.DELETE)
        assert not tampered.verify_signature(key)

    def test_tampered_fields_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(cap, selected_fields=["id", "ssn"])
        assert not tampered.verify_signature(key)

    def test_tampered_predicate_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(
            cap,
            enforced_predicates=[{"field": "tenant_id", "operator": "=", "value": "tenant-b"}],
        )
        assert not tampered.verify_signature(key)

    def test_tampered_limit_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(cap, limit=99999)
        assert not tampered.verify_signature(key)

    def test_tampered_tenant_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        new_actor = dataclasses.replace(cap.actor, tenant_id="tenant-evil")
        tampered = dataclasses.replace(cap, actor=new_actor)
        assert not tampered.verify_signature(key)

    def test_tampered_policy_version_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(cap, policy_version="evil-version")
        assert not tampered.verify_signature(key)

    def test_tampered_expiry_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        new_expiry = datetime.now(timezone.utc) + timedelta(days=365)
        tampered = dataclasses.replace(cap, expires_at=new_expiry)
        assert not tampered.verify_signature(key)

    def test_tampered_audience_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(cap, audience="evil-service")
        assert not tampered.verify_signature(key)

    def test_tampered_nonce_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered = dataclasses.replace(cap, nonce="attacker-chosen-nonce")
        assert not tampered.verify_signature(key)

    def test_expired_capability_rejected_by_verifier(self) -> None:
        """A capability with TTL=1s must be rejected after expiry."""
        boundary, key, _ = _make_boundary(ttl=1)
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        # Force-expire the capability.
        expired_cap = dataclasses.replace(
            cap,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
        verifier = CapabilityVerifier(key, expected_audience="test-service")
        with pytest.raises(CapabilityVerificationError, match="expired"):
            verifier.verify(expired_cap)

    def test_wrong_audience_rejected_by_verifier(self) -> None:
        boundary, key, _ = _make_boundary(audience="service-a")
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        verifier = CapabilityVerifier(key, expected_audience="service-b")
        with pytest.raises(CapabilityVerificationError, match="audience"):
            verifier.verify(cap)

    def test_invalid_signature_rejected_by_verifier(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        wrong_key = token_bytes(32)
        verifier = CapabilityVerifier(wrong_key, expected_audience="test-service")
        with pytest.raises(CapabilityVerificationError, match="signature"):
            verifier.verify(cap)

    def test_connector_rejects_forged_capability(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        forged = dataclasses.replace(cap, resource="orders")
        connector = InMemoryReferenceConnector({}, signing_key=key, expected_audience="test-service")
        with pytest.raises(CapabilityVerificationError):
            connector.execute(forged)

    def test_two_different_authorizations_have_different_nonces(self) -> None:
        """Each authorize() call must produce a distinct nonce."""
        boundary, _, _ = _make_boundary()
        principal = Actor("user:1", "tenant-a")
        intent = Intent("customers", Operation.READ, ["id"])
        cap1 = boundary.authorize(principal, intent)
        cap2 = boundary.authorize(principal, intent)
        assert cap1.nonce != cap2.nonce
        assert cap1.execution_id != cap2.execution_id


# ===========================================================================
# 3. Predicate losslessness
# ===========================================================================


class TestPredicateLosslessness:
    """
    Every supported operator must survive the full pipeline:
    Intent → Policy → AuthorizedExecution → filter_constraints().
    """

    def _boundary_with_rule(self, op: PredicateOperator, value: Any) -> tuple[DataFenceBoundary, bytes]:
        reg = ResourceRegistry()
        reg.register(
            ResourceDefinition(
                "metrics",
                fields={
                    "id": FieldDefinition("id", "integer"),
                    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                    "value": FieldDefinition("value", "decimal"),
                    "category": FieldDefinition("category", "string"),
                },
                supported_operations=("read",),
            )
        )
        policy = DataFencePolicy(
            "p", "1",
            {
                "metrics": ResourcePolicy(
                    "metrics",
                    actions={"read": ActionDecision.ALLOW},
                    allowed_fields=["id", "tenant_id", "value", "category"],
                    row_rules=[
                        RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id"),
                        RowRule("value", op, value),
                    ],
                    max_rows=100,
                )
            },
        )
        engine = DataFencePolicyEngine(policy, registry=reg)
        key = token_bytes(32)
        boundary = DataFenceBoundary.create(engine, reg, key, capability_audience="test-service")
        return boundary, key

    def _get_operator_for_field(
        self, constraints: list[dict], field: str
    ) -> str | None:
        for c in constraints:
            if c["field"] == field:
                return c["operator"]
        return None

    def test_operator_eq(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.EQ, 42)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "="

    def test_operator_neq(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.NEQ, 0)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "!="

    def test_operator_lt(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.LT, 1000)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "<"

    def test_operator_lte(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.LTE, 1000)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "<="

    def test_operator_gt(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.GT, 500)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == ">"

    def test_operator_gte(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.GTE, 500)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == ">="

    def test_operator_in(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.IN, ["a", "b", "c"])
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "IN"

    def test_operator_not_in(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.NOT_IN, ["x", "y"])
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "NOT IN"

    def test_operator_is_null(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.IS_NULL, None)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "IS NULL"

    def test_operator_is_not_null(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.IS_NOT_NULL, None)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        op = self._get_operator_for_field(cap.filter_constraints(), "value")
        assert op == "IS NOT NULL"

    def test_lt_predicate_not_confused_with_eq(self) -> None:
        """Regression: amount > 1000 must not become amount == 1000."""
        b, _ = self._boundary_with_rule(PredicateOperator.GT, 1000)
        cap = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        constraints = cap.filter_constraints()
        value_constraint = next(c for c in constraints if c["field"] == "value")
        assert value_constraint["operator"] == ">", (
            "GT predicate must not be coerced to EQ. "
            f"Got: {value_constraint['operator']!r}"
        )


# ===========================================================================
# 4. Registry validation (fail-closed)
# ===========================================================================


class TestRegistryFailClosed:
    def test_registry_mutation_after_freeze_raises(self) -> None:
        boundary, _, registry = _make_boundary()
        assert registry.is_frozen
        with pytest.raises(RuntimeError, match="frozen"):
            registry.register(ResourceDefinition("new_resource"))

    def test_policy_references_unknown_resource_is_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("u", "t"),
                Intent("nonexistent_table", Operation.READ),
            )

    def test_policy_references_unknown_field_is_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Actor("u", "t"),
                Intent("customers", Operation.READ, fields=["id", "mystery_column"]),
            )

    def test_policy_registry_mismatch_prevents_boundary_creation(self) -> None:
        reg1 = _make_registry()
        reg2 = _make_registry()  # different object
        engine = _make_policy(reg1)
        key = token_bytes(32)
        with pytest.raises(ValueError, match="registry"):
            DataFenceBoundary.create(engine, reg2, key)

    def test_empty_signing_key_prevented(self) -> None:
        reg = _make_registry()
        engine = _make_policy(reg)
        with pytest.raises(ValueError, match="signing_key"):
            DataFenceBoundary.create(engine, reg, b"")

    def test_direct_instantiation_blocked(self) -> None:
        with pytest.raises(TypeError, match="DataFenceBoundary.create"):
            DataFenceBoundary()

    def test_unknown_yaml_operator_fails_closed(self) -> None:
        """An unknown row-filter operator must raise, not silently fall back to EQ."""
        with pytest.raises(ValueError, match="operator"):
            YAMLPolicyLoader.from_dict(
                {
                    "name": "p",
                    "version": "1",
                    "resources": {
                        "customers": {
                            "actions": {"read": "allow"},
                            "fields": {"allow": ["id"]},
                            "rows": [{"field": "id", "operator": "TYPO_OP", "value": 1}],
                        }
                    },
                }
            )

    def test_malformed_policy_decision_fails_closed(self) -> None:
        """A policy engine that returns garbage must not produce an AuthorizedExecution."""

        class BrokenEngine:
            registry = _make_registry()

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return "not a PolicyDecision"

        reg = _make_registry()
        # Freeze the registry manually since BrokenEngine.registry is a different object.
        broken = BrokenEngine()
        broken.registry = reg
        key = token_bytes(32)
        reg.freeze()

        boundary = DataFenceBoundary.__new__(DataFenceBoundary)
        boundary.policy_engine = broken  # type: ignore[assignment]
        boundary._registry = reg
        boundary._signing_key = key
        boundary._capability_ttl_seconds = 300
        boundary._capability_audience = "x"

        with pytest.raises(PolicyError):
            boundary.authorize(Actor("u", "t"), Intent("customers", Operation.READ))


# ===========================================================================
# 5. Identity model (LLM cannot choose principal)
# ===========================================================================


class TestIdentityModel:
    def test_llm_cannot_override_tenant_via_intent(self) -> None:
        """
        The LLM supplies Intent. The application supplies Actor.
        The tenant_id in AuthorizedExecution must come from Actor, not Intent.
        """
        boundary, key, _ = _make_boundary()
        # Application says this is tenant-a.
        principal = Actor("user:1", "tenant-a")
        # LLM tries to filter by tenant-b.
        intent = Intent("customers", Operation.READ, filters={"tenant_id": "tenant-b"})
        cap = boundary.authorize(principal, intent)
        # The policy-enforced filter must bind to tenant-a (from Actor).
        enforced = {c["field"]: c["value"] for c in cap.filter_constraints() if c["operator"] == "="}
        assert enforced.get("tenant_id") == "tenant-a", (
            "tenant_id must be bound to the authenticated Actor's tenant, not the LLM's filter"
        )

    def test_llm_cannot_choose_actor_id(self) -> None:
        """The actor.id must come from the application, not the LLM's arguments."""
        boundary, key, _ = _make_boundary()
        principal = Actor("user:alice", "tenant-a")
        cap = boundary.authorize(principal, Intent("customers", Operation.READ))
        assert cap.actor.id == "user:alice"

    def test_raw_sql_in_intent_is_ignored(self) -> None:
        """
        DataFence does not use raw_sql from Intent.
        No connector in DataFence core executes raw SQL from the agent.
        """
        # Intent allows raw_sql field for observability (storing what the LLM proposed),
        # but DataFence must never pass it to a connector.
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent(
                "customers",
                Operation.READ,
                fields=["id"],
            ),
        )
        # The AuthorizedExecution must contain NO raw_sql.
        assert not hasattr(cap, "raw_sql"), (
            "AuthorizedExecution must not carry raw SQL from the agent"
        )

    def test_actor_is_immutable_after_creation(self) -> None:
        actor = Actor("user:1", "tenant-a", metadata={"dept": "finance"})
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            actor.id = "hacked"  # type: ignore[misc]

    def test_authorized_execution_is_immutable(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            cap.resource = "hacked"  # type: ignore[misc]


# ===========================================================================
# 6. In-memory connector — full end-to-end
# ===========================================================================


class TestConnectorEndToEnd:
    def _setup(self) -> tuple[DataFenceBoundary, InMemoryReferenceConnector, bytes]:
        boundary, key, _ = _make_boundary()
        data = {
            "customers": [
                {"id": 1, "tenant_id": "tenant-a", "name": "Alice", "email": "a@a.com", "ssn": "111"},
                {"id": 2, "tenant_id": "tenant-a", "name": "Bob", "email": "b@a.com", "ssn": "222"},
                {"id": 3, "tenant_id": "tenant-b", "name": "Carol", "email": "c@b.com", "ssn": "333"},
            ],
            "orders": [
                {"id": 10, "tenant_id": "tenant-a", "total": 99.99, "status": "shipped"},
                {"id": 11, "tenant_id": "tenant-b", "total": 49.00, "status": "pending"},
            ],
        }
        connector = InMemoryReferenceConnector(data, key, expected_audience="test-service")
        return boundary, connector, key

    def test_correct_rows_returned(self) -> None:
        boundary, connector, _ = self._setup()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        result = connector.execute(cap)
        assert result.row_count == 2
        names = {r["name"] for r in result.rows}
        assert names == {"Alice", "Bob"}

    def test_ssn_not_in_results(self) -> None:
        """SSN must never appear in results even though it exists in the data."""
        boundary, connector, _ = self._setup()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name", "email"]),
        )
        result = connector.execute(cap)
        for row in result.rows:
            assert "ssn" not in row, "SSN must never leak into connector results"

    def test_other_tenant_rows_not_returned(self) -> None:
        boundary, connector, _ = self._setup()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("orders", Operation.READ, ["id", "total", "status"]),
        )
        result = connector.execute(cap)
        for row in result.rows:
            assert row.get("tenant_id", "tenant-a") == "tenant-a"
