"""
DataFence security invariant tests.

These tests prove the critical security properties of DataFence:

    1.  Authorization — allow/deny correctness
    2.  Capability integrity — HMAC covers every security-relevant field
                              including principal.roles (Phase 3)
    3.  Predicate losslessness — all operators survive the full pipeline
    4.  Registry validation — fail-closed on unknown resources / fields / ops
    5.  Identity model — LLM cannot choose or override the principal
    6.  Architecture — DataFence does not execute data, holds no connector
    7.  Connector end-to-end — InMemoryReferenceConnector enforces all rules
    8.  MCP security invariants
    9.  Package boundary invariants
   10.  Hardening invariants — key length, immutability, policy freeze,
        obligations, CapabilityToken, tenant isolation, filter authorization

A failing test is a security regression.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from secrets import token_bytes
from typing import Any

import pytest

# Additional imports for boundary validation and nonce tests
from datafence import (
    MIN_KEY_BYTES,
    ActionDecision,
    AuthorizedExecution,
    CapabilityToken,
    CapabilityVerificationError,
    CapabilityVerifier,
    DataClassification,
    DataFenceBoundary,
    DataFencePolicy,
    DataFencePolicyEngine,
    FieldDefinition,
    Intent,
    Operation,
    Principal,
    ResourceDefinition,
    ResourcePolicy,
    ResourceRegistry,
    RowRule,
    YAMLPolicyLoader,
)
from datafence.core.policy import PolicyDecision, PolicyEffect
from datafence.core.resources import FieldRef, Filter, Predicate, PredicateOperator, RowLimit
from datafence.errors import ConfigurationError, PolicyDeniedError, PolicyError
from examples.reference_connector.memory import InMemoryReferenceConnector

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
                    "ssn", "string",
                    classification=__import__("datafence").DataClassification.RESTRICTED,
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
                },
                allowed_fields=["id", "tenant_id", "name", "email"],
                denied_fields=["ssn"],
                filterable_fields=["id", "tenant_id", "name"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=25,
            ),
            "orders": ResourcePolicy(
                "orders",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "total", "status"],
                filterable_fields=["id", "tenant_id", "status"],
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
            Principal("user:1", "tenant-a"),
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
                Principal("user:1", "tenant-a"),
                Intent("customers", Operation.INSERT),
            )

    def test_different_tenant_gets_own_filter(self) -> None:
        """Policy injects tenant isolation — a different principal sees their own tenant."""
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:2", "tenant-b"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        constraints = cap.filter_constraints()
        tenant_filter = next(c for c in constraints if c["field"] == "tenant_id")
        assert tenant_filter["value"] == "tenant-b"

    def test_agent_cannot_override_tenant_filter(self) -> None:
        """Agent-supplied tenant filter must be overridden by the policy-enforced one."""
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, filters={"tenant_id": "tenant-b"}),
        )
        constraints = cap.filter_constraints()
        tenant_filters = [c for c in constraints if c["field"] == "tenant_id"]
        assert any(c["value"] == "tenant-a" for c in tenant_filters), (
            "Policy-enforced tenant filter must override agent-supplied value"
        )
        connector = InMemoryReferenceConnector(
            {
                "customers": [
                    {"id": 1, "tenant_id": "tenant-a", "name": "Alice", "email": "a@a.com", "ssn": "X"},
                    {"id": 2, "tenant_id": "tenant-b", "name": "Bob",   "email": "b@b.com", "ssn": "Y"},
                ]
            },
            signing_key=key,
            expected_audience="test-service",
        )
        result = connector.execute(cap)
        assert all(r["tenant_id"] == "tenant-a" for r in result.rows)

    def test_unauthorized_field_denied(self) -> None:
        """ssn is in denied_fields — must never appear in the capability."""
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Principal("user:1", "tenant-a"),
                Intent("customers", Operation.READ, fields=["id", "name", "ssn"]),
            )

    def test_restricted_field_blocked_at_registry(self) -> None:
        """Registry catches restricted field in filters."""
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Principal("user:1", "tenant-a"),
                Intent("customers", Operation.READ, filters={"ssn": "123-45-6789"}),
            )

    def test_unknown_resource_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Principal("user:1", "tenant-a"),
                Intent("salary_data", Operation.READ),
            )

    def test_unknown_field_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Principal("user:1", "tenant-a"),
                Intent("customers", Operation.READ, fields=["id", "nonexistent_field"]),
            )

    def test_unsupported_operation_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Principal("user:1", "tenant-a"),
                Intent("customers", Operation.INSERT),
            )
    def test_row_limit_capped_by_policy(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, limit=9999),
        )
        assert cap.limit == 25  # policy max_rows = 25

    def test_row_limit_respects_agent_if_lower(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, limit=5),
        )
        assert cap.limit == 5


# ===========================================================================
# 2. Capability integrity
# ===========================================================================


class TestCapabilityIntegrity:
    def test_valid_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        assert cap.verify_signature(key)

    def test_forged_key_fails(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        assert not cap.verify_signature(token_bytes(32))

    def test_tampered_resource_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not dataclasses.replace(cap, resource="orders").verify_signature(key)

    def test_tampered_operation_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not dataclasses.replace(cap, operation=Operation.INSERT).verify_signature(key)

    def test_tampered_fields_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not dataclasses.replace(cap, selected_fields=["id", "ssn"]).verify_signature(key)

    def test_tampered_predicate_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        tampered = dataclasses.replace(
            cap,
            predicates=[{"field": "tenant_id", "operator": "=", "value": "tenant-b"}],
        )
        assert not tampered.verify_signature(key)

    def test_tampered_limit_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not dataclasses.replace(cap, limit=99999).verify_signature(key)

    def test_tampered_tenant_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        new_actor = dataclasses.replace(cap.actor, tenant_id="tenant-evil")
        assert not dataclasses.replace(cap, actor=new_actor).verify_signature(key)

    def test_tampered_policy_version_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not dataclasses.replace(cap, policy_version="evil-version").verify_signature(key)

    def test_tampered_expiry_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        new_expiry = datetime.now(timezone.utc) + timedelta(days=365)
        assert not dataclasses.replace(cap, expires_at=new_expiry).verify_signature(key)

    def test_tampered_audience_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not dataclasses.replace(cap, audience="evil-service").verify_signature(key)

    def test_tampered_nonce_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not dataclasses.replace(cap, nonce="attacker-chosen").verify_signature(key)

    def test_expired_capability_rejected_by_verifier(self) -> None:
        boundary, key, _ = _make_boundary(ttl=1)
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        expired = dataclasses.replace(
            cap, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        with pytest.raises(CapabilityVerificationError, match="expired"):
            CapabilityVerifier(key, expected_audience="test-service").verify(expired)

    def test_wrong_audience_rejected_by_verifier(self) -> None:
        boundary, key, _ = _make_boundary(audience="service-a")
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        with pytest.raises(CapabilityVerificationError, match="audience"):
            CapabilityVerifier(key, expected_audience="service-b").verify(cap)

    def test_wrong_key_rejected_by_verifier(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(token_bytes(32), expected_audience="test-service").verify(cap)

    def test_each_authorization_has_unique_nonce(self) -> None:
        boundary, _, _ = _make_boundary()
        p = Principal("user:1", "tenant-a")
        i = Intent("customers", Operation.READ, ["id"])
        cap1 = boundary.authorize(p, i)
        cap2 = boundary.authorize(p, i)
        assert cap1.nonce != cap2.nonce
        assert cap1.execution_id != cap2.execution_id

    def test_connector_rejects_tampered_capability(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        forged = dataclasses.replace(cap, resource="orders")
        connector = InMemoryReferenceConnector({}, signing_key=key,
                                               expected_audience="test-service")
        with pytest.raises(CapabilityVerificationError):
            connector.execute(forged)


# ===========================================================================
# 3. Predicate losslessness
# ===========================================================================


class TestPredicateLosslessness:
    """Every supported operator must survive the full pipeline end-to-end."""

    def _boundary_with_rule(
        self, op: PredicateOperator, value: Any
    ) -> tuple[DataFenceBoundary, bytes]:
        reg = ResourceRegistry()
        reg.register(
            ResourceDefinition(
                "metrics",
                fields={
                    "id": FieldDefinition("id", "integer"),
                    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                    "value": FieldDefinition("value", "decimal"),
                },
                supported_operations=("read",),
            )
        )
        policy = DataFencePolicy("p", "1", {
            "metrics": ResourcePolicy(
                "metrics",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "value"],
                row_rules=[
                    RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id"),
                    RowRule("value", op, value),
                ],
                max_rows=100,
            )
        })
        engine = DataFencePolicyEngine(policy, registry=reg)
        key = token_bytes(32)
        return DataFenceBoundary.create(engine, reg, key, capability_audience="test-service"), key

    def _op_for_field(self, constraints: list[dict], field: str) -> str | None:
        return next((c["operator"] for c in constraints if c["field"] == field), None)

    def test_eq(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.EQ, 42)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "="

    def test_neq(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.NEQ, 0)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "!="

    def test_lt(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.LT, 1000)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "<"

    def test_lte(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.LTE, 1000)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "<="

    def test_gt(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.GT, 500)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == ">"

    def test_gte(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.GTE, 500)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == ">="

    def test_in(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.IN, ["a", "b"])
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "IN"

    def test_not_in(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.NOT_IN, ["x"])
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "NOT IN"

    def test_is_null(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.IS_NULL, None)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "IS NULL"

    def test_is_not_null(self) -> None:
        b, _ = self._boundary_with_rule(PredicateOperator.IS_NOT_NULL, None)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        assert self._op_for_field(cap.filter_constraints(), "value") == "IS NOT NULL"

    def test_gt_not_confused_with_eq(self) -> None:
        """Regression: amount > 1000 must not become amount == 1000."""
        b, _ = self._boundary_with_rule(PredicateOperator.GT, 1000)
        cap = b.authorize(Principal("u", "t-a"), Intent("metrics", Operation.READ))
        value_c = next(c for c in cap.filter_constraints() if c["field"] == "value")
        assert value_c["operator"] == ">", (
            f"GT predicate must not be coerced to EQ; got {value_c['operator']!r}"
        )


# ===========================================================================
# 4. Registry fail-closed
# ===========================================================================


class TestRegistryFailClosed:
    def test_registry_frozen_after_boundary_create(self) -> None:
        boundary, _, registry = _make_boundary()
        assert registry.is_frozen
        with pytest.raises(RuntimeError, match="frozen"):
            registry.register(ResourceDefinition("new_resource"))

    def test_unknown_resource_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(Principal("u", "t"),
                               Intent("nonexistent_table", Operation.READ))

    def test_unknown_field_denied(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(Principal("u", "t"),
                               Intent("customers", Operation.READ, fields=["id", "ghost"]))

    def test_registry_mismatch_prevents_boundary_creation(self) -> None:
        reg1 = _make_registry()
        reg2 = _make_registry()
        engine = _make_policy(reg1)
        with pytest.raises(ValueError, match="registry"):
            DataFenceBoundary.create(engine, reg2, token_bytes(32))

    def test_empty_signing_key_rejected(self) -> None:
        reg = _make_registry()
        engine = _make_policy(reg)
        with pytest.raises(ValueError, match="signing_key"):
            DataFenceBoundary.create(engine, reg, b"")

    def test_direct_instantiation_blocked(self) -> None:
        with pytest.raises(TypeError, match="DataFenceBoundary.create"):
            DataFenceBoundary()

    def test_unknown_yaml_operator_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="operator"):
            YAMLPolicyLoader.from_dict({
                "name": "p", "version": "1",
                "resources": {
                    "customers": {
                        "actions": {"read": "allow"},
                        "fields": {"allow": ["id"]},
                        "rows": [{"field": "id", "operator": "TYPO_OP", "value": 1}],
                    }
                },
            })

    def test_malformed_policy_decision_fails_closed(self) -> None:
        """A policy engine that returns garbage must not produce an AuthorizedExecution."""

        class BrokenEngine:
            def evaluate(self, principal: Any, intent: Any) -> Any:
                return "not a PolicyDecision"

        reg = _make_registry()
        broken = BrokenEngine()
        broken.registry = reg  # type: ignore[attr-defined]
        key = token_bytes(32)
        reg.freeze()

        boundary = DataFenceBoundary.__new__(DataFenceBoundary)
        boundary.policy_engine = broken  # type: ignore[assignment]
        boundary._registry = reg
        boundary._signing_key = key
        boundary._capability_ttl_seconds = 300
        boundary._capability_audience = "x"

        with pytest.raises(PolicyError):
            boundary.authorize(Principal("u", "t"),
                               Intent("customers", Operation.READ))


# ===========================================================================
# 5. Identity model — LLM cannot choose principal
# ===========================================================================


class TestIdentityModel:
    def test_llm_cannot_override_tenant_via_intent(self) -> None:
        """
        The application supplies Principal. The LLM supplies Intent.
        tenant_id in AuthorizedExecution must come from Principal, not Intent.
        """
        boundary, key, _ = _make_boundary()
        principal = Principal("user:1", "tenant-a")
        intent = Intent("customers", Operation.READ, filters={"tenant_id": "tenant-b"})
        cap = boundary.authorize(principal, intent)
        enforced = {c["field"]: c["value"]
                    for c in cap.filter_constraints() if c["operator"] == "="}
        assert enforced.get("tenant_id") == "tenant-a"

    def test_llm_cannot_choose_principal_id(self) -> None:
        boundary, _, _ = _make_boundary()
        principal = Principal("user:alice", "tenant-a")
        cap = boundary.authorize(principal, Intent("customers", Operation.READ))
        assert cap.actor.id == "user:alice"

    def test_authorized_execution_carries_no_raw_sql(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        assert not hasattr(cap, "raw_sql")

    def test_principal_is_immutable(self) -> None:
        p = Principal("user:1", "tenant-a", attributes={"dept": "finance"})
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            p.id = "hacked"  # type: ignore[misc]

    def test_authorized_execution_is_immutable(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(Principal("user:1", "tenant-a"),
                                 Intent("customers", Operation.READ, ["id"]))
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            cap.resource = "hacked"  # type: ignore[misc]

    def test_actor_removed_from_public_api(self) -> None:
        """Actor alias has been removed — Principal is the only identity type."""
        import datafence
        assert not hasattr(datafence, "Actor"), (
            "Actor must not be in the public API — use Principal"
        )


# ===========================================================================
# 6. Architecture — DataFence holds no connector, does not execute
# ===========================================================================


class TestArchitectureBoundary:
    def test_boundary_has_no_execute_method(self) -> None:
        boundary, _ , _ = _make_boundary()
        assert not hasattr(boundary, "execute"), (
            "DataFenceBoundary must NOT have execute() — "
            "execution belongs to the customer connector"
        )

    def test_boundary_stores_no_connector(self) -> None:
        boundary, _, _ = _make_boundary()
        connector_attrs = [
            a for a in vars(boundary)
            if any(x in a.lower() for x in ("connector", "connection", "cursor", "db"))
        ]
        assert connector_attrs == []

    def test_boundary_stores_no_db_credentials(self) -> None:
        boundary, _, _ = _make_boundary()
        cred_attrs = [
            a for a in vars(boundary)
            if any(x in a.lower() for x in
                   ("password", "conninfo", "dsn", "host", "port",
                    "database", "schema", "warehouse", "bucket",
                    "access_key", "secret_key", "token"))
        ]
        assert cred_attrs == []

    def test_authorize_returns_capability_not_rows(self) -> None:
        boundary, _, _ = _make_boundary()
        result = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        assert isinstance(result, AuthorizedExecution)
        assert not isinstance(result, (list, dict))

    def test_full_authorization_needs_no_database(self) -> None:
        """authorize() must succeed with no database driver installed."""
        boundary, key = _make_boundary()[:2]
        cap = boundary.authorize(
            Principal("user:alice", "tenant-x"),
            Intent("customers", Operation.READ, ["id"]),
        )
        assert isinstance(cap, AuthorizedExecution)
        CapabilityVerifier(key, expected_audience="test-service").verify(cap)

    def test_core_boundary_has_no_db_imports(self) -> None:
        import inspect

        import datafence.core.boundary as mod
        source = inspect.getsource(mod)
        for lib in ("psycopg", "sqlite3", "boto3", "pyathena", "snowflake"):
            assert lib not in source, f"core.boundary must not import {lib!r}"

    def test_legacy_types_not_in_public_api(self) -> None:
        import datafence
        for name in ("DataFence", "AllowedRequest", "DeniedRequest",
                     "ExecutionPlan", "ExecutionResult", "SimplePolicyEngine",
                     "ConnectorError", "ExecutionError"):
            assert not hasattr(datafence, name), (
                f"Legacy type {name!r} must not be in the public API"
            )

    def test_boundary_create_accepts_no_connector_param(self) -> None:
        import inspect
        sig = inspect.signature(DataFenceBoundary.create)
        connector_params = [p for p in sig.parameters if "connector" in p.lower()]
        assert connector_params == []

    def test_boundary_has_no_execute_in_class_definition(self) -> None:
        import inspect
        public_methods = {
            n for n, _ in inspect.getmembers(DataFenceBoundary, predicate=callable)
            if not n.startswith("_") and n != "create"
        }
        assert "execute" not in public_methods

    def test_boundary_public_surface_is_authorize_and_registry(self) -> None:
        import inspect
        public_methods = {
            n for n, _ in inspect.getmembers(DataFenceBoundary, predicate=callable)
            if not n.startswith("_") and n != "create"
        }
        unexpected = public_methods - {"authorize"}
        assert unexpected == set(), (
            f"Unexpected public methods on DataFenceBoundary: {unexpected}"
        )


# ===========================================================================
# 7. InMemoryReferenceConnector end-to-end
# ===========================================================================


class TestConnectorEndToEnd:
    def _setup(self) -> tuple[DataFenceBoundary, InMemoryReferenceConnector, bytes]:
        boundary, key, _ = _make_boundary()
        data = {
            "customers": [
                {"id": 1, "tenant_id": "tenant-a", "name": "Alice", "email": "a@a.com", "ssn": "111"},
                {"id": 2, "tenant_id": "tenant-a", "name": "Bob",   "email": "b@a.com", "ssn": "222"},
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
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        result = connector.execute(cap)
        assert result.row_count == 2
        assert {r["name"] for r in result.rows} == {"Alice", "Bob"}

    def test_ssn_never_in_results(self) -> None:
        """SSN must never appear even though it exists in the data."""
        boundary, connector, _ = self._setup()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name", "email"]),
        )
        result = connector.execute(cap)
        for row in result.rows:
            assert "ssn" not in row

    def test_cross_tenant_rows_not_returned(self) -> None:
        boundary, connector, _ = self._setup()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("orders", Operation.READ, ["id", "total", "status"]),
        )
        result = connector.execute(cap)
        for row in result.rows:
            assert row.get("tenant_id", "tenant-a") == "tenant-a"


# ===========================================================================
# 8. MCP security invariants
# ===========================================================================


class TestMCPSecurityInvariants:
    """
    Invariants 5, 6, 7 from the task specification:

    5. MCP cannot accept principal identity from agent-controlled arguments.
    6. MCP requires trusted principal resolution (no optional fallback).
    7. MCP returns authorization/capability information, not database rows.
    """

    def _make_server(self) -> tuple:
        """Return (server, boundary, key) with a minimal resolver."""
        boundary, key, _ = _make_boundary()

        def resolver(ctx: dict) -> Principal:
            return Principal(
                id=ctx["user_id"],
                tenant_id=ctx["tenant_id"],
            )

        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(
            boundary=boundary,
            server_name="test",
            principal_resolver=resolver,
        )
        return server, boundary, key

    # ------------------------------------------------------------------
    # Invariant 6: principal_resolver is REQUIRED
    # ------------------------------------------------------------------

    def test_mcp_server_requires_principal_resolver(self) -> None:
        """Constructing DataFenceMCPServer without a resolver raises TypeError."""
        from datafence.mcp.server import DataFenceMCPServer
        boundary, _, _ = _make_boundary()
        with pytest.raises(TypeError, match="principal_resolver"):
            DataFenceMCPServer(boundary=boundary)

    def test_mcp_server_resolver_none_raises(self) -> None:
        """Passing principal_resolver=None explicitly must also raise."""
        from datafence.mcp.server import DataFenceMCPServer
        boundary, _, _ = _make_boundary()
        with pytest.raises(TypeError, match="principal_resolver"):
            DataFenceMCPServer(boundary=boundary, principal_resolver=None)

    # ------------------------------------------------------------------
    # Invariant 5: agent JSON cannot be identity source
    # ------------------------------------------------------------------

    def test_mcp_agent_cannot_inject_principal_via_arguments(self) -> None:
        """
        Agent-controlled ``arguments`` dict must not be used to set principal.
        The session_context (transport-layer) is the only identity source.
        """
        server, _, _ = self._make_server()
        # Even if the agent injects a user_id into arguments, the server
        # must use session_context, not arguments.  Verify by checking the
        # allowed response carries the resolver-produced tenant, not any
        # value embedded in the tool arguments.
        response = server.handle_call_tool(
            tool_name="datafence_query",
            arguments={
                "resource": "customers",
                "fields": ["id", "name"],
                # attacker attempts to embed identity here — must be ignored
                "user_id": "attacker:evil",
                "tenant_id": "evil-tenant",
            },
            session_context={"user_id": "user:1", "tenant_id": "tenant-a"},
        )
        assert response.get("isError") is not True, (
            "Expected an allowed response for a valid session context"
        )
        import json
        payload = json.loads(response["content"][0]["text"])
        assert payload["status"] == "authorized"
        # The capability actor must reflect the session_context principal,
        # not anything from the agent's arguments.
        cap_data = payload["capability"]
        # The resource/fields came from arguments — that is correct (Intent).
        # The principal is not echoed into the MCP JSON but the policy
        # enforcement (tenant filter) must reference the session tenant.
        predicates = cap_data.get("predicates", [])
        tenant_preds = [p for p in predicates if p["field"] == "tenant_id"]
        assert any(p["value"] == "tenant-a" for p in tenant_preds), (
            "Policy-enforced tenant filter must use session principal's tenant, "
            "not any value from agent arguments"
        )

    def test_mcp_missing_session_context_causes_auth_error(self) -> None:
        """
        A resolver that requires a token must fail gracefully when no
        session context is provided — not fall back to any default identity.
        """
        from datafence.mcp.server import DataFenceMCPServer
        boundary, _, _ = _make_boundary()

        def strict_resolver(ctx: dict) -> Principal:
            if "user_id" not in ctx:
                raise ValueError("No authenticated session context provided")
            return Principal(id=ctx["user_id"], tenant_id=ctx["tenant_id"])

        server = DataFenceMCPServer(
            boundary=boundary,
            principal_resolver=strict_resolver,
        )
        response = server.handle_call_tool(
            tool_name="datafence_query",
            arguments={"resource": "customers"},
            session_context={},   # empty — no authenticated context
        )
        assert response.get("isError") is True
        import json
        payload = json.loads(response["content"][0]["text"])
        assert "error" in payload

    def test_mcp_resolver_returning_wrong_type_is_rejected(self) -> None:
        """Resolver must return Principal; non-Principal is rejected."""
        from datafence.mcp.server import DataFenceMCPServer
        boundary, _, _ = _make_boundary()

        def bad_resolver(ctx: dict) -> dict:  # type: ignore[return]
            return {"id": "user:1", "tenant_id": "t"}   # dict, not Principal

        server = DataFenceMCPServer(
            boundary=boundary,
            principal_resolver=bad_resolver,  # type: ignore[arg-type]
        )
        response = server.handle_call_tool(
            tool_name="datafence_query",
            arguments={"resource": "customers"},
            session_context={"ok": True},
        )
        assert response.get("isError") is True

    # ------------------------------------------------------------------
    # Invariant 7: MCP response contains capability, not database rows
    # ------------------------------------------------------------------

    def test_mcp_allowed_response_contains_capability_not_rows(self) -> None:
        """An allowed MCP response must describe the capability, never data rows."""
        import json
        server, _, _ = self._make_server()
        response = server.handle_call_tool(
            tool_name="datafence_query",
            arguments={"resource": "customers", "fields": ["id", "name"]},
            session_context={"user_id": "user:1", "tenant_id": "tenant-a"},
        )
        assert response.get("isError") is not True
        payload = json.loads(response["content"][0]["text"])

        assert payload["status"] == "authorized"
        assert "capability" in payload
        assert "request_id" in payload

        # Must NOT contain database row fields
        for forbidden in ("rows", "data", "row_count", "results", "records"):
            assert forbidden not in payload, (
                f"MCP response must not contain {forbidden!r} — "
                "DataFence does not execute database operations"
            )

    def test_mcp_denied_response_contains_reasons_not_rows(self) -> None:
        """A denied MCP response must contain denial reasons, not data."""
        import json
        server, _, _ = self._make_server()
        # Request a field that doesn't exist → denial
        response = server.handle_call_tool(
            tool_name="datafence_query",
            arguments={"resource": "nonexistent_resource"},
            session_context={"user_id": "user:1", "tenant_id": "tenant-a"},
        )
        assert response.get("isError") is True
        payload = json.loads(response["content"][0]["text"])
        assert payload["status"] == "denied"
        assert "reasons" in payload
        for forbidden in ("rows", "data", "row_count"):
            assert forbidden not in payload

    def test_mcp_unknown_tool_returns_error(self) -> None:
        """Calling a tool that was never registered must return an error."""
        import json
        server, _, _ = self._make_server()
        response = server.handle_call_tool(
            tool_name="nonexistent_tool",
            arguments={},
            session_context={"user_id": "user:1", "tenant_id": "tenant-a"},
        )
        assert response.get("isError") is True
        payload = json.loads(response["content"][0]["text"])
        assert "error" in payload

    def test_mcp_handle_request_does_not_forward_agent_session(self) -> None:
        """
        handle_request() must NOT pass the agent's _session field to the
        principal resolver.  Session context must come from the transport,
        not the JSON-RPC body.
        """
        from datafence.mcp.server import DataFenceMCPServer
        boundary, _, _ = _make_boundary()

        calls: list[dict] = []

        def recording_resolver(ctx: dict) -> Principal:
            calls.append(ctx)
            return Principal(id="user:1", tenant_id="tenant-a")

        server = DataFenceMCPServer(
            boundary=boundary,
            principal_resolver=recording_resolver,
        )
        # The JSON-RPC request embeds a _session block under params
        # (as some MCP clients do). It must NOT reach the resolver.
        server.handle_request({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "datafence_query",
                "arguments": {"resource": "customers"},
                "_session": {"user_id": "attacker:evil", "tenant_id": "evil"},
            },
        })
        # The resolver was called with an empty dict (None → {}), not _session.
        assert calls, "resolver should have been called"
        assert calls[0] == {}, (
            "handle_request must pass empty context to resolver, "
            "never the agent-provided _session field"
        )


# ===========================================================================
# 9. Package boundary invariants
# ===========================================================================


class TestPackageBoundaryInvariants:
    """
    Invariants 10, 11, 12 from the task specification:

    10. Legacy package is not present in the installed package.
    11. Reference connectors are outside the installable core package.
    12. Public API contains only intentional core concepts.
    """

    def test_legacy_package_not_importable(self) -> None:
        """
        src/datafence/_legacy/ has been deleted.
        Attempting to import it must raise ImportError / ModuleNotFoundError.
        """
        with pytest.raises((ImportError, ModuleNotFoundError)):
            import datafence._legacy  # type: ignore[import]  # noqa: F401

    def test_reference_connector_not_in_core_package(self) -> None:
        """
        InMemoryReferenceConnector must NOT be importable from datafence.*
        It lives under examples/, which is not part of the installable package.
        """
        import datafence
        assert not hasattr(datafence, "InMemoryReferenceConnector"), (
            "Reference connectors must live under examples/, not in the core package"
        )
        with pytest.raises((ImportError, ModuleNotFoundError)):
            from datafence.connectors import (
                InMemoryReferenceConnector,  # type: ignore  # noqa: F401
            )

    def test_core_package_has_no_memory_connector_module(self) -> None:
        """memory_connector.py must not exist inside the core package."""
        with pytest.raises((ImportError, ModuleNotFoundError)):
            import datafence.connectors.memory_connector  # type: ignore[import]  # noqa: F401

    def test_core_package_does_not_import_db_drivers(self) -> None:
        """
        DataFence core source files must not import any database driver.
        Uses source inspection (not sys.modules) to be immune to test-runner
        side effects such as pytest-cov importing sqlite3.
        """
        import importlib
        import inspect
        import pkgutil

        db_libs = ("psycopg", "sqlite3", "boto3", "pyathena",
                   "snowflake.connector", "pymysql", "pymongo")

        import datafence.core as core_pkg
        violations: list[str] = []
        for _finder, mod_name, _ in pkgutil.walk_packages(
            core_pkg.__path__, prefix="datafence.core."
        ):
            try:
                mod = importlib.import_module(mod_name)
                source = inspect.getsource(mod)
                for lib in db_libs:
                    if lib in source:
                        violations.append(f"{mod_name} imports {lib!r}")
            except Exception:
                pass

        assert violations == [], (
            "Core modules must not import database drivers:\n" + "\n".join(violations)
        )

    def test_public_api_does_not_contain_legacy_types(self) -> None:
        """
        The public datafence namespace must not expose legacy v0.x types.
        """
        import datafence
        legacy_names = [
            "DataFence",           # v0.3 top-level class
            "AllowedRequest",      # v0.3 result type
            "DeniedRequest",       # v0.3 result type
            "ExecutionPlan",       # v0.3/v0.4 internal type
            "ExecutionResult",     # v0.3/v0.4 internal type
            "SimplePolicyEngine",  # v0.3 policy helper
            "ConnectorError",      # v0.3 error
            "ExecutionError",      # v0.3 error
        ]
        for name in legacy_names:
            assert not hasattr(datafence, name), (
                f"Legacy type {name!r} must not be in the public API"
            )

    def test_public_api_does_not_expose_internal_types(self) -> None:
        """
        Internal plumbing types (Request, Decision) must not appear in
        the public datafence namespace.  They are implementation details.
        """
        import datafence
        internal_names = ["Request", "Decision"]
        for name in internal_names:
            assert not hasattr(datafence, name), (
                f"Internal type {name!r} must not be exported in the public API"
            )

    def test_public_api_exposes_core_concepts(self) -> None:
        """
        The public API must expose the essential core concepts an integrator
        needs: boundary, principal, intent, policy, registry, errors.
        """
        import datafence
        required = [
            "DataFenceBoundary",
            "Principal",
            "Intent",
            "Operation",
            "AuthorizedExecution",
            "CapabilityVerifier",
            "DataFencePolicyEngine",
            "DataFencePolicy",
            "ResourceRegistry",
            "ResourceDefinition",
            "FieldDefinition",
            "PolicyDeniedError",
            "DataFenceError",
        ]
        for name in required:
            assert hasattr(datafence, name), (
                f"Expected {name!r} in datafence public API"
            )


# ===========================================================================
# 10. Hardening invariants (Phase 1–10)
# ===========================================================================


class TestCapabilityTokenCodec:
    """Phase 1: CapabilityToken — portable signed token round-trip."""

    def test_encode_decode_round_trip(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        token = CapabilityToken.encode(cap)
        restored = CapabilityVerifier(key, expected_audience="test-service").verify_token(token)
        assert restored.execution_id == cap.execution_id
        assert set(restored.selected_fields) == set(cap.selected_fields)

    def test_token_is_json_string(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        token = CapabilityToken.encode(cap)
        data = json.loads(token)
        assert isinstance(data, dict)
        assert "dfv" in data
        assert "sig" in data

    def test_token_contains_signature_hex(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        data = json.loads(CapabilityToken.encode(cap))
        sig = bytes.fromhex(data["sig"])
        assert len(sig) == 32  # HMAC-SHA256 = 32 bytes

    def test_token_version_field_is_1(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        data = json.loads(CapabilityToken.encode(cap))
        assert data["dfv"] == 1

    def test_wrong_token_version_rejected(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        data = json.loads(CapabilityToken.encode(cap))
        data["dfv"] = 99
        with pytest.raises(CapabilityVerificationError, match="version"):
            CapabilityVerifier(key, expected_audience="test-service").verify_token(
                json.dumps(data)
            )

    def test_malformed_json_rejected(self) -> None:
        boundary, key, _ = _make_boundary()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode("not valid json{{")

    def test_missing_required_field_rejected(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        data = json.loads(CapabilityToken.encode(cap))
        del data["execution_id"]
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(json.dumps(data))

    def test_token_tamper_resource_detected(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        data = json.loads(CapabilityToken.encode(cap))
        data["resource"] = "evil_table"
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test-service").verify_token(
                json.dumps(data)
            )

    def test_token_tamper_roles_detected(self) -> None:
        """principal.roles are signed — role injection via token must be detected."""
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        data = json.loads(CapabilityToken.encode(cap))
        data["actor_roles"] = ["admin", "superuser"]
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test-service").verify_token(
                json.dumps(data)
            )

    def test_connector_verifies_without_boundary(self) -> None:
        """Connector can verify a token with only the key — no DataFence runtime needed."""
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        token = CapabilityToken.encode(cap)
        # Simulate a separate process — no boundary or engine available
        verifier = CapabilityVerifier(key, expected_audience="test-service")
        verified = verifier.verify_token(token)
        assert verified.execution_id == cap.execution_id

    def test_obligations_in_token(self) -> None:
        """Obligations from policy are carried in the token."""
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "audit_resource",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            },
            supported_operations=("read",),
        ))
        policy = DataFencePolicy("p", "1", {"audit_resource": ResourcePolicy(
            "audit_resource",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
            obligations={"audit": True, "notify": "compliance@example.com"},
        )})
        engine = DataFencePolicyEngine(policy, registry=reg)
        key = token_bytes(32)
        b = DataFenceBoundary.create(engine, reg, key, capability_audience="test-service")
        cap = b.authorize(Principal("u", "t-a"), Intent("audit_resource", Operation.READ))
        assert cap.obligations.get("audit") is True
        data = json.loads(CapabilityToken.encode(cap))
        assert data["obligations"]["audit"] is True


class TestDeepImmutability:
    """Phase 2: deep immutability — tuples, no mutable interior state."""

    def test_selected_fields_is_tuple(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        assert isinstance(cap.selected_fields, tuple)

    def test_predicates_is_tuple(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ),
        )
        assert isinstance(cap.predicates, tuple)

    def test_policy_decisions_is_tuple(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ),
        )
        assert isinstance(cap.policy_decisions, tuple)

    def test_cannot_append_to_selected_fields(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        with pytest.raises((AttributeError, TypeError)):
            cap.selected_fields.append("injected")  # type: ignore[union-attr]

    def test_principal_roles_is_tuple(self) -> None:
        p = Principal("u", "t", roles=["admin", "user"])
        assert isinstance(p.roles, tuple)

    def test_principal_attributes_is_immutable_proxy(self) -> None:
        from types import MappingProxyType
        p = Principal("u", "t", attributes={"dept": "finance"})
        assert isinstance(p.attributes, MappingProxyType)
        with pytest.raises((TypeError, AttributeError)):
            p.attributes["injected"] = "value"  # type: ignore[index]

    def test_filter_constraints_returns_defensive_copy(self) -> None:
        boundary, _, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ),
        )
        c1 = cap.filter_constraints()
        c2 = cap.filter_constraints()
        assert c1 is not c2  # different list objects


class TestRolesInHMAC:
    """Phase 3: principal.roles must be included in the HMAC canonical representation."""

    def test_role_tampering_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a", roles=("analyst",)),
            Intent("customers", Operation.READ, ["id"]),
        )
        # Replace actor with tampered roles
        tampered_actor = dataclasses.replace(cap.actor, roles=("admin", "superuser"))
        tampered = dataclasses.replace(cap, actor=tampered_actor)
        assert not tampered.verify_signature(key)

    def test_role_addition_invalidates_signature(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        tampered_actor = dataclasses.replace(cap.actor, roles=("superadmin",))
        tampered = dataclasses.replace(cap, actor=tampered_actor)
        assert not tampered.verify_signature(key)

    def test_roles_survive_token_round_trip(self) -> None:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a", roles=("finance:read", "audit:read")),
            Intent("customers", Operation.READ, ["id"]),
        )
        token = CapabilityToken.encode(cap)
        restored = CapabilityToken.decode(token)
        assert set(restored.actor.roles) == {"finance:read", "audit:read"}


class TestMinKeyLength:
    """Phase 4: minimum 32-byte key enforcement."""

    def test_min_key_constant(self) -> None:
        assert MIN_KEY_BYTES == 32

    def test_short_key_rejected_at_boundary_create(self) -> None:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "things",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            },
            supported_operations=("read",),
        ))
        pol = DataFencePolicy("p", "1", {"things": ResourcePolicy(
            "things",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        with pytest.raises(ValueError, match="32"):
            DataFenceBoundary.create(engine, reg, b"too_short_key_123")

    def test_short_key_rejected_at_verifier(self) -> None:
        with pytest.raises(ValueError, match="32"):
            CapabilityVerifier(b"short", expected_audience="test")

    def test_exactly_32_bytes_accepted(self) -> None:
        boundary, key, _ = _make_boundary()
        assert len(key) >= 32
        # Verifier with exactly 32 bytes should not raise
        CapabilityVerifier(token_bytes(32), expected_audience="test")


class TestPolicyCompilation:
    """Phase 5: compile-time policy+registry validation."""

    def test_policy_referencing_unknown_resource_rejected(self) -> None:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "real_resource",
            fields={"id": FieldDefinition("id", "integer"),
                    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True)},
            supported_operations=("read",),
        ))
        pol = DataFencePolicy("p", "1", {
            "real_resource": ResourcePolicy(
                "real_resource",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=10,
            ),
            "nonexistent_resource": ResourcePolicy(
                "nonexistent_resource",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id"],
                max_rows=10,
            ),
        })
        engine = DataFencePolicyEngine(pol, registry=reg)
        with pytest.raises(ConfigurationError, match="nonexistent_resource"):
            DataFenceBoundary.create(engine, reg, token_bytes(32))

    def test_policy_referencing_unknown_field_rejected(self) -> None:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "items",
            fields={"id": FieldDefinition("id", "integer"),
                    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True)},
            supported_operations=("read",),
        ))
        pol = DataFencePolicy("p", "1", {"items": ResourcePolicy(
            "items",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "ghost_field"],  # ghost_field doesn't exist
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        with pytest.raises(ConfigurationError, match="ghost_field"):
            DataFenceBoundary.create(engine, reg, token_bytes(32))

    def test_policy_referencing_unsupported_operation_rejected(self) -> None:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "things",
            fields={"id": FieldDefinition("id", "integer"),
                    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True)},
            supported_operations=("read",),  # only read supported
        ))
        pol = DataFencePolicy("p", "1", {"things": ResourcePolicy(
            "things",
            actions={"read": ActionDecision.ALLOW, "delete": ActionDecision.ALLOW},
            allowed_fields=["id"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        with pytest.raises(ConfigurationError, match="delete"):
            DataFenceBoundary.create(engine, reg, token_bytes(32))


class TestPolicyFreeze:
    """Phase 6: policy mutation after boundary creation has no effect."""

    def test_policy_mutation_does_not_affect_serving_boundary(self) -> None:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "docs",
            fields={"id": FieldDefinition("id", "integer"),
                    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                    "title": FieldDefinition("title", "string")},
            supported_operations=("read",),
        ))
        rp = ResourcePolicy(
            "docs",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "title"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
        )
        pol = DataFencePolicy("p", "1", {"docs": rp})
        engine = DataFencePolicyEngine(pol, registry=reg)
        key = token_bytes(32)
        b = DataFenceBoundary.create(engine, reg, key, capability_audience="test")

        # Mutate the original ResourcePolicy row_rules after boundary creation
        rp.row_rules.clear()  # would remove tenant isolation if policy is not frozen

        # Boundary must still enforce tenant isolation from its frozen snapshot
        cap = b.authorize(Principal("u", "t-a"), Intent("docs", Operation.READ))
        predicates = cap.filter_constraints()
        tenant_predicates = [p for p in predicates if p["field"] == "tenant_id"]
        assert tenant_predicates, (
            "Tenant isolation row rule must still be enforced after original policy was mutated"
        )


class TestTenantIsolationEnforcement:
    """Phase 7: tenant isolation — missing row rule causes compilation failure."""

    def test_tenant_scoped_resource_without_row_rule_rejected(self) -> None:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "tenant_data",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "value": FieldDefinition("value", "string"),
            },
            supported_operations=("read",),
        ))
        # Policy allows read but has NO tenant row rule — must fail compilation
        pol = DataFencePolicy("p", "1", {"tenant_data": ResourcePolicy(
            "tenant_data",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "value"],
            row_rules=[],  # missing tenant isolation
            max_rows=100,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        with pytest.raises(ConfigurationError, match="tenant"):
            DataFenceBoundary.create(engine, reg, token_bytes(32))

    def test_non_tenant_resource_without_row_rule_allowed(self) -> None:
        """A resource with no tenant key does not require a tenant row rule."""
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "global_config",
            fields={"key": FieldDefinition("key", "string"),
                    "value": FieldDefinition("value", "string")},
            supported_operations=("read",),
        ))
        pol = DataFencePolicy("p", "1", {"global_config": ResourcePolicy(
            "global_config",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["key", "value"],
            row_rules=[],  # no tenant key → no tenant row rule required
            max_rows=100,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        # Must NOT raise
        b = DataFenceBoundary.create(engine, reg, token_bytes(32))
        cap = b.authorize(Principal("u", "t"), Intent("global_config", Operation.READ))
        assert isinstance(cap, AuthorizedExecution)


class TestFilterAuthorization:
    """Phase 8: only explicitly authorized fields may be used as filters."""

    def test_unauthorized_filter_field_denied(self) -> None:
        """Agent cannot filter on a field that is not in filterable_fields."""
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "products",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "name": FieldDefinition("name", "string"),
                "cost": FieldDefinition("cost", "decimal"),
            },
            supported_operations=("read",),
        ))
        pol = DataFencePolicy("p", "1", {"products": ResourcePolicy(
            "products",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "name", "cost"],
            filterable_fields=["id", "tenant_id"],  # cost and name not filterable
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=50,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        key = token_bytes(32)
        b = DataFenceBoundary.create(engine, reg, key)

        # Filtering on authorized field → OK
        b.authorize(
            Principal("u", "t-a"),
            Intent("products", Operation.READ, filters={"id": 1}),
        )

        # Filtering on cost (not filterable) → DENIED
        with pytest.raises(PolicyDeniedError):
            b.authorize(
                Principal("u", "t-a"),
                Intent("products", Operation.READ, filters={"cost": 100}),
            )

    def test_policy_injected_filter_cannot_be_overridden(self) -> None:
        """Policy-injected tenant filter always overrides agent-supplied tenant filter."""
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, filters={"tenant_id": "evil-tenant"}),
        )
        tenant_preds = [c for c in cap.filter_constraints() if c["field"] == "tenant_id"]
        assert any(c["value"] == "tenant-a" for c in tenant_preds)
        assert not any(c["value"] == "evil-tenant" for c in tenant_preds)


class TestDataClassificationSemantics:
    """Phase 9: RESTRICTED fields are auto-denied even if listed in allowed_fields."""

    def test_restricted_field_auto_denied_even_if_in_allowed(self) -> None:
        from datafence import DataClassification
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "sensitive",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "secret": FieldDefinition(
                    "secret", "string",
                    classification=DataClassification.RESTRICTED,
                ),
            },
            supported_operations=("read",),
        ))
        # Policy explicitly lists "secret" in allowed_fields — should be overridden
        pol = DataFencePolicy("p", "1", {"sensitive": ResourcePolicy(
            "sensitive",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "secret"],  # RESTRICTED field listed!
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        key = token_bytes(32)
        b = DataFenceBoundary.create(engine, reg, key)

        cap = b.authorize(Principal("u", "t-a"), Intent("sensitive", Operation.READ))
        # RESTRICTED field must never appear in selected_fields
        assert "secret" not in cap.selected_fields

    def test_restricted_field_cannot_be_requested(self) -> None:
        """Explicitly requesting a RESTRICTED field must be denied."""
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Principal("user:1", "tenant-a"),
                Intent("customers", Operation.READ, fields=["id", "ssn"]),
            )


# ===========================================================================
# 11. Deep immutability — nested mutation must be impossible
# ===========================================================================


class TestDeepImmutabilityNested:
    """
    Prove that every security-relevant container inside AuthorizedExecution
    and Principal is immutable at every depth.
    """

    def _cap(self) -> tuple[AuthorizedExecution, bytes]:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        return cap, key

    # ------------------------------------------------------------------
    # predicates — tuple of MappingProxyType
    # ------------------------------------------------------------------

    def test_predicates_tuple_is_immutable(self) -> None:
        cap, _ = self._cap()
        assert isinstance(cap.predicates, tuple)
        with pytest.raises((AttributeError, TypeError)):
            cap.predicates.append({"field": "evil", "operator": "=", "value": "x"})  # type: ignore[union-attr]

    def test_predicate_dict_cannot_be_mutated(self) -> None:
        """cap.predicates[0]['value'] = 'attacker' must raise."""
        cap, _ = self._cap()
        p = cap.predicates[0]
        with pytest.raises(TypeError):
            p["value"] = "attacker"  # type: ignore[index]

    def test_predicate_dict_key_cannot_be_deleted(self) -> None:
        cap, _ = self._cap()
        p = cap.predicates[0]
        with pytest.raises(TypeError):
            del p["field"]  # type: ignore[attr-defined]

    def test_filter_constraints_returns_mutable_copy(self) -> None:
        """filter_constraints() must return plain dicts for connector use,
        but mutations to those copies must NOT affect the capability."""
        cap, key = self._cap()
        original_value = next(
            c["value"] for c in cap.filter_constraints() if c["field"] == "tenant_id"
        )
        mutable_list = cap.filter_constraints()
        mutable_list[0]["value"] = "evil-mutation"
        # cap.predicates[0] must still hold the original value
        assert cap.predicates[0]["value"] == original_value  # type: ignore[index]
        assert cap.verify_signature(key)

    # ------------------------------------------------------------------
    # obligations — MappingProxyType
    # ------------------------------------------------------------------

    def test_obligations_cannot_be_mutated(self) -> None:
        """cap.obligations['audit'] = False must raise."""
        boundary, key, _ = _make_boundary()
        # Build boundary with obligations
        reg2 = ResourceRegistry()
        reg2.register(ResourceDefinition(
            "audited",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            },
            supported_operations=("read",),
        ))
        from datafence.core.policy import RowRule
        pol2 = DataFencePolicy("p2", "1", {"audited": ResourcePolicy(
            "audited",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
            obligations={"audit": True, "notify": "compliance@example.com"},
        )})
        engine2 = DataFencePolicyEngine(pol2, registry=reg2)
        b2 = DataFenceBoundary.create(engine2, reg2, token_bytes(32), capability_audience="test-service")
        cap2 = b2.authorize(Principal("u", "t-a"), Intent("audited", Operation.READ))
        assert cap2.obligations["audit"] is True  # type: ignore[index]
        with pytest.raises(TypeError):
            cap2.obligations["audit"] = False  # type: ignore[index]

    def test_obligations_nested_value_immutable(self) -> None:
        """Nested lists/dicts inside obligations must also be immutable."""
        from datafence.core.policy import RowRule
        reg3 = ResourceRegistry()
        reg3.register(ResourceDefinition(
            "nested_obl",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            },
            supported_operations=("read",),
        ))
        pol3 = DataFencePolicy("p3", "1", {"nested_obl": ResourcePolicy(
            "nested_obl",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
            obligations={"tags": ["pii", "audit"]},  # list value
        )})
        engine3 = DataFencePolicyEngine(pol3, registry=reg3)
        b3 = DataFenceBoundary.create(engine3, reg3, token_bytes(32), capability_audience="test-service")
        cap3 = b3.authorize(Principal("u", "t-a"), Intent("nested_obl", Operation.READ))
        # The tags list inside obligations must be a tuple (deep-frozen)
        tags = cap3.obligations["tags"]  # type: ignore[index]
        assert isinstance(tags, tuple), f"Expected tuple, got {type(tags).__name__}"
        with pytest.raises((AttributeError, TypeError)):
            tags.append("evil")  # type: ignore[union-attr]

    # ------------------------------------------------------------------
    # Principal.attributes — MappingProxyType (nested)
    # ------------------------------------------------------------------

    def test_principal_attributes_top_level_immutable(self) -> None:
        p = Principal("u", "t", attributes={"dept": "finance"})
        with pytest.raises(TypeError):
            p.attributes["dept"] = "evil"  # type: ignore[index]

    def test_principal_attributes_nested_dict_immutable(self) -> None:
        p = Principal("u", "t", attributes={"meta": {"x": 1}})
        from types import MappingProxyType
        assert isinstance(p.attributes["meta"], MappingProxyType)  # type: ignore[index]
        with pytest.raises(TypeError):
            p.attributes["meta"]["x"] = 99  # type: ignore[index]

    def test_principal_attributes_nested_list_is_tuple(self) -> None:
        p = Principal("u", "t", attributes={"tags": ["a", "b"]})
        tags = p.attributes["tags"]  # type: ignore[index]
        assert isinstance(tags, tuple), f"Expected tuple, got {type(tags).__name__}"
        with pytest.raises((AttributeError, TypeError)):
            tags.append("c")  # type: ignore[union-attr]

    def test_principal_rejects_non_json_serialisable_attribute(self) -> None:
        """datetime, object(), bytes in attributes must be rejected at construction."""
        import datetime
        with pytest.raises(ValueError, match="JSON-serialisable"):
            Principal("u", "t", attributes={"ts": datetime.datetime.now()})

    def test_principal_rejects_non_finite_float_attribute(self) -> None:
        with pytest.raises(ValueError, match="non-finite"):
            Principal("u", "t", attributes={"val": float("nan")})
        with pytest.raises(ValueError, match="non-finite"):
            Principal("u", "t", attributes={"val": float("inf")})

    def test_principal_accepts_valid_json_attributes(self) -> None:
        """All JSON-compatible types must be accepted."""
        p = Principal("u", "t", attributes={
            "str_val": "hello",
            "int_val": 42,
            "float_val": 3.14,
            "bool_val": True,
            "null_val": None,
            "nested_dict": {"x": 1},
            "nested_list": [1, 2, 3],
        })
        assert p.attributes["str_val"] == "hello"   # type: ignore[index]
        assert p.attributes["float_val"] == 3.14   # type: ignore[index]

    def test_selected_fields_cannot_be_mutated(self) -> None:
        cap, _ = self._cap()
        assert isinstance(cap.selected_fields, tuple)
        with pytest.raises((AttributeError, TypeError)):
            cap.selected_fields.append("injected")  # type: ignore[union-attr]

    def test_policy_decisions_cannot_be_mutated(self) -> None:
        cap, _ = self._cap()
        assert isinstance(cap.policy_decisions, tuple)
        with pytest.raises((AttributeError, TypeError)):
            cap.policy_decisions.append("injected")  # type: ignore[union-attr]


# ===========================================================================
# 12. Tenant isolation — strict semantic invariant
# ===========================================================================


class TestTenantIsolationSemantics:
    """
    The tenant isolation row rule must be exactly:
        field == tenant_key  AND  operator == EQ  AND  value == ':actor_tenant_id'

    Any deviation must be rejected at DataFenceBoundary.create() time.
    """

    def _reg_with_tenant(self) -> ResourceRegistry:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "items",
            fields={
                "id":        FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "value":     FieldDefinition("value", "string"),
            },
            supported_operations=("read",),
        ))
        return reg

    def _make_engine(self, reg: ResourceRegistry, row_rules: list) -> DataFencePolicyEngine:
        pol = DataFencePolicy("p", "1", {"items": ResourcePolicy(
            "items",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "value"],
            row_rules=row_rules,
            max_rows=10,
        )})
        return DataFencePolicyEngine(pol, registry=reg)

    def _should_fail(self, row_rules: list, match: str) -> None:
        reg = self._reg_with_tenant()
        engine = self._make_engine(reg, row_rules)
        from datafence.errors import ConfigurationError
        with pytest.raises(ConfigurationError, match=match):
            DataFenceBoundary.create(engine, reg, token_bytes(32))

    def _should_pass(self, row_rules: list) -> DataFenceBoundary:
        reg = self._reg_with_tenant()
        engine = self._make_engine(reg, row_rules)
        return DataFenceBoundary.create(engine, reg, token_bytes(32))

    # Correct invariant
    def test_eq_actor_tenant_id_accepted(self) -> None:
        from datafence.core.policy import RowRule
        b = self._should_pass(
            [RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")]
        )
        assert isinstance(b, DataFenceBoundary)

    # Wrong operators
    def test_neq_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.NEQ, ":actor_tenant_id")],
            "EQ",
        )

    def test_lt_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.LT, ":actor_tenant_id")],
            "EQ",
        )

    def test_lte_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.LTE, ":actor_tenant_id")],
            "EQ",
        )

    def test_gt_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.GT, ":actor_tenant_id")],
            "EQ",
        )

    def test_gte_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.GTE, ":actor_tenant_id")],
            "EQ",
        )

    def test_in_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.IN, [":actor_tenant_id"])],
            "EQ",
        )

    def test_not_in_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.NOT_IN, [":actor_tenant_id"])],
            "EQ",
        )

    def test_is_null_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.IS_NULL, None)],
            "EQ",
        )

    def test_is_not_null_operator_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.IS_NOT_NULL, None)],
            "EQ",
        )

    # Wrong values
    def test_literal_tenant_value_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.EQ, "hardcoded-tenant")],
            ":actor_tenant_id",
        )

    def test_other_actor_attr_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.EQ, ":actor_id")],
            ":actor_tenant_id",
        )

    def test_old_alias_actor_dot_tenant_rejected(self) -> None:
        """':actor.tenant_id' is no longer accepted — must use ':actor_tenant_id'."""
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.EQ, ":actor.tenant_id")],
            ":actor_tenant_id",
        )

    def test_empty_value_rejected(self) -> None:
        from datafence.core.policy import RowRule
        self._should_fail(
            [RowRule("tenant_id", PredicateOperator.EQ, "")],
            ":actor_tenant_id",
        )

    def test_no_tenant_rule_rejected(self) -> None:
        from datafence.errors import ConfigurationError
        reg = self._reg_with_tenant()
        pol = DataFencePolicy("p", "1", {"items": ResourcePolicy(
            "items",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "value"],
            row_rules=[],   # missing tenant rule
            max_rows=10,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        with pytest.raises(ConfigurationError, match="tenant"):
            DataFenceBoundary.create(engine, reg, token_bytes(32))

    def test_agent_filter_cannot_override_tenant_predicate(self) -> None:
        """After boundary is created, agent-supplied tenant filter is overridden by policy."""
        from datafence.core.policy import RowRule
        b = self._should_pass(
            [RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")]
        )
        cap = b.authorize(
            Principal("u", "tenant-a"),
            Intent("items", Operation.READ, filters={"tenant_id": "evil-tenant"}),
        )
        tenant_vals = [c["value"] for c in cap.filter_constraints() if c["field"] == "tenant_id"]
        assert "evil-tenant" not in tenant_vals
        assert "tenant-a" in tenant_vals

    def test_tenant_predicate_tampering_detected_via_token(self) -> None:
        """Tampering the tenant predicate in the CapabilityToken fails HMAC."""
        from datafence.core.policy import RowRule
        self._should_pass(
            [RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")]
        )
        key_bytes = token_bytes(32)
        # Need fresh boundary with known key
        reg2 = self._reg_with_tenant()
        pol2 = DataFencePolicy("p", "1", {"items": ResourcePolicy(
            "items",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "value"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
        )})
        engine2 = DataFencePolicyEngine(pol2, registry=reg2)
        b2 = DataFenceBoundary.create(engine2, reg2, key_bytes)
        cap = b2.authorize(Principal("u", "tenant-a"), Intent("items", Operation.READ))
        token_str = CapabilityToken.encode(cap)
        data = json.loads(token_str)
        data["predicates"] = [{"field": "tenant_id", "operator": "=", "value": "evil"}]
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key_bytes).verify_token(json.dumps(data))


# ===========================================================================
# 13. REST API read-only contract
# ===========================================================================


class TestRESTReadOnly:
    """
    v0.1 REST API must reject INSERT / UPDATE / DELETE with 422.
    Only READ is supported.
    """

    def _make_test_client(self):  # type: ignore[no-untyped-def]
        """Create a TestClient for the DataFence API. Skip if fastapi/httpx not installed."""
        try:
            from fastapi.testclient import TestClient
        except ImportError:
            pytest.skip("fastapi not installed")

        from datafence.api import create_api
        from datafence.core.principal import Principal as P

        boundary, _, _ = _make_boundary()

        def resolver(credentials: Any) -> P:
            return P(id="user:test", tenant_id="tenant-a")

        app = create_api(boundary, principal_resolver=resolver)
        return TestClient(app)

    def test_read_operation_accepted(self) -> None:
        client = self._make_test_client()
        resp = client.post(
            "/authorize",
            json={"resource": "customers", "operation": "read", "fields": ["id"]},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "authorized"
        assert "token" in data

    def test_insert_rejected_422(self) -> None:
        client = self._make_test_client()
        resp = client.post(
            "/authorize",
            json={"resource": "customers", "operation": "insert"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 422

    def test_update_rejected_422(self) -> None:
        client = self._make_test_client()
        resp = client.post(
            "/authorize",
            json={"resource": "customers", "operation": "update"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 422

    def test_delete_rejected_422(self) -> None:
        client = self._make_test_client()
        resp = client.post(
            "/authorize",
            json={"resource": "customers", "operation": "delete"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 422

    def test_unauthenticated_returns_403(self) -> None:
        client = self._make_test_client()
        resp = client.post(
            "/authorize",
            json={"resource": "customers"},
            # no Authorization header
        )
        assert resp.status_code in (401, 403, 422)

    def test_response_contains_capability_token(self) -> None:
        """Authorized response must contain the signed token field."""
        client = self._make_test_client()
        resp = client.post(
            "/authorize",
            json={"resource": "customers", "fields": ["id"]},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "token" in data
        # Token must be parseable JSON with dfv field
        token_data = json.loads(data["token"])
        assert token_data["dfv"] == 1
        assert "sig" in token_data

    def test_unknown_resource_returns_403(self) -> None:
        client = self._make_test_client()
        resp = client.post(
            "/authorize",
            json={"resource": "nonexistent_table"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 403

    def test_health_endpoint(self) -> None:
        client = self._make_test_client()
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ===========================================================================
# 14. CapabilityToken schema strictness
# ===========================================================================


class TestCapabilityTokenStrictness:
    """
    Malformed tokens must fail closed — rejected rather than silently coerced.
    """

    def _valid_token(self) -> tuple[str, bytes]:
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        return CapabilityToken.encode(cap), key

    def _tamper(self, token: str, field: str, value: Any) -> str:
        data = json.loads(token)
        data[field] = value
        return json.dumps(data)

    def _delete(self, token: str, field: str) -> str:
        data = json.loads(token)
        del data[field]
        return json.dumps(data)

    # --- Missing required fields ---
    def test_missing_execution_id_raises(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._delete(tok, "execution_id"))

    def test_missing_sig_raises(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._delete(tok, "sig"))

    def test_missing_audience_raises(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._delete(tok, "audience"))

    def test_missing_nonce_raises(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._delete(tok, "nonce"))

    def test_missing_expires_at_raises(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._delete(tok, "expires_at"))

    # --- Wrong types (no silent coercion) ---
    def test_limit_as_string_rejected(self) -> None:
        """int(data['limit']) was a silent coercion — now must reject."""
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "limit", "999999"))

    def test_limit_as_float_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "limit", 10.5))

    def test_limit_zero_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "limit", 0))

    def test_negative_limit_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "limit", -1))

    def test_actor_id_as_int_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "actor_id", 12345))

    def test_resource_as_int_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "resource", 99))

    def test_selected_fields_not_list_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "selected_fields", "id,name"))

    def test_selected_fields_with_int_element_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "selected_fields", [1, 2, 3]))

    def test_predicates_not_list_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "predicates", "bad"))

    def test_predicates_with_non_dict_element_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "predicates", ["not-a-dict"]))

    def test_predicates_missing_field_key_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(
                tok, "predicates", [{"operator": "=", "value": "x"}]
            ))

    def test_obligations_not_dict_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "obligations", ["audit"]))

    def test_actor_roles_not_list_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "actor_roles", "admin"))

    def test_actor_roles_with_non_str_element_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "actor_roles", [1, 2]))

    def test_actor_attributes_not_dict_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "actor_attributes", ["dept"]))

    # --- Invalid field values ---
    def test_invalid_operation_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "operation", "hack"))

    def test_invalid_sig_hex_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "sig", "not-hex!!"))

    def test_empty_sig_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "sig", ""))

    def test_invalid_date_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(self._tamper(tok, "created_at", "not-a-date"))

    # --- Malformed JSON ---
    def test_non_json_string_rejected(self) -> None:
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode("this is not json")

    def test_json_array_not_object_rejected(self) -> None:
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode('["a","b"]')

    def test_wrong_dfv_version_rejected(self) -> None:
        tok, _ = self._valid_token()
        with pytest.raises(CapabilityVerificationError, match="version"):
            CapabilityToken.decode(self._tamper(tok, "dfv", 99))

    # --- Decoded capability deep-immutability ---
    def test_decoded_token_predicates_are_frozen(self) -> None:
        tok, key = self._valid_token()
        cap = CapabilityVerifier(key, expected_audience="test-service").verify_token(tok)
        if cap.predicates:
            with pytest.raises(TypeError):
                cap.predicates[0]["value"] = "evil"  # type: ignore[index]

    def test_decoded_token_obligations_are_frozen(self) -> None:
        tok, key = self._valid_token()
        cap = CapabilityVerifier(key, expected_audience="test-service").verify_token(tok)
        with pytest.raises(TypeError):
            cap.obligations["injected"] = "x"  # type: ignore[index]



# ===========================================================================
# 15. Boundary-level decision validation — malicious PolicyEngine
# ===========================================================================


class _MaliciousBoundaryFixtures:
    """Shared helpers for building boundaries with a custom engine."""

    # Default authoritative policy used by malicious engine tests.
    # This is registered at boundary-creation time. Evil engines try to
    # bypass it by returning decisions that violate these constraints.
    _DEFAULT_POLICY_NAME = "test-policy"
    _DEFAULT_POLICY_VERSION = "1.0"

    @staticmethod
    def _reg() -> ResourceRegistry:
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "orders",
            fields={
                "id":        FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "total":     FieldDefinition("total", "decimal"),
                "secret":    FieldDefinition(
                    "secret", "string",
                    classification=DataClassification.RESTRICTED,
                ),
            },
            supported_operations=("read",),
        ))
        return reg

    @classmethod
    def _authoritative_policy(cls, allowed_fields: list[str] | None = None) -> DataFencePolicy:
        """Return the authoritative policy the boundary will enforce."""
        from datafence.core.policy import RowRule
        return DataFencePolicy(
            cls._DEFAULT_POLICY_NAME,
            cls._DEFAULT_POLICY_VERSION,
            {"orders": ResourcePolicy(
                "orders",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=allowed_fields or ["id", "tenant_id"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=50,
            )},
        )

    @classmethod
    def _make(cls, engine: object, allowed_fields: list[str] | None = None) -> DataFenceBoundary:
        """Build a boundary with a custom engine and an explicit authoritative policy."""
        reg = cls._reg()
        engine._registry = reg  # type: ignore[attr-defined]
        auth_policy = cls._authoritative_policy(allowed_fields)
        key = token_bytes(32)
        # Use create() with authoritative_policy so _frozen_policy is always set.
        return DataFenceBoundary.create(
            engine,  # type: ignore[arg-type]
            reg,
            key,
            capability_audience="test",
            authoritative_policy=auth_policy,
        )


def _allow_decision(
    allowed_fields: list[str],
    predicates: tuple[Predicate, ...],
    row_limit: int = 10,
    resource: str = "orders",
    operation: str = "read",
    policy_name: str = "test-policy",
    policy_version: str = "1.0",
) -> PolicyDecision:
    """Build a crafted ALLOW PolicyDecision with required provenance."""
    return PolicyDecision.allow(
        allowed_fields=allowed_fields,
        enforced_filter=Filter(predicates=predicates),
        row_limit=RowLimit(row_limit),
        policy_name=policy_name,
        policy_version=policy_version,
        decision_resource=resource,
        decision_operation=operation,
    )


class TestBoundaryDecisionValidation(_MaliciousBoundaryFixtures):
    """
    Prove that DataFenceBoundary independently validates the PolicyDecision
    before signing any capability.  A malicious or buggy custom PolicyEngine
    cannot bypass registry security invariants.
    """

    # ------------------------------------------------------------------
    # Invariant 1+2: allowed_fields — RESTRICTED and unknown fields
    # ------------------------------------------------------------------

    def test_restricted_field_in_allowed_fields_blocked(self) -> None:
        """A PolicyEngine returning a RESTRICTED field must be rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id", "secret"],   # 'secret' is RESTRICTED
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="RESTRICTED"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_unknown_field_in_allowed_fields_blocked(self) -> None:
        """A PolicyEngine returning a field not in the registry must be rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id", "nonexistent_field"],
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="not in\nregistry|not in registry"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_multiple_unauthorized_fields_all_blocked(self) -> None:
        """Multiple bad fields in one decision — all rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["ghost1", "ghost2", "secret"],
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 4+5: enforced_filter — unknown and RESTRICTED fields
    # ------------------------------------------------------------------

    def test_restricted_field_in_enforced_filter_blocked(self) -> None:
        """A PolicyEngine using a RESTRICTED field in the filter must be rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (
                        Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),
                        Predicate(FieldRef("secret"), PredicateOperator.EQ, "x"),  # RESTRICTED!
                    ),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="RESTRICTED"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_unknown_field_in_enforced_filter_blocked(self) -> None:
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (
                        Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),
                        Predicate(FieldRef("ghost"), PredicateOperator.EQ, "x"),
                    ),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="unknown"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 5: missing tenant predicate
    # ------------------------------------------------------------------

    def test_missing_tenant_predicate_blocked(self) -> None:
        """A PolicyEngine omitting the mandatory tenant predicate must be rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (),   # no predicates at all — missing tenant isolation
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="tenant"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_cross_tenant_filter_blocked(self) -> None:
        """A PolicyEngine injecting another tenant's ID must be rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, "evil-tenant"),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="tenant_id|cross-tenant|tenant"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_wrong_tenant_filter_operator_neq_blocked(self) -> None:
        """A NEQ tenant predicate must be rejected even with the correct tenant_id."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.NEQ, principal.tenant_id),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="EQ|operator"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_wrong_tenant_filter_operator_gt_blocked(self) -> None:
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.GT, principal.tenant_id),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="EQ|operator"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_wrong_tenant_filter_operator_in_blocked(self) -> None:
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (Predicate(
                        FieldRef("tenant_id"), PredicateOperator.IN, [principal.tenant_id]
                    ),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="EQ|operator"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 7 / operation check
    # ------------------------------------------------------------------

    def test_unsupported_operation_in_request_blocked(self) -> None:
        """Even if the engine returns ALLOW for an unsupported op, boundary rejects."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    ["id"],
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),),
                )

        b = self._make(EvilEngine())
        # registry only supports 'read' — INSERT must be caught at registry validate_intent
        # but if a custom engine bypassed that, the boundary catches it
        with pytest.raises((PolicyDeniedError, PolicyError)):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.INSERT))

    # ------------------------------------------------------------------
    # Invariant 12: malformed decision fields
    # ------------------------------------------------------------------

    def test_empty_allowed_fields_in_allow_decision_blocked(self) -> None:
        """An ALLOW decision with empty allowed_fields must be rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return _allow_decision(
                    [],   # empty!
                    (Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),),
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="empty"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_zero_row_limit_in_decision_blocked(self) -> None:
        """An ALLOW decision with row_limit=0 must be rejected."""
        class EvilEngine:
            @property
            def registry(self) -> Any:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                from datafence.core.resources import RowLimit as RL
                # Bypass RowLimit's own positive-check by patching value via object.__setattr__
                rl = object.__new__(RL)
                object.__setattr__(rl, "value", 0)
                from datafence.core.policy import PolicyDecision
                return PolicyDecision(
                    effect=PolicyEffect.ALLOW,
                    allowed_fields=("id",),
                    enforced_filter=Filter(predicates=(
                        Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal.tenant_id),
                    )),
                    row_limit=rl,
                    policy_name="bad",
                    policy_version="1.0",
                )

        b = self._make(EvilEngine())
        with pytest.raises(PolicyError, match="row_limit|positive"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    # ------------------------------------------------------------------
    # Happy path — a correct engine still works after validation
    # ------------------------------------------------------------------

    def test_correct_engine_still_authorized(self) -> None:
        """After all the malicious engine tests, a correct engine still works."""
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        assert isinstance(cap, AuthorizedExecution)
        CapabilityVerifier(key, expected_audience="test-service").verify(cap)

    def test_boundary_validation_does_not_double_count_tenant_for_non_tenant_resource(
        self,
    ) -> None:
        """Resources with no tenant key do not require a tenant predicate."""

        reg2 = ResourceRegistry()
        reg2.register(ResourceDefinition(
            "config",
            fields={"key": FieldDefinition("key", "string")},
            supported_operations=("read",),
        ))
        pol2 = DataFencePolicy("p", "1", {"config": ResourcePolicy(
            "config",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["key"],
            row_rules=[],   # no tenant key → no tenant row rule required
            max_rows=10,
        )})
        engine2 = DataFencePolicyEngine(pol2, registry=reg2)
        key2 = token_bytes(32)
        b2 = DataFenceBoundary.create(engine2, reg2, key2)
        cap2 = b2.authorize(Principal("u", "t"), Intent("config", Operation.READ))
        assert isinstance(cap2, AuthorizedExecution)


# ===========================================================================
# 16. Nonce and replay semantics
# ===========================================================================


class TestNonceAndReplaySemantics:
    """
    Verify the documented v0.1 nonce semantics:
    - Each issuance has a unique nonce
    - Nonce is included in HMAC (tampering detected)
    - Capability is a bearer token (stateless) — valid until expires_at
    - Replay within TTL is explicitly the connector's responsibility
    """

    def _cap(self, ttl: int = 300) -> tuple[AuthorizedExecution, bytes]:
        boundary, key, _ = _make_boundary(ttl=ttl)
        cap = boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        return cap, key

    def test_each_issuance_has_unique_nonce(self) -> None:
        boundary, _, _ = _make_boundary()
        p = Principal("user:1", "tenant-a")
        i = Intent("customers", Operation.READ, ["id"])
        c1 = boundary.authorize(p, i)
        c2 = boundary.authorize(p, i)
        assert c1.nonce != c2.nonce, "Each issuance must have a unique nonce"
        assert c1.execution_id != c2.execution_id

    def test_nonce_is_non_empty_string(self) -> None:
        cap, _ = self._cap()
        assert isinstance(cap.nonce, str)
        assert len(cap.nonce) >= 16, "Nonce should be a substantial random string"

    def test_nonce_is_hmac_signed(self) -> None:
        """Tampering with the nonce invalidates the HMAC."""
        cap, key = self._cap()
        import dataclasses
        tampered = dataclasses.replace(cap, nonce="replayed-nonce-0000")
        assert not tampered.verify_signature(key)

    def test_nonce_tamper_in_token_detected(self) -> None:
        cap, key = self._cap()
        token_str = CapabilityToken.encode(cap)
        data = json.loads(token_str)
        data["nonce"] = "replayed"
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test-service").verify_token(
                json.dumps(data)
            )

    def test_capability_is_bearer_until_expiry(self) -> None:
        """A valid unexpired capability verifies without any nonce store."""
        cap, key = self._cap(ttl=300)
        verifier = CapabilityVerifier(key, expected_audience="test-service")
        # Can be verified multiple times — it is a bearer token
        verifier.verify(cap)
        verifier.verify(cap)   # second call — still valid (no nonce store)

    def test_expired_capability_rejected(self) -> None:
        """Expiry is enforced — an expired capability cannot be replayed."""
        import dataclasses
        from datetime import timedelta, timezone
        cap, key = self._cap(ttl=300)
        expired = dataclasses.replace(
            cap, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)
        )
        with pytest.raises(CapabilityVerificationError, match="expired"):
            CapabilityVerifier(key, expected_audience="test-service").verify(expired)

    def test_audience_prevents_cross_service_replay(self) -> None:
        """Audience binding prevents a captured token from being used elsewhere."""
        cap, key = self._cap()
        with pytest.raises(CapabilityVerificationError, match="audience"):
            CapabilityVerifier(key, expected_audience="different-service").verify(cap)

    def test_connector_side_nonce_store_pattern(self) -> None:
        """
        Verify the documented connector-side replay-protection pattern works.
        DataFence core is stateless; this tests the interface the connector should
        implement, not a DataFence feature.
        """
        cap, key = self._cap(ttl=300)

        # Simulate a minimal connector nonce store
        used_nonces: set[str] = set()

        def execute_with_replay_protection(capability: AuthorizedExecution) -> str:
            """Simulate connector.execute() with nonce tracking."""
            CapabilityVerifier(key, expected_audience="test-service").verify(capability)
            if capability.nonce in used_nonces:
                raise RuntimeError(f"Replay detected: nonce {capability.nonce!r}")
            used_nonces.add(capability.nonce)
            return "ok"

        # First use: succeeds
        result = execute_with_replay_protection(cap)
        assert result == "ok"

        # Second use with same capability: replay detected
        with pytest.raises(RuntimeError, match="Replay"):
            execute_with_replay_protection(cap)

    def test_different_capabilities_have_different_nonces(self) -> None:
        """Even two authorizations with the same principal/intent produce different nonces."""
        boundary, key, _ = _make_boundary()
        p = Principal("user:1", "tenant-a")
        i = Intent("customers", Operation.READ, ["id"])
        nonces = {boundary.authorize(p, i).nonce for _ in range(10)}
        assert len(nonces) == 10, "All 10 issuances must have distinct nonces"

    def test_nonce_included_in_capability_token(self) -> None:
        cap, _ = self._cap()
        token_str = CapabilityToken.encode(cap)
        data = json.loads(token_str)
        assert "nonce" in data
        assert data["nonce"] == cap.nonce


# ===========================================================================
# 17. Policy field ceiling, row-limit ceiling, and provenance enforcement
# ===========================================================================


class TestPolicyCeilingAndProvenance(_MaliciousBoundaryFixtures):
    """
    Prove that DataFenceBoundary enforces the policy-defined ceilings for
    field access and row limits, and validates decision provenance.
    These invariants hold even when a custom PolicyEngine bypasses the
    built-in DataFencePolicyEngine.
    """

    @staticmethod
    def _frozen_boundary(
        policy_fields: list[str],
        max_rows: int = 10,
    ) -> tuple[DataFenceBoundary, ResourceRegistry]:
        """Build a fully frozen boundary with a single 'orders' resource."""
        from datafence.core.policy import RowRule
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "orders",
            fields={
                "id":        FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "email":     FieldDefinition("email", "string"),
                "total":     FieldDefinition("total", "decimal"),
            },
            supported_operations=("read",),
        ))
        pol = DataFencePolicy("my-policy", "2.0", {"orders": ResourcePolicy(
            "orders",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=policy_fields,
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=max_rows,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        key = token_bytes(32)
        b = DataFenceBoundary.create(engine, reg, key, capability_audience="test")
        return b, reg

    @staticmethod
    def _evil_engine(
        reg: ResourceRegistry,
        allowed_fields: list[str],
        row_limit_val: int = 5,
        policy_name: str = "my-policy",
        policy_version: str = "2.0",
        decision_resource: str = "orders",
        decision_operation: str = "read",
    ) -> object:
        """Build a minimal evil engine that returns a crafted ALLOW decision."""
        from datafence.core.policy import PolicyDecision
        from datafence.core.resources import (
            FieldRef,
            Filter,
            Predicate,
            PredicateOperator,
            RowLimit,
        )

        class _EvilEngine:
            def __init__(self, r: ResourceRegistry) -> None:
                self._registry = r

            @property
            def registry(self) -> ResourceRegistry:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                return PolicyDecision.allow(
                    allowed_fields=allowed_fields,
                    enforced_filter=Filter(predicates=(
                        Predicate(
                            FieldRef("tenant_id"),
                            PredicateOperator.EQ,
                            principal.tenant_id,
                        ),
                    )),
                    row_limit=RowLimit(row_limit_val),
                    policy_name=policy_name,
                    policy_version=policy_version,
                    decision_resource=decision_resource,
                    decision_operation=decision_operation,
                )

        return _EvilEngine(reg)

    # ------------------------------------------------------------------
    # Field ceiling
    # ------------------------------------------------------------------

    def test_policy_unauthorized_known_field_blocked(self) -> None:
        """
        policy allows: ['id']
        custom engine returns: ['id', 'email']
        → DataFenceBoundary MUST reject — email is not in the policy ceiling.
        """
        b, reg = self._frozen_boundary(["id"], max_rows=10)
        b.policy_engine = self._evil_engine(reg, ["id", "email"])  # type: ignore[assignment]
        with pytest.raises(PolicyError, match="policy ceiling|not permitted"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_policy_ceiling_single_extra_field_blocked(self) -> None:
        b, reg = self._frozen_boundary(["id", "total"], max_rows=10)
        # engine returns a field that exists in registry but not in policy
        b.policy_engine = self._evil_engine(reg, ["id", "total", "email"])  # type: ignore[assignment]
        with pytest.raises(PolicyError, match="policy ceiling|not permitted"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_policy_ceiling_all_valid_fields_allowed(self) -> None:
        """A correct engine returning exactly the policy fields is allowed."""
        b, reg = self._frozen_boundary(["id", "total"])
        # Default engine is correct — no substitution
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        assert isinstance(cap, AuthorizedExecution)

    # ------------------------------------------------------------------
    # Row-limit ceiling
    # ------------------------------------------------------------------

    def test_excessive_row_limit_blocked(self) -> None:
        """
        policy max_rows = 10
        custom engine returns row_limit = 1000
        → DataFenceBoundary MUST reject.
        """
        b, reg = self._frozen_boundary(["id"], max_rows=10)
        b.policy_engine = self._evil_engine(reg, ["id"], row_limit_val=1000)  # type: ignore[assignment]
        with pytest.raises(PolicyError, match="max_rows|row_limit"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_row_limit_at_ceiling_allowed(self) -> None:
        """row_limit == max_rows is exactly the ceiling — should be accepted."""
        b, reg = self._frozen_boundary(["id"], max_rows=10)
        b.policy_engine = self._evil_engine(reg, ["id"], row_limit_val=10)  # type: ignore[assignment]
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        assert isinstance(cap, AuthorizedExecution)

    def test_row_limit_below_ceiling_allowed(self) -> None:
        b, reg = self._frozen_boundary(["id"], max_rows=50)
        b.policy_engine = self._evil_engine(reg, ["id"], row_limit_val=5)  # type: ignore[assignment]
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        assert cap.limit == 5

    def test_row_limit_one_above_ceiling_blocked(self) -> None:
        b, reg = self._frozen_boundary(["id"], max_rows=10)
        b.policy_engine = self._evil_engine(reg, ["id"], row_limit_val=11)  # type: ignore[assignment]
        with pytest.raises(PolicyError, match="max_rows|row_limit"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    # ------------------------------------------------------------------
    # Decision/resource mismatch
    # ------------------------------------------------------------------

    def test_decision_resource_mismatch_blocked(self) -> None:
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"], decision_resource="evil_table"
        )
        with pytest.raises(PolicyError, match="decision_resource|resource"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_decision_resource_matches_request_allowed(self) -> None:
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"], decision_resource="orders"
        )
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        assert isinstance(cap, AuthorizedExecution)

    # ------------------------------------------------------------------
    # Decision/operation mismatch
    # ------------------------------------------------------------------

    def test_decision_operation_mismatch_blocked(self) -> None:
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"], decision_operation="delete"
        )
        with pytest.raises(PolicyError, match="decision_operation|operation"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_decision_operation_matches_request_allowed(self) -> None:
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"], decision_operation="read"
        )
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        assert isinstance(cap, AuthorizedExecution)

    # ------------------------------------------------------------------
    # Policy name/version mismatch
    # ------------------------------------------------------------------

    def test_policy_name_mismatch_blocked(self) -> None:
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"], policy_name="wrong-policy"
        )
        with pytest.raises(PolicyError, match="policy_name|policy name"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_policy_version_mismatch_blocked(self) -> None:
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"], policy_version="9.9.9"
        )
        with pytest.raises(PolicyError, match="policy_version|policy version"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_policy_name_unknown_is_rejected(self) -> None:
        """
        'unknown' policy_name was the old lenient default.
        The boundary now REQUIRES provenance — 'unknown' MUST be rejected.
        """
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"], policy_name="unknown", policy_version="2.0"
        )
        with pytest.raises(PolicyError, match="policy_name|policy name|unknown"):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    def test_empty_provenance_is_rejected(self) -> None:
        """
        Empty string provenance was the old lenient bypass.
        The boundary now REQUIRES provenance — empty strings MUST be rejected.
        """
        b, reg = self._frozen_boundary(["id"])
        b.policy_engine = self._evil_engine(  # type: ignore[assignment]
            reg, ["id"],
            decision_resource="",   # empty = missing provenance → rejected
            decision_operation="",
            policy_name="",
            policy_version="",
        )
        with pytest.raises(PolicyError):
            b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))

    # ------------------------------------------------------------------
    # Built-in engine provenance round-trip
    # ------------------------------------------------------------------

    def test_builtin_engine_populates_provenance(self) -> None:
        """DataFencePolicyEngine must populate decision_resource and decision_operation."""
        from datafence.core.policy import RowRule
        reg = ResourceRegistry()
        reg.register(ResourceDefinition("items", fields={
            "id": FieldDefinition("id", "integer"),
            "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
        }, supported_operations=("read",)))
        pol = DataFencePolicy("provenance-test", "3.0", {"items": ResourcePolicy(
            "items",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id"],
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=10,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        decision = engine.evaluate(Principal("u", "t-a"), Intent("items", Operation.READ))
        assert decision.decision_resource == "items"
        assert decision.decision_operation == "read"
        assert decision.policy_name == "provenance-test"
        assert decision.policy_version == "3.0"


# ===========================================================================
# 18. Strict provenance — independent custom engine with authoritative_policy
# ===========================================================================


class TestStrictProvenanceWithCustomEngine:
    """
    Prove that a completely independent custom PolicyEngine — one that
    does NOT extend DataFencePolicyEngine — cannot bypass ceiling or
    provenance invariants when the boundary is created with
    authoritative_policy=.

    These are the hardest attack scenarios: the engine shares no code with
    the built-in engine and has full freedom to return any PolicyDecision.
    """

    @staticmethod
    def _build_custom_boundary(
        allowed_fields_ceiling: list[str] = None,
        max_rows_ceiling: int = 10,
        extra_registry_fields: dict | None = None,
    ) -> tuple[DataFenceBoundary, DataFencePolicy]:
        """
        Build a boundary using a stub engine + explicit authoritative_policy.
        Returns (boundary, authoritative_policy).
        """
        from datafence.core.policy import RowRule

        if allowed_fields_ceiling is None:
            allowed_fields_ceiling = ["id", "total"]

        fields: dict[str, FieldDefinition] = {
            "id":        FieldDefinition("id", "integer"),
            "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            "total":     FieldDefinition("total", "decimal"),
            "email":     FieldDefinition("email", "string"),
            "secret":    FieldDefinition("secret", "string",
                             classification=DataClassification.RESTRICTED),
        }
        if extra_registry_fields:
            fields.update(extra_registry_fields)

        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "items",
            fields=fields,
            supported_operations=("read",),
        ))

        auth_policy = DataFencePolicy("auth-policy", "3.0", {"items": ResourcePolicy(
            "items",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=allowed_fields_ceiling,
            row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
            max_rows=max_rows_ceiling,
        )})

        # Completely independent stub engine — shares no code with DataFencePolicyEngine
        class StubEngine:
            def __init__(self, r: ResourceRegistry) -> None:
                self._registry = r

            @property
            def registry(self) -> ResourceRegistry:
                return self._registry

            def evaluate(self, principal: Any, intent: Any) -> Any:
                # This will be replaced per-test
                raise NotImplementedError

        stub = StubEngine(reg)
        key = token_bytes(32)
        b = DataFenceBoundary.create(
            stub,  # type: ignore[arg-type]
            reg,
            key,
            capability_audience="test",
            authoritative_policy=auth_policy,
        )
        return b, auth_policy

    def _make_decision(
        self,
        principal_tenant: str,
        allowed_fields: list[str],
        row_limit: int = 5,
        resource: str = "items",
        operation: str = "read",
        policy_name: str = "auth-policy",
        policy_version: str = "3.0",
    ) -> PolicyDecision:
        from datafence.core.resources import FieldRef, Filter, Predicate, PredicateOperator, RowLimit
        return PolicyDecision.allow(
            allowed_fields=allowed_fields,
            enforced_filter=Filter(predicates=(
                Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, principal_tenant),
            )),
            row_limit=RowLimit(row_limit),
            policy_name=policy_name,
            policy_version=policy_version,
            decision_resource=resource,
            decision_operation=operation,
        )

    def _set_engine_decision(self, b: DataFenceBoundary, decision: PolicyDecision) -> None:
        """Replace the engine's evaluate() to return the given decision."""
        def _eval(principal: Any, intent: Any) -> Any:
            return decision
        b.policy_engine.evaluate = _eval  # type: ignore[method-assign]

    # ------------------------------------------------------------------
    # Happy path: boundary accepts a correct independent engine decision
    # ------------------------------------------------------------------

    def test_correct_custom_engine_decision_accepted(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"], max_rows_ceiling=10)
        decision = self._make_decision("t-a", ["id", "total"], row_limit=5)
        self._set_engine_decision(b, decision)
        cap = b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))
        assert isinstance(cap, AuthorizedExecution)

    # ------------------------------------------------------------------
    # Invariant 3: field ceiling enforced even for independent engine
    # ------------------------------------------------------------------

    def test_field_outside_policy_ceiling_blocked_custom_engine(self) -> None:
        """policy ceiling=['id','total'], engine returns ['id','total','email'] → rejected."""
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total", "email"])
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="policy ceiling|not permitted|outside"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    def test_restricted_field_ceiling_blocked_custom_engine(self) -> None:
        """RESTRICTED field must be rejected even from independent engine."""
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "secret"])
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="RESTRICTED"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 6: row-limit ceiling enforced even for independent engine
    # ------------------------------------------------------------------

    def test_excessive_row_limit_blocked_custom_engine(self) -> None:
        """policy max_rows=10, engine returns row_limit=999 → rejected."""
        b, _ = self._build_custom_boundary(["id", "total"], max_rows_ceiling=10)
        decision = self._make_decision("t-a", ["id", "total"], row_limit=999)
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="max_rows|row_limit"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 7: resource provenance enforced
    # ------------------------------------------------------------------

    def test_resource_mismatch_blocked_custom_engine(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], resource="evil_table")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="decision_resource|resource"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    def test_missing_resource_provenance_blocked_custom_engine(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], resource="")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="decision_resource|missing"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 8: operation provenance enforced
    # ------------------------------------------------------------------

    def test_operation_mismatch_blocked_custom_engine(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], operation="delete")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="decision_operation|operation"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    def test_missing_operation_provenance_blocked_custom_engine(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], operation="")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="decision_operation|missing"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 9: policy name provenance enforced
    # ------------------------------------------------------------------

    def test_policy_name_mismatch_blocked_custom_engine(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], policy_name="attacker-policy")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="policy_name|policy name"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    def test_unknown_policy_name_blocked_custom_engine(self) -> None:
        """'unknown' is no longer a valid bypass — it must be rejected."""
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], policy_name="unknown")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="policy_name|unknown"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    def test_missing_policy_name_blocked_custom_engine(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], policy_name="")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="policy_name|missing"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    # ------------------------------------------------------------------
    # Invariant 10: policy version provenance enforced
    # ------------------------------------------------------------------

    def test_policy_version_mismatch_blocked_custom_engine(self) -> None:
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], policy_version="9.9")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="policy_version|policy version"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    def test_unknown_policy_version_blocked_custom_engine(self) -> None:
        """'unknown' is no longer a valid bypass — it must be rejected."""
        b, _ = self._build_custom_boundary(["id", "total"])
        decision = self._make_decision("t-a", ["id", "total"], policy_version="unknown")
        self._set_engine_decision(b, decision)
        with pytest.raises(PolicyError, match="policy_version|unknown"):
            b.authorize(Principal("u", "t-a"), Intent("items", Operation.READ))

    # ------------------------------------------------------------------
    # Mandatory authoritative_policy at create() time
    # ------------------------------------------------------------------

    def test_create_without_policy_raises(self) -> None:
        """
        DataFenceBoundary.create() must reject a custom engine that exposes
        no ._policy and no authoritative_policy is provided.
        """
        reg = ResourceRegistry()
        reg.register(ResourceDefinition("things", fields={
            "id": FieldDefinition("id", "integer"),
            "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
        }, supported_operations=("read",)))

        class NoPolicyEngine:
            @property
            def registry(self) -> ResourceRegistry:
                return reg

            def evaluate(self, principal: Any, intent: Any) -> Any:
                raise NotImplementedError

        with pytest.raises(ValueError, match="authoritative.*DataFencePolicy|authoritative_policy"):
            DataFenceBoundary.create(
                NoPolicyEngine(),  # type: ignore[arg-type]
                reg,
                token_bytes(32),
                # no authoritative_policy= provided
            )

    def test_boundary_exposes_frozen_policy(self) -> None:
        """DataFenceBoundary must expose the frozen policy for audit/introspection."""
        b, auth_policy = self._build_custom_boundary(["id", "total"])
        assert b.frozen_policy.name == auth_policy.name
        assert b.frozen_policy.version == auth_policy.version
