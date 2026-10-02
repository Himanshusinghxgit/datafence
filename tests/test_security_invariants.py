"""
DataFence security invariant tests.

These tests prove the critical security properties of DataFence:

    1.  Authorization — allow/deny correctness
    2.  Capability integrity — HMAC covers every security-relevant field
    3.  Predicate losslessness — all operators survive the full pipeline
    4.  Registry validation — fail-closed on unknown resources / fields / ops
    5.  Identity model — LLM cannot choose or override the principal
    6.  Architecture — DataFence does not execute data, holds no connector
    7.  Connector end-to-end — InMemoryReferenceConnector enforces all rules

A failing test is a security regression.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timedelta, timezone
from secrets import token_bytes
from typing import Any

import pytest

from datafence import (
    ActionDecision,
    AuthorizedExecution,
    CapabilityVerifier,
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
from datafence.connectors.memory_connector import InMemoryReferenceConnector
from datafence.core.capability import CapabilityVerificationError
from datafence.core.resources import PredicateOperator
from datafence.errors import PolicyDeniedError, PolicyError

# Actor alias must still work
from datafence import Actor


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
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id", "name"]),
        )
        assert isinstance(cap, AuthorizedExecution)
        assert cap.resource == "customers"
        assert "id" in cap.selected_fields
        assert "name" in cap.selected_fields

    def test_actor_alias_also_works(self) -> None:
        """Actor is a backward-compatibility alias — must work identically to Principal."""
        boundary, key, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("customers", Operation.READ, ["id"]),
        )
        assert isinstance(cap, AuthorizedExecution)

    def test_denied_operation_raises(self) -> None:
        boundary, _, _ = _make_boundary()
        with pytest.raises(PolicyDeniedError):
            boundary.authorize(
                Principal("user:1", "tenant-a"),
                Intent("customers", Operation.DELETE),
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
        assert not dataclasses.replace(cap, operation=Operation.DELETE).verify_signature(key)

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
            enforced_predicates=[{"field": "tenant_id", "operator": "=", "value": "tenant-b"}],
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

    def test_principal_and_actor_are_the_same_type(self) -> None:
        """Actor is a backward-compatibility alias for Principal."""
        from datafence import Actor, Principal
        assert Actor is Principal


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
