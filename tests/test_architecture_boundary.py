"""
Architecture boundary tests.

These tests prove structural properties independent of any specific
authorization scenario. They answer: is the ownership boundary enforced in code?

Groups:
    A. DataFenceBoundary structural contract
    B. No legacy execution path
    C. Capability round-trip serialization (with CapabilityToken)
    D. Tamper detection after serialization
"""

from __future__ import annotations

import dataclasses
import inspect
import json
import sys
from pathlib import Path
from secrets import token_bytes
from typing import Any

import pytest

from datafence import (
    AuthorizedExecution,
    CapabilityToken,
    CapabilityVerificationError,
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
)
from datafence.core.policy import ActionDecision, RowRule
from datafence.core.resources import PredicateOperator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_boundary() -> tuple[DataFenceBoundary, bytes]:
    reg = ResourceRegistry()
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
    pol = DataFencePolicy(
        "p",
        "1.0",
        {
            "orders": ResourcePolicy(
                "orders",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "total", "status"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=100,
            )
        },
    )
    engine = DataFencePolicyEngine(pol, registry=reg)
    key = token_bytes(32)
    return DataFenceBoundary.create(engine, reg, key, capability_audience="test"), key


# ===========================================================================
# A. Structural contract
# ===========================================================================


class TestBoundaryStructuralContract:
    def test_has_authorize(self) -> None:
        b, _ = _make_boundary()
        assert callable(getattr(b, "authorize", None))

    def test_no_execute(self) -> None:
        b, _ = _make_boundary()
        assert not hasattr(b, "execute")

    def test_no_connector_stored(self) -> None:
        b, _ = _make_boundary()
        bad = [a for a in vars(b) if "connector" in a.lower() or "connection" in a.lower()]
        assert bad == []

    def test_authorize_returns_capability(self) -> None:
        b, _ = _make_boundary()
        r = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        assert isinstance(r, AuthorizedExecution)
        assert not isinstance(r, (list, dict))

    def test_authorize_needs_no_database(self) -> None:
        b, key = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        CapabilityVerifier(key, expected_audience="test").verify(cap)

    def test_boundary_source_has_no_db_imports(self) -> None:
        import datafence.core.boundary as mod

        src = inspect.getsource(mod)
        for lib in ("psycopg", "sqlite3", "boto3", "pyathena", "snowflake"):
            assert lib not in src

    def test_direct_instantiation_raises(self) -> None:
        with pytest.raises(TypeError):
            DataFenceBoundary()

    def test_registry_frozen_after_create(self) -> None:
        b, _ = _make_boundary()
        assert b.registry.is_frozen
        with pytest.raises(RuntimeError):
            b.registry.register(ResourceDefinition("new"))

    def test_only_authorize_is_public(self) -> None:
        public = {
            n
            for n, _ in inspect.getmembers(DataFenceBoundary, predicate=callable)
            if not n.startswith("_") and n != "create"
        }
        assert public == {"authorize"}

    def test_create_has_no_connector_param(self) -> None:
        sig = inspect.signature(DataFenceBoundary.create)
        assert not any("connector" in p.lower() for p in sig.parameters)

    def test_weak_key_rejected(self) -> None:
        """Keys shorter than 32 bytes must be rejected."""
        reg = ResourceRegistry()
        reg.register(
            ResourceDefinition(
                "orders",
                fields={
                    "id": FieldDefinition("id", "integer"),
                    "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                },
                supported_operations=("read",),
            )
        )
        pol = DataFencePolicy(
            "p",
            "1",
            {
                "orders": ResourcePolicy(
                    "orders",
                    actions={"read": ActionDecision.ALLOW},
                    allowed_fields=["id"],
                    row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                    max_rows=10,
                )
            },
        )
        engine = DataFencePolicyEngine(pol, registry=reg)
        with pytest.raises(ValueError, match="32"):
            DataFenceBoundary.create(engine, reg, b"short")


# ===========================================================================
# B. No legacy execution path
# ===========================================================================


class TestNoLegacyExecution:
    def test_no_legacy_datafence_class(self) -> None:
        import datafence

        assert not hasattr(datafence, "DataFence")

    def test_no_actor_in_public_api(self) -> None:
        """Actor alias has been removed."""
        import datafence

        assert not hasattr(datafence, "Actor")

    def test_no_execute_plan(self) -> None:
        b, _ = _make_boundary()
        assert not hasattr(b, "execute_plan")

    def test_no_allowed_request(self) -> None:
        import datafence

        assert not hasattr(datafence, "AllowedRequest")

    def test_no_denied_request(self) -> None:
        import datafence

        assert not hasattr(datafence, "DeniedRequest")

    def test_no_execution_plan(self) -> None:
        import datafence

        assert not hasattr(datafence, "ExecutionPlan")

    def test_no_execution_result(self) -> None:
        import datafence

        assert not hasattr(datafence, "ExecutionResult")

    def test_no_raw_sql_on_capability(self) -> None:
        b, _ = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        assert not hasattr(cap, "raw_sql")

    def test_no_enforced_filters_on_capability(self) -> None:
        """Single predicates field only; enforced_filters was removed."""
        b, _ = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        assert not hasattr(cap, "enforced_filters")
        assert hasattr(cap, "predicates")

    def test_decision_not_in_public_api(self) -> None:
        import datafence

        assert not hasattr(datafence, "Decision")

    def test_request_not_in_public_api(self) -> None:
        import datafence

        assert not hasattr(datafence, "Request")

    def test_capability_fields_are_tuples(self) -> None:
        """Deep immutability: selected_fields and predicates are tuples."""
        b, _ = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        assert isinstance(cap.selected_fields, tuple)
        assert isinstance(cap.predicates, tuple)
        assert isinstance(cap.policy_decisions, tuple)

    def test_capability_selected_fields_immutable(self) -> None:
        """selected_fields is a tuple — no append possible."""
        b, _ = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        with pytest.raises((AttributeError, TypeError)):
            cap.selected_fields.append("injected")  # type: ignore[union-attr]


# ===========================================================================
# C. Capability serialization round-trip via CapabilityToken
# ===========================================================================


class TestCapabilityRoundTrip:
    def test_round_trip_preserves_signature(self) -> None:
        b, key = _make_boundary()
        original = b.authorize(
            Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id", "total"])
        )
        token = CapabilityToken.encode(original)
        restored = CapabilityVerifier(key, expected_audience="test").verify_token(token)
        assert restored.execution_id == original.execution_id

    def test_token_includes_signature(self) -> None:
        b, _ = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        token_str = CapabilityToken.encode(cap)
        data = json.loads(token_str)
        assert "sig" in data
        assert len(data["sig"]) == 64  # 32 bytes = 64 hex chars

    def test_token_has_version(self) -> None:
        b, _ = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        data = json.loads(CapabilityToken.encode(cap))
        assert data["dfv"] == 1

    def test_token_includes_roles(self) -> None:
        b, _ = _make_boundary()
        cap = b.authorize(
            Principal("u:1", "t-a", roles=("finance:read",)),
            Intent("orders", Operation.READ, ["id"]),
        )
        data = json.loads(CapabilityToken.encode(cap))
        assert data["actor_roles"] == ["finance:read"]

    def test_round_trip_preserves_all_fields(self) -> None:
        b, key = _make_boundary()
        original = b.authorize(
            Principal("u:alice", "t-acme"), Intent("orders", Operation.READ, ["id", "status"])
        )
        token = CapabilityToken.encode(original)
        restored = CapabilityToken.decode(token)
        assert restored.execution_id == original.execution_id
        assert restored.actor.id == original.actor.id
        assert restored.actor.tenant_id == original.actor.tenant_id
        assert set(restored.selected_fields) == set(original.selected_fields)
        assert restored.resource == original.resource
        assert restored.operation == original.operation
        assert restored.limit == original.limit
        assert restored.policy_version == original.policy_version
        assert restored.audience == original.audience
        assert restored.nonce == original.nonce
        assert restored.signature == original.signature

    def test_round_trip_preserves_predicates(self) -> None:
        b, key = _make_boundary()
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        token = CapabilityToken.encode(cap)
        restored = CapabilityToken.decode(token)
        # Tenant predicate must survive round-trip
        assert any(p["field"] == "tenant_id" for p in restored.filter_constraints())

    def test_malformed_token_raises(self) -> None:
        from datafence.core.capability import CapabilityVerificationError

        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode("not-json")

    def test_wrong_version_rejected(self) -> None:
        from datafence.core.capability import CapabilityVerificationError

        b, _ = _make_boundary()
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        data = json.loads(CapabilityToken.encode(cap))
        data["dfv"] = 999
        with pytest.raises(CapabilityVerificationError, match="version"):
            CapabilityToken.decode(json.dumps(data))

    def test_missing_sig_field_raises(self) -> None:
        from datafence.core.capability import CapabilityVerificationError

        b, _ = _make_boundary()
        cap = b.authorize(Principal("u", "t-a"), Intent("orders", Operation.READ))
        data = json.loads(CapabilityToken.encode(cap))
        del data["sig"]
        with pytest.raises(CapabilityVerificationError):
            CapabilityToken.decode(json.dumps(data))

    def test_connector_can_verify_without_datafence_runtime(self) -> None:
        """The connector needs only the signing key — no DataFence boundary object."""
        b, key = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        token = CapabilityToken.encode(cap)

        # Simulate a separate process — no boundary object available
        del b

        verifier = CapabilityVerifier(key, expected_audience="test")
        restored = verifier.verify_token(token)
        assert restored.execution_id == cap.execution_id


# ===========================================================================
# D. Tamper detection
# ===========================================================================


class TestTamperDetection:
    def _cap_and_key(self) -> tuple[AuthorizedExecution, bytes, str]:
        b, key = _make_boundary()
        cap = b.authorize(
            Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id", "total"])
        )
        token = CapabilityToken.encode(cap)
        return cap, key, token

    def _tamper_token(self, token: str, field: str, value: Any) -> str:
        data = json.loads(token)
        data[field] = value
        return json.dumps(data)

    def _assert_tamper_fails(self, token: str, field: str, value: Any, key: bytes) -> None:
        tampered = self._tamper_token(token, field, value)
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test").verify_token(tampered)

    def test_resource(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "resource", "secret_table", key)

    def test_operation(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "operation", "delete", key)

    def test_fields(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "selected_fields", ["id", "total", "ssn"], key)

    def test_limit(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "limit", 999999, key)

    def test_tenant(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "actor_tenant_id", "evil-tenant", key)

    def test_roles(self) -> None:
        """principal.roles are now HMAC-signed — tampering must be detected."""
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "actor_roles", ["admin", "superuser"], key)

    def test_predicates(self) -> None:
        cap, key, token = self._cap_and_key()
        d = json.loads(token)
        d["predicates"] = [{"field": "tenant_id", "operator": "=", "value": "evil"}]
        tampered = json.dumps(d)
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test").verify_token(tampered)

    def test_policy_version(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "policy_version", "old-permissive", key)

    def test_nonce(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "nonce", "replayed-nonce", key)

    def test_wrong_key(self) -> None:
        cap, key, token = self._cap_and_key()
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(token_bytes(32), expected_audience="test").verify_token(token)

    def test_stripped_signature(self) -> None:
        cap, key, token = self._cap_and_key()
        self._assert_tamper_fails(token, "sig", "00" * 32, key)

    def test_audience_tamper(self) -> None:
        cap, key, token = self._cap_and_key()
        d = json.loads(token)
        d["audience"] = "attacker-service"
        tampered = json.dumps(d)
        with pytest.raises(CapabilityVerificationError):
            CapabilityVerifier(key, expected_audience="test").verify_token(tampered)

    def test_in_memory_tamper_detected(self) -> None:
        """Direct dataclasses.replace tampering must also fail verification."""
        b, key = _make_boundary()
        cap = b.authorize(Principal("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        tampered = dataclasses.replace(cap, resource="evil_table")
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test").verify(tampered)
