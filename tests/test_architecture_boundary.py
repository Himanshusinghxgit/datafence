"""
Architecture boundary tests.

These tests prove structural properties independent of any specific
authorization scenario. They answer: is the ownership boundary enforced in code?

Groups:
    A. DataFenceBoundary structural contract
    B. No legacy execution path
    C. Capability round-trip serialization
    D. Tamper detection after serialization
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path
from secrets import token_bytes
from typing import Any

import pytest

from datafence import (
    ActionDecision,
    Actor,
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
)
from datafence.core.capability import CapabilityVerificationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_boundary() -> tuple[DataFenceBoundary, bytes]:
    reg = ResourceRegistry()
    reg.register(ResourceDefinition(
        "orders",
        fields={
            "id":        FieldDefinition("id", "integer"),
            "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
            "total":     FieldDefinition("total", "decimal"),
            "status":    FieldDefinition("status", "string"),
        },
        supported_operations=("read",),
    ))
    pol = DataFencePolicy("p", "1.0", {"orders": ResourcePolicy(
        "orders",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id", "tenant_id", "total", "status"],
        row_rules=[],
        max_rows=100,
    )})
    engine = DataFencePolicyEngine(pol, registry=reg)
    key = token_bytes(32)
    return DataFenceBoundary.create(engine, reg, key, capability_audience="test"), key


def _cap_to_dict(cap: AuthorizedExecution) -> dict[str, Any]:
    return {
        "execution_id":   cap.execution_id,
        "created_at":     cap.created_at.isoformat(),
        "actor_id":       cap.actor.id,
        "actor_tenant_id": cap.actor.tenant_id,
        "actor_attributes": cap.actor.attributes,
        "resource":       cap.resource,
        "operation":      cap.operation.value,
        "selected_fields": cap.selected_fields,
        "predicates":     cap.predicates,
        "limit":          cap.limit,
        "policy_version": cap.policy_version,
        "policy_decisions": cap.policy_decisions,
        "expires_at":     cap.expires_at.isoformat() if cap.expires_at else None,
        "audience":       cap.audience,
        "nonce":          cap.nonce,
        "signature":      cap.signature.hex(),
    }


def _dict_to_cap(d: dict[str, Any]) -> AuthorizedExecution:
    from datetime import datetime, timezone

    from datafence.core.principal import Principal
    from datafence.core.types import Operation

    def _dt(s: str | None) -> datetime | None:
        if not s:
            return None
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    created_at = _dt(d["created_at"]) or datetime.now(timezone.utc)
    return AuthorizedExecution(
        execution_id=d["execution_id"],
        created_at=created_at,
        actor=Principal(
            id=d["actor_id"],
            tenant_id=d["actor_tenant_id"],
            attributes=d.get("actor_attributes", {}),
        ),
        resource=d["resource"],
        operation=Operation(d["operation"]),
        selected_fields=d["selected_fields"],
        predicates=d.get("predicates", []),
        limit=d["limit"],
        policy_version=d["policy_version"],
        policy_decisions=d.get("policy_decisions", []),
        expires_at=_dt(d.get("expires_at")),
        audience=d["audience"],
        nonce=d["nonce"],
        signature=bytes.fromhex(d["signature"]),
    )


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
        r = b.authorize(Actor("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        assert isinstance(r, AuthorizedExecution)
        assert not isinstance(r, (list, dict))

    def test_authorize_needs_no_database(self) -> None:
        b, key = _make_boundary()
        cap = b.authorize(Actor("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
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
            n for n, _ in inspect.getmembers(DataFenceBoundary, predicate=callable)
            if not n.startswith("_") and n != "create"
        }
        assert public == {"authorize"}

    def test_create_has_no_connector_param(self) -> None:
        sig = inspect.signature(DataFenceBoundary.create)
        assert not any("connector" in p.lower() for p in sig.parameters)


# ===========================================================================
# B. No legacy execution path
# ===========================================================================

class TestNoLegacyExecution:
    def test_no_legacy_datafence_class(self) -> None:
        import datafence
        assert not hasattr(datafence, "DataFence")

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

    def test_no_simple_policy_engine(self) -> None:
        import datafence
        assert not hasattr(datafence, "SimplePolicyEngine")

    def test_no_raw_sql_on_capability(self) -> None:
        b, _ = _make_boundary()
        cap = b.authorize(Actor("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        assert not hasattr(cap, "raw_sql")

    def test_no_enforced_filters_on_capability(self) -> None:
        """Dual representation removed — only predicates."""
        b, _ = _make_boundary()
        cap = b.authorize(Actor("u:1", "t-a"), Intent("orders", Operation.READ, ["id"]))
        assert not hasattr(cap, "enforced_filters")
        assert hasattr(cap, "predicates")

    def test_decision_not_in_public_api(self) -> None:
        import datafence
        assert not hasattr(datafence, "Decision")

    def test_request_not_in_public_api(self) -> None:
        import datafence
        assert not hasattr(datafence, "Request")


# ===========================================================================
# C. Capability serialization round-trip
# ===========================================================================

class TestCapabilityRoundTrip:
    def test_round_trip_preserves_signature(self) -> None:
        b, key = _make_boundary()
        original = b.authorize(Actor("u:1", "t-a"),
                               Intent("orders", Operation.READ, ["id", "total"]))
        restored = _dict_to_cap(json.loads(json.dumps(_cap_to_dict(original))))
        CapabilityVerifier(key, expected_audience="test").verify(restored)

    def test_round_trip_preserves_all_fields(self) -> None:
        b, _ = _make_boundary()
        original = b.authorize(Actor("u:alice", "t-acme"),
                               Intent("orders", Operation.READ, ["id", "status"]))
        restored = _dict_to_cap(_cap_to_dict(original))
        assert restored.execution_id == original.execution_id
        assert restored.actor.id == original.actor.id
        assert restored.actor.tenant_id == original.actor.tenant_id
        assert restored.resource == original.resource
        assert restored.operation == original.operation
        assert restored.selected_fields == original.selected_fields
        assert restored.limit == original.limit
        assert restored.policy_version == original.policy_version
        assert restored.audience == original.audience
        assert restored.nonce == original.nonce
        assert restored.signature == original.signature

    def test_round_trip_preserves_predicates(self) -> None:
        from datafence.core.policy import RowRule
        from datafence.core.resources import PredicateOperator
        reg = ResourceRegistry()
        reg.register(ResourceDefinition(
            "metrics",
            fields={
                "id":        FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "value":     FieldDefinition("value", "decimal"),
            },
            supported_operations=("read",),
        ))
        pol = DataFencePolicy("p", "1", {"metrics": ResourcePolicy(
            "metrics",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "value"],
            row_rules=[
                RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id"),
                RowRule("value", PredicateOperator.GT, 100),
            ],
            max_rows=50,
        )})
        engine = DataFencePolicyEngine(pol, registry=reg)
        key = token_bytes(32)
        b = DataFenceBoundary.create(engine, reg, key, capability_audience="test")
        original = b.authorize(Actor("u", "t-a"), Intent("metrics", Operation.READ))
        restored = _dict_to_cap(_cap_to_dict(original))
        gt = [c for c in restored.filter_constraints()
              if c["field"] == "value" and c["operator"] == ">"]
        assert gt and gt[0]["value"] == 100


# ===========================================================================
# D. Tamper detection
# ===========================================================================

class TestTamperDetection:
    def _orig(self) -> tuple[AuthorizedExecution, bytes]:
        b, key = _make_boundary()
        cap = b.authorize(Actor("u:1", "t-a"),
                          Intent("orders", Operation.READ, ["id", "total"]))
        return cap, key

    def _tamper(self, field: str, val: Any, key: bytes, cap: AuthorizedExecution) -> None:
        d = _cap_to_dict(cap)
        d[field] = val
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test").verify(_dict_to_cap(d))

    def test_resource(self) -> None:
        cap, key = self._orig()
        self._tamper("resource", "secret_table", key, cap)

    def test_operation(self) -> None:
        cap, key = self._orig()
        self._tamper("operation", "delete", key, cap)

    def test_fields(self) -> None:
        cap, key = self._orig()
        self._tamper("selected_fields", ["id", "total", "ssn"], key, cap)

    def test_limit(self) -> None:
        cap, key = self._orig()
        self._tamper("limit", 999999, key, cap)

    def test_tenant(self) -> None:
        cap, key = self._orig()
        self._tamper("actor_tenant_id", "evil-tenant", key, cap)

    def test_predicates(self) -> None:
        cap, key = self._orig()
        d = _cap_to_dict(cap)
        d["predicates"] = [{"field": "tenant_id", "operator": "=", "value": "evil"}]
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test").verify(_dict_to_cap(d))

    def test_policy_version(self) -> None:
        cap, key = self._orig()
        self._tamper("policy_version", "old-permissive", key, cap)

    def test_nonce(self) -> None:
        cap, key = self._orig()
        self._tamper("nonce", "replayed-nonce", key, cap)

    def test_wrong_key(self) -> None:
        cap, key = self._orig()
        d = _cap_to_dict(cap)
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(token_bytes(32), expected_audience="test").verify(
                _dict_to_cap(d)
            )

    def test_stripped_signature_is_forgery(self) -> None:
        cap, key = self._orig()
        d = _cap_to_dict(cap)
        d["signature"] = "00" * 32
        with pytest.raises(CapabilityVerificationError, match="signature"):
            CapabilityVerifier(key, expected_audience="test").verify(_dict_to_cap(d))

    def test_audience_tamper_caught(self) -> None:
        cap, key = self._orig()
        d = _cap_to_dict(cap)
        d["audience"] = "attacker-service"
        with pytest.raises(CapabilityVerificationError):
            CapabilityVerifier(key, expected_audience="test").verify(_dict_to_cap(d))
