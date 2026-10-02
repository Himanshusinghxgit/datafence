"""
Architecture boundary tests.

These tests prove structural properties of DataFenceBoundary and the
capability model — independent of any specific authorization scenario.

They answer: "Is the ownership boundary actually enforced in code?"

Grouped into:

    A. DataFenceBoundary structural contract
       — has authorize(), no execute(), no connector, no DB dependency

    B. No public legacy execution path
       — old DataFence/execute_plan/AllowedRequest unreachable via public API

    C. Capability serialization round-trip
       — JSON round-trip preserves all signed fields and signature validates

    D. Capability tamper detection
       — modifying any single field after serialization fails verification

    E. Core package database independence
       — datafence.core imports carry no psycopg/boto3/snowflake/sqlite deps
"""

from __future__ import annotations

import importlib
import inspect
import json
import sys
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

# ---------------------------------------------------------------------------
# Shared fixture factory
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
    policy = DataFencePolicy("p", "1.0", {
        "orders": ResourcePolicy(
            "orders",
            actions={"read": ActionDecision.ALLOW},
            allowed_fields=["id", "tenant_id", "total", "status"],
            row_rules=[],
            max_rows=100,
        )
    })
    engine = DataFencePolicyEngine(policy, registry=reg)
    key = token_bytes(32)
    return DataFenceBoundary.create(engine, reg, key, capability_audience="test"), key


def _authorize(boundary: DataFenceBoundary) -> AuthorizedExecution:
    return boundary.authorize(
        Actor("user:1", "tenant-a"),
        Intent("orders", Operation.READ, ["id", "total"]),
    )


# ===========================================================================
# A. DataFenceBoundary structural contract
# ===========================================================================


class TestBoundaryStructuralContract:

    def test_boundary_has_authorize_method(self) -> None:
        boundary, _ = _make_boundary()
        assert callable(getattr(boundary, "authorize", None)), (
            "DataFenceBoundary must expose authorize()"
        )

    def test_boundary_has_no_execute_method(self) -> None:
        """
        The canonical boundary API is authorize(), not execute().
        DataFence must not own database execution.
        """
        boundary, _ = _make_boundary()
        assert not hasattr(boundary, "execute"), (
            "DataFenceBoundary must NOT have an execute() method — "
            "database execution belongs to the customer connector"
        )

    def test_boundary_stores_no_connector(self) -> None:
        """Boundary must not hold a reference to any database connector."""
        boundary, _ = _make_boundary()
        connector_attrs = [
            attr for attr in vars(boundary)
            if "connector" in attr.lower() or "connection" in attr.lower()
               or "cursor" in attr.lower() or "db" in attr.lower()
        ]
        assert connector_attrs == [], (
            f"DataFenceBoundary must not store a connector/connection. "
            f"Found: {connector_attrs}"
        )

    def test_boundary_stores_no_db_credentials(self) -> None:
        """Boundary must not hold database credentials or connection strings."""
        boundary, _ = _make_boundary()
        cred_attrs = [
            attr for attr in vars(boundary)
            if any(x in attr.lower() for x in
                   ("password", "conninfo", "dsn", "user", "host", "port",
                    "database", "schema", "warehouse", "bucket", "region",
                    "access_key", "secret", "token"))
        ]
        assert cred_attrs == [], (
            f"DataFenceBoundary must not store database credentials. "
            f"Found: {cred_attrs}"
        )

    def test_authorize_returns_authorized_execution_not_rows(self) -> None:
        """authorize() must return a capability, never database rows."""
        boundary, _ = _make_boundary()
        result = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("orders", Operation.READ, ["id", "total"]),
        )
        assert isinstance(result, AuthorizedExecution), (
            "authorize() must return AuthorizedExecution, not database rows"
        )
        assert not isinstance(result, (list, dict)), (
            "authorize() must not return raw data rows"
        )

    def test_authorize_does_not_execute_data_operation(self) -> None:
        """
        Calling authorize() on a boundary with no connector must succeed.
        This proves authorization is independent of execution.
        """
        # Build a boundary with absolutely no connector attached.
        boundary, key = _make_boundary()
        # If authorize() tried to execute a DB call this would fail because
        # there is no database. It must not — authorization is complete here.
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("orders", Operation.READ, ["id"]),
        )
        assert isinstance(cap, AuthorizedExecution)
        # The capability is valid and verifiable without any database.
        CapabilityVerifier(key, expected_audience="test").verify(cap)

    def test_boundary_class_source_has_no_db_imports(self) -> None:
        """
        datafence.core.boundary must not import psycopg, sqlite3, boto3,
        snowflake, or pyathena at module level.
        """
        import datafence.core.boundary as mod
        source = inspect.getsource(mod)
        forbidden = ["psycopg", "sqlite3", "boto3", "pyathena", "snowflake"]
        hits = [lib for lib in forbidden if lib in source]
        assert hits == [], (
            f"datafence.core.boundary must not import database libraries. "
            f"Found: {hits}"
        )

    def test_direct_instantiation_raises(self) -> None:
        with pytest.raises(TypeError, match="DataFenceBoundary.create"):
            DataFenceBoundary()

    def test_boundary_registry_is_frozen_after_create(self) -> None:
        boundary, _ = _make_boundary()
        assert boundary.registry.is_frozen
        with pytest.raises(RuntimeError):
            boundary.registry.register(ResourceDefinition("new"))

    def test_boundary_has_no_execute_in_public_interface(self) -> None:
        """Inspect the class itself, not just an instance."""
        public_methods = [
            name for name, _ in inspect.getmembers(DataFenceBoundary, predicate=inspect.isfunction)
            if not name.startswith("_")
        ]
        assert "execute" not in public_methods, (
            f"DataFenceBoundary class must not expose execute(). "
            f"Public methods: {public_methods}"
        )

    def test_boundary_public_api_is_only_authorize_and_registry(self) -> None:
        """The only public methods should be authorize() and the registry property."""
        public_methods = {
            name for name, _ in inspect.getmembers(DataFenceBoundary, predicate=callable)
            if not name.startswith("_") and name != "create"
        }
        # 'create' is the classmethod constructor — acceptable.
        # 'authorize' is the one canonical operation.
        # 'registry' is a read-only property (will show as property not method).
        unexpected = public_methods - {"authorize", "create"}
        assert unexpected == set(), (
            f"DataFenceBoundary has unexpected public methods: {unexpected}. "
            "The API surface should be: create(), authorize(), .registry"
        )


# ===========================================================================
# B. No public legacy execution path
# ===========================================================================


class TestNoLegacyExecutionPath:

    def test_legacy_datafence_class_not_importable_from_public_api(self) -> None:
        """The legacy DataFence class must not be importable from datafence."""
        import datafence
        assert not hasattr(datafence, "DataFence"), (
            "Legacy DataFence class must not be exported from datafence.__init__"
        )

    def test_execute_plan_not_on_boundary(self) -> None:
        boundary, _ = _make_boundary()
        assert not hasattr(boundary, "execute_plan"), (
            "execute_plan() was a v0.3 method and must not exist on boundary"
        )

    def test_allowed_request_not_in_public_api(self) -> None:
        import datafence
        assert not hasattr(datafence, "AllowedRequest"), (
            "AllowedRequest was a v0.3 type and must not be in the public API"
        )

    def test_denied_request_not_in_public_api(self) -> None:
        import datafence
        assert not hasattr(datafence, "DeniedRequest"), (
            "DeniedRequest was a v0.3 type and must not be in the public API"
        )

    def test_execution_plan_not_in_public_api(self) -> None:
        import datafence
        assert not hasattr(datafence, "ExecutionPlan"), (
            "ExecutionPlan was a v0.3 type and must not be in the public API"
        )

    def test_execution_result_not_in_public_api(self) -> None:
        import datafence
        assert not hasattr(datafence, "ExecutionResult"), (
            "ExecutionResult was a v0.3 type and must not be in the public API"
        )

    def test_core_boundary_has_no_execute_method(self) -> None:
        from datafence.core import boundary as mod
        assert not hasattr(mod.DataFenceBoundary, "execute"), (
            "datafence.core.boundary.DataFenceBoundary must not have execute()"
        )

    def test_boundary_does_not_accept_connector_argument(self) -> None:
        """DataFenceBoundary.create() must not accept a connector parameter."""
        sig = inspect.signature(DataFenceBoundary.create)
        param_names = list(sig.parameters.keys())
        connector_params = [p for p in param_names if "connector" in p.lower()]
        assert connector_params == [], (
            f"DataFenceBoundary.create() must not accept connector params. "
            f"Found: {connector_params}"
        )

    def test_connector_factories_not_in_boundary_signature(self) -> None:
        """connector_factory, database_path, conninfo must not be in boundary.create()."""
        sig = inspect.signature(DataFenceBoundary.create)
        forbidden = {"connector_factory", "database_path", "conninfo",
                     "dsn", "connection_string", "db_url"}
        present = set(sig.parameters) & forbidden
        assert present == set(), (
            f"DataFenceBoundary.create() must not accept DB params: {present}"
        )

    def test_core_package_does_not_import_legacy_engine(self) -> None:
        """Public datafence package must not re-export legacy policy engine."""
        import datafence
        assert not hasattr(datafence, "SimplePolicyEngine"), (
            "Legacy SimplePolicyEngine must not be in the public API"
        )

    def test_no_raw_sql_attribute_on_authorized_execution(self) -> None:
        """AuthorizedExecution must not carry raw SQL from the agent."""
        boundary, _ = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("orders", Operation.READ, ["id"]),
        )
        assert not hasattr(cap, "raw_sql"), (
            "AuthorizedExecution must not carry raw SQL"
        )


# ===========================================================================
# C. Core package database independence
# ===========================================================================


class TestCorePackageDatabaseIndependence:
    """
    The datafence.core modules must be importable without any database
    driver installed.  Authorization must not require a live database.
    """

    def test_core_boundary_no_db_dep_at_import(self) -> None:
        """Importing datafence.core.boundary must not pull in DB drivers."""
        # Re-import fresh to catch top-level imports.
        if "datafence.core.boundary" in sys.modules:
            mod = sys.modules["datafence.core.boundary"]
        else:
            mod = importlib.import_module("datafence.core.boundary")
        src = inspect.getsource(mod)
        for lib in ("psycopg", "sqlite3", "boto3", "pyathena", "snowflake"):
            assert lib not in src, (
                f"datafence.core.boundary must not reference {lib!r}"
            )

    def test_core_capability_no_db_dep(self) -> None:
        mod = importlib.import_module("datafence.core.capability")
        src = inspect.getsource(mod)
        for lib in ("psycopg", "sqlite3", "boto3", "pyathena", "snowflake"):
            assert lib not in src

    def test_core_policy_no_db_dep(self) -> None:
        mod = importlib.import_module("datafence.core.policy")
        src = inspect.getsource(mod)
        for lib in ("psycopg", "sqlite3", "boto3", "pyathena", "snowflake"):
            assert lib not in src

    def test_core_registry_no_db_dep(self) -> None:
        mod = importlib.import_module("datafence.core.registry")
        src = inspect.getsource(mod)
        for lib in ("psycopg", "sqlite3", "boto3", "pyathena", "snowflake"):
            assert lib not in src

    def test_full_authorization_cycle_needs_no_database(self) -> None:
        """
        The complete authorize() call must succeed with no DB installed.
        This is the architectural proof: DataFence is database-agnostic.
        """
        boundary, key = _make_boundary()
        cap = boundary.authorize(
            Actor("user:alice", "tenant-x"),
            Intent("orders", Operation.READ, ["id", "status"]),
        )
        assert isinstance(cap, AuthorizedExecution)
        # Verification also requires no database.
        CapabilityVerifier(key, expected_audience="test").verify(cap)


# ===========================================================================
# D. Capability serialization round-trip
# ===========================================================================


def _cap_to_dict(cap: AuthorizedExecution) -> dict[str, Any]:
    """Serialize capability to a plain dict (simulating JSON transport)."""
    return {
        "execution_id":      cap.execution_id,
        "created_at":        cap.created_at.isoformat(),
        "actor_id":          cap.actor.id,
        "actor_tenant_id":   cap.actor.tenant_id,
        "actor_metadata":    cap.actor.attributes,
        "resource":          cap.resource,
        "operation":         cap.operation.value,
        "selected_fields":   cap.selected_fields,
        "enforced_filters":  cap.enforced_filters,
        "enforced_predicates": cap.enforced_predicates,
        "limit":             cap.limit,
        "policy_version":    cap.policy_version,
        "policy_decisions":  cap.policy_decisions,
        "expires_at":        cap.expires_at.isoformat() if cap.expires_at else None,
        "audience":          cap.audience,
        "nonce":             cap.nonce,
        "signature":         cap.signature.hex(),
    }


def _dict_to_cap(d: dict[str, Any]) -> AuthorizedExecution:
    """Deserialize capability from a plain dict."""
    from datetime import datetime, timezone

    from datafence.core.types import Operation
    from datafence.core.principal import Principal

    created_at = datetime.fromisoformat(d["created_at"])
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    expires_at = None
    if d.get("expires_at"):
        expires_at = datetime.fromisoformat(d["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

    return AuthorizedExecution(
        execution_id=d["execution_id"],
        created_at=created_at,
        actor=Principal(
            id=d["actor_id"],
            tenant_id=d["actor_tenant_id"],
            attributes=d.get("actor_metadata", {}),
        ),
        resource=d["resource"],
        operation=Operation(d["operation"]),
        selected_fields=d["selected_fields"],
        enforced_filters=d["enforced_filters"],
        enforced_predicates=d.get("enforced_predicates", []),
        limit=d["limit"],
        policy_version=d["policy_version"],
        policy_decisions=d.get("policy_decisions", []),
        expires_at=expires_at,
        audience=d["audience"],
        nonce=d["nonce"],
        signature=bytes.fromhex(d["signature"]),
    )


class TestCapabilitySerializationRoundTrip:
    """
    Prove that AuthorizedExecution can be serialized and deserialized
    across a transport boundary while preserving signature validity.

    This is required for any deployment where the boundary and connector
    run in separate processes (REST API, MCP, microservices, etc.).
    """

    def test_round_trip_preserves_signature(self) -> None:
        boundary, key = _make_boundary()
        original = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("orders", Operation.READ, ["id", "total"]),
        )
        # Serialize → transport → deserialize
        serialized = json.dumps(_cap_to_dict(original))
        restored = _dict_to_cap(json.loads(serialized))

        verifier = CapabilityVerifier(key, expected_audience="test")
        verifier.verify(restored)  # must not raise

    def test_round_trip_preserves_all_fields(self) -> None:
        boundary, _ = _make_boundary()
        original = boundary.authorize(
            Actor("user:alice", "tenant-acme"),
            Intent("orders", Operation.READ, ["id", "status"]),
        )
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
        """Predicates must survive serialization with full operator semantics."""
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
        policy = DataFencePolicy("p", "1", {
            "metrics": ResourcePolicy(
                "metrics",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "value"],
                row_rules=[
                    RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id"),
                    RowRule("value", PredicateOperator.GT, 100),
                ],
                max_rows=50,
            )
        })
        engine = DataFencePolicyEngine(policy, registry=reg)
        key = token_bytes(32)
        boundary = DataFenceBoundary.create(engine, reg, key, capability_audience="test")

        original = boundary.authorize(
            Actor("u", "t-a"), Intent("metrics", Operation.READ)
        )
        restored = _dict_to_cap(_cap_to_dict(original))

        # The GT predicate must survive round-trip
        gt_preds = [
            c for c in restored.filter_constraints()
            if c["field"] == "value" and c["operator"] == ">"
        ]
        assert gt_preds, "GT predicate must survive serialization round-trip"
        assert gt_preds[0]["value"] == 100


# ===========================================================================
# E. Tamper detection after serialization
# ===========================================================================


class TestCapabilityTamperDetectionAfterSerialize:
    """
    Any modification to a serialized field must be detectable after
    deserialization — the HMAC must fail.
    """

    def _original(self) -> tuple[AuthorizedExecution, bytes]:
        boundary, key = _make_boundary()
        cap = boundary.authorize(
            Actor("user:1", "tenant-a"),
            Intent("orders", Operation.READ, ["id", "total"]),
        )
        return cap, key

    def _tamper_and_verify(
        self,
        field: str,
        new_value: Any,
        key: bytes,
        cap: AuthorizedExecution,
    ) -> None:
        d = _cap_to_dict(cap)
        d[field] = new_value
        tampered = _dict_to_cap(d)
        verifier = CapabilityVerifier(key, expected_audience="test")
        with pytest.raises(CapabilityVerificationError, match="signature"):
            verifier.verify(tampered)

    def test_tampered_resource_detected(self) -> None:
        cap, key = self._original()
        self._tamper_and_verify("resource", "secret_table", key, cap)

    def test_tampered_operation_detected(self) -> None:
        cap, key = self._original()
        self._tamper_and_verify("operation", "delete", key, cap)

    def test_tampered_fields_detected(self) -> None:
        cap, key = self._original()
        self._tamper_and_verify("selected_fields", ["id", "total", "ssn"], key, cap)

    def test_tampered_limit_detected(self) -> None:
        cap, key = self._original()
        self._tamper_and_verify("limit", 999999, key, cap)

    def test_tampered_tenant_detected(self) -> None:
        cap, key = self._original()
        self._tamper_and_verify("actor_tenant_id", "evil-tenant", key, cap)

    def test_tampered_predicate_detected(self) -> None:
        cap, key = self._original()
        d = _cap_to_dict(cap)
        d["enforced_predicates"] = [{"field": "tenant_id", "operator": "=", "value": "evil"}]
        tampered = _dict_to_cap(d)
        verifier = CapabilityVerifier(key, expected_audience="test")
        with pytest.raises(CapabilityVerificationError, match="signature"):
            verifier.verify(tampered)

    def test_tampered_policy_version_detected(self) -> None:
        cap, key = self._original()
        self._tamper_and_verify("policy_version", "old-permissive-v0", key, cap)

    def test_tampered_audience_detected(self) -> None:
        """
        Tampered audience is caught by the audience binding check (step 2 of
        CapabilityVerifier.verify), which fires before the signature check.
        The verifier still rejects the capability — the exact error message
        depends on verification order.
        """
        cap, key = self._original()
        d = _cap_to_dict(cap)
        d["audience"] = "attacker-service"
        tampered = _dict_to_cap(d)
        verifier = CapabilityVerifier(key, expected_audience="test")
        # Caught by audience check (before signature) — any CapabilityVerificationError is correct.
        with pytest.raises(CapabilityVerificationError):
            verifier.verify(tampered)

    def test_tampered_nonce_detected(self) -> None:
        cap, key = self._original()
        self._tamper_and_verify("nonce", "replayed-nonce-123", key, cap)

    def test_tampered_expiry_detected(self) -> None:
        from datetime import datetime, timedelta, timezone
        cap, key = self._original()
        far_future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
        self._tamper_and_verify("expires_at", far_future, key, cap)

    def test_wrong_signing_key_detected(self) -> None:
        """A capability verified with the wrong key must fail."""
        cap, correct_key = self._original()
        d = _cap_to_dict(cap)
        restored = _dict_to_cap(d)
        wrong_key = token_bytes(32)
        verifier = CapabilityVerifier(wrong_key, expected_audience="test")
        with pytest.raises(CapabilityVerificationError, match="signature"):
            verifier.verify(restored)

    def test_reconstructing_from_unsigned_fields_is_forgery(self) -> None:
        """
        Prove that stripping the signature and reconstructing is a forgery.

        This directly tests the prompt spec requirement:
        'Reconstructing a capability from unsigned fields is forbidden.'
        """
        cap, key = self._original()
        d = _cap_to_dict(cap)
        # Attacker strips the signature and re-signs with wrong key, or leaves it blank.
        d["signature"] = "00" * 32   # 32 zero bytes — wrong signature
        forged = _dict_to_cap(d)
        verifier = CapabilityVerifier(key, expected_audience="test")
        with pytest.raises(CapabilityVerificationError, match="signature"):
            verifier.verify(forged)
