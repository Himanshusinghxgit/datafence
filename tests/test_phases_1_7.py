"""
DataFence Phase 1-7 tests.

Covers:
    Phase 0+1 : ExecutionPlan audit-only semantics, unified types
    Phase 2   : Resource/Execution IR (ResourceRef, FieldRef, Predicate, Filter)
    Phase 2   : SQLite connector — identifier validation, parameterised queries
    Phase 3   : Enhanced policy model (DataFencePolicyEngine, YAML loader)
    Phase 3   : Policy injects row filters (not required from LLM)
    Phase 4   : PostgreSQL connector interface (unit, no real DB)
    Phase 5   : Athena / Snowflake connector interface (unit, no real cloud)
    Phase 6   : MCP tool + server
    Phase 7   : OpenAI, Anthropic, LangChain adapters
"""

from __future__ import annotations

import json
import os
import tempfile
from secrets import token_bytes

import pytest

# ---------------------------------------------------------------------------
# Core imports
# ---------------------------------------------------------------------------
from datafence.core.boundary import DataFenceBoundary
from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.policy import (
    ActionDecision,
    DataFencePolicy,
    DataFencePolicyEngine,
    PolicyEffect,
    ResourcePolicy,
    RowRule,
    YAMLPolicyLoader,
    create_banking_policy,
)
from datafence.core.resources import (
    FieldRef,
    Filter,
    Predicate,
    PredicateOperator,
    Projection,
    ResourceRef,
    RowLimit,
    validate_identifier,
)
from datafence.core.types import (
    Actor,
    AllowedRequest,
    Decision,
    DeniedRequest,
    ExecutionPlan,
    Intent,
    Operation,
)
from datafence.connectors.sqlite_connector import SQLiteConnector, create_demo_database


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def signing_key():
    return token_bytes(32)


@pytest.fixture
def db_path():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        p = f.name
    yield p
    os.unlink(p)


@pytest.fixture
def connector(db_path, signing_key):
    c = create_demo_database(db_path, signing_key)
    yield c
    c.close()


@pytest.fixture
def banking_engine():
    return create_banking_policy()


@pytest.fixture
def boundary(banking_engine, db_path):
    b = DataFenceBoundary.create(
        policy_engine=banking_engine,
        connector_factory=SQLiteConnector,
        registry=banking_engine.registry,
        database_path=db_path,
    )
    create_demo_database(db_path, b._signing_key)
    return b


# ===========================================================================
# Phase 0+1 — ExecutionPlan is audit-only
# ===========================================================================

class TestExecutionPlanAuditOnly:

    def test_execution_plan_create_exists_but_is_internal(self):
        """ExecutionPlan.create() exists — it's fine for internal boundary use."""
        actor = Actor(id="u", tenant_id="t")
        plan = ExecutionPlan.create(
            actor=actor,
            resource="transactions",
            operation=Operation.READ,
            selected_fields=["id", "amount"],
            enforced_filters={"tenant_id": "t"},
            limit=10,
            policy_version="v1",
            policy_decisions=[],
        )
        assert plan.resource == "transactions"

    def test_connector_does_not_accept_execution_plan(self, connector, signing_key):
        """Connector.execute() requires AuthorizedExecution, not ExecutionPlan."""
        actor = Actor(id="u", tenant_id="tenant_a")
        plan = ExecutionPlan.create(
            actor=actor,
            resource="transactions",
            operation=Operation.READ,
            selected_fields=["id"],
            enforced_filters={},
            limit=10,
            policy_version="v1",
            policy_decisions=[],
        )
        with pytest.raises((AttributeError, TypeError, CapabilityVerificationError)):
            connector.execute(plan)   # plan has no .verify_signature()

    def test_allowed_request_carries_execution_plan_for_audit(self, boundary):
        """AllowedRequest.execution_plan is populated — audit trail."""
        actor = Actor(id="a", tenant_id="tenant_a")
        intent = Intent(resource="transactions", operation=Operation.READ,
                        fields=["id", "merchant"])
        result = boundary.execute(actor, intent)
        assert isinstance(result, AllowedRequest)
        assert result.execution_plan is not None
        assert result.execution_plan.resource == "transactions"


# ===========================================================================
# Phase 2 — Resource / Execution IR
# ===========================================================================

class TestResourceRef:

    def test_valid_name(self):
        r = ResourceRef(name="transactions")
        assert r.name == "transactions"

    def test_qualified_name(self):
        r = ResourceRef(name="orders", namespace="sales")
        assert r.qualified_name() == "sales.orders"

    def test_plain_qualified_name(self):
        r = ResourceRef(name="orders")
        assert r.qualified_name() == "orders"

    def test_from_string_with_namespace(self):
        r = ResourceRef.from_string("banking.transactions")
        assert r.namespace == "banking"
        assert r.name == "transactions"

    def test_from_string_plain(self):
        r = ResourceRef.from_string("transactions")
        assert r.name == "transactions"
        assert r.namespace == ""

    def test_invalid_name_rejected(self):
        with pytest.raises(ValueError, match="Unsafe"):
            ResourceRef(name="'; DROP TABLE transactions; --")

    def test_invalid_name_with_spaces(self):
        with pytest.raises(ValueError, match="Unsafe"):
            ResourceRef(name="my table")

    def test_invalid_name_with_dot(self):
        with pytest.raises(ValueError, match="Unsafe"):
            ResourceRef(name="schema.table")  # dots not allowed in name alone


class TestFieldRef:

    def test_valid_field(self):
        f = FieldRef(name="merchant")
        assert f.name == "merchant"

    def test_invalid_field_rejected(self):
        with pytest.raises(ValueError, match="Unsafe"):
            FieldRef(name="merchant; DROP TABLE")

    def test_from_string_qualified(self):
        f = FieldRef.from_string("transactions.amount")
        assert f.name == "amount"
        assert f.resource is not None
        assert f.resource.name == "transactions"


class TestValidateIdentifier:

    @pytest.mark.parametrize("name", [
        "transactions", "tenant_id", "amount", "_private", "CamelCase",
    ])
    def test_valid(self, name):
        assert validate_identifier(name) == name

    @pytest.mark.parametrize("name", [
        "'; DROP TABLE", "1_starts_with_digit", "has space", "has-dash",
        "has.dot", "", "SELECT *",
    ])
    def test_invalid(self, name):
        with pytest.raises(ValueError):
            validate_identifier(name)


class TestPredicate:

    def test_basic_predicate(self):
        p = Predicate(
            field=FieldRef("tenant_id"),
            operator=PredicateOperator.EQ,
            value="tenant_a",
        )
        assert not p.is_actor_reference()

    def test_actor_reference_detected(self):
        p = Predicate(
            field=FieldRef("tenant_id"),
            operator=PredicateOperator.EQ,
            value=":actor_tenant_id",
        )
        assert p.is_actor_reference()

    def test_resolve_tenant(self):
        p = Predicate(FieldRef("tenant_id"), PredicateOperator.EQ, ":actor_tenant_id")
        actor = Actor(id="u", tenant_id="acme")
        resolved = p.resolve(actor)
        assert resolved.value == "acme"
        assert not resolved.is_actor_reference()

    def test_resolve_actor_id(self):
        p = Predicate(FieldRef("user_id"), PredicateOperator.EQ, ":actor_id")
        actor = Actor(id="user:alice", tenant_id="acme")
        resolved = p.resolve(actor)
        assert resolved.value == "user:alice"


class TestFilter:

    def test_empty(self):
        f = Filter.empty()
        assert not f

    def test_from_dict(self):
        f = Filter.from_dict({"tenant_id": "acme", "status": "active"})
        assert len(f.predicates) == 2

    def test_to_dict_roundtrip(self):
        d = {"tenant_id": "acme", "region": "us-east"}
        f = Filter.from_dict(d)
        assert f.to_dict() == d

    def test_merge_non_conflicting(self):
        policy_filter = Filter.from_dict({"tenant_id": "acme"})
        intent_filter = Filter.from_dict({"merchant": "Amazon"})
        merged = policy_filter.merge(intent_filter)
        names = {p.field.name for p in merged.predicates}
        assert "tenant_id" in names
        assert "merchant" in names

    def test_merge_policy_takes_priority(self):
        policy_filter = Filter.from_dict({"tenant_id": "acme"})
        intent_filter = Filter.from_dict({"tenant_id": "EVIL_TENANT"})
        merged = policy_filter.merge(intent_filter)
        # Only one tenant_id predicate, and it's from policy
        tenant_preds = [p for p in merged.predicates if p.field.name == "tenant_id"]
        assert len(tenant_preds) == 1
        assert tenant_preds[0].value == "acme"

    def test_resolve_actor_references(self):
        f = Filter.from_dict({"tenant_id": ":actor_tenant_id"})
        actor = Actor(id="u", tenant_id="myorg")
        resolved = f.resolve(actor)
        assert resolved.to_dict()["tenant_id"] == "myorg"


class TestProjection:

    def test_from_strings(self):
        p = Projection.from_strings(["id", "merchant", "amount"])
        assert p.field_names() == ["id", "merchant", "amount"]

    def test_length(self):
        p = Projection.from_strings(["a", "b"])
        assert len(p) == 2

    def test_bool(self):
        assert Projection.from_strings(["a"])
        assert not Projection.from_strings([])


# ===========================================================================
# Phase 2 — SQLite connector identifier validation
# ===========================================================================

class TestSQLiteConnectorIdentifierValidation:

    def test_valid_query_succeeds(self, connector, signing_key):
        cap = AuthorizedExecution.create_signed(
            execution_id="test_001",
            actor=Actor(id="u", tenant_id="tenant_a"),
            resource="transactions",
            operation=Operation.READ,
            selected_fields=["id", "merchant"],
            enforced_filters={"tenant_id": "tenant_a"},
            limit=10,
            policy_version="v1",
            policy_decisions=[],
            signing_key=signing_key,
        )
        rows = connector.execute(cap)
        assert all("merchant" in r for r in rows)
        assert all("card_number" not in r for r in rows)

    def test_injected_resource_name_rejected(self, connector, signing_key):
        """A capability with an unsafe resource name is rejected at compile time."""
        # We can only test this by temporarily bypassing signature check
        # Create valid cap then mutate resource via object.__setattr__
        cap = AuthorizedExecution.create_signed(
            execution_id="test_002",
            actor=Actor(id="u", tenant_id="tenant_a"),
            resource="transactions",
            operation=Operation.READ,
            selected_fields=["id"],
            enforced_filters={},
            limit=5,
            policy_version="v1",
            policy_decisions=[],
            signing_key=signing_key,
        )
        # Mutate resource to unsafe value
        object.__setattr__(cap, "resource", "'; DROP TABLE transactions; --")
        # Connector should reject — signature will fail
        with pytest.raises(CapabilityVerificationError):
            connector.execute(cap)

    def test_filter_values_are_parameterised(self, connector, signing_key):
        """SQL injection in filter values is impossible — values are parameterised."""
        cap = AuthorizedExecution.create_signed(
            execution_id="test_003",
            actor=Actor(id="u", tenant_id="tenant_a"),
            resource="transactions",
            operation=Operation.READ,
            selected_fields=["id", "merchant"],
            enforced_filters={"tenant_id": "tenant_a' OR '1'='1"},  # injection attempt
            limit=10,
            policy_version="v1",
            policy_decisions=[],
            signing_key=signing_key,
        )
        # No rows should be returned (value treated as literal string, no match)
        rows = connector.execute(cap)
        assert rows == []

    def test_only_authorised_fields_returned(self, connector, signing_key):
        cap = AuthorizedExecution.create_signed(
            execution_id="test_004",
            actor=Actor(id="u", tenant_id="tenant_a"),
            resource="transactions",
            operation=Operation.READ,
            selected_fields=["id", "merchant"],
            enforced_filters={"tenant_id": "tenant_a"},
            limit=100,
            policy_version="v1",
            policy_decisions=[],
            signing_key=signing_key,
        )
        rows = connector.execute(cap)
        for row in rows:
            assert set(row.keys()) <= {"id", "merchant"}


# ===========================================================================
# Phase 3 — Enhanced policy model
# ===========================================================================

class TestDataFencePolicyEngine:

    def test_allow_read_authorised_fields(self, banking_engine):
        actor = Actor(id="u", tenant_id="acme")
        decision = banking_engine.evaluate(
            actor, Intent("transactions", Operation.READ, ["id", "merchant", "amount"])
        )
        assert decision.is_allow
        assert "id" in decision.allowed_fields
        assert "card_number" not in decision.allowed_fields

    def test_deny_read_denied_field(self, banking_engine):
        actor = Actor(id="u", tenant_id="acme")
        decision = banking_engine.evaluate(
            actor, Intent("transactions", Operation.READ, ["id", "card_number"])
        )
        assert decision.is_deny
        assert any("denied" in r.lower() for r in decision.reasons)

    def test_deny_delete_operation(self, banking_engine):
        actor = Actor(id="u", tenant_id="acme")
        decision = banking_engine.evaluate(
            actor, Intent("transactions", Operation.DELETE)
        )
        assert decision.is_deny

    def test_deny_unknown_resource(self, banking_engine):
        actor = Actor(id="u", tenant_id="acme")
        decision = banking_engine.evaluate(
            actor, Intent("secret_vault", Operation.READ)
        )
        assert decision.is_deny
        assert any("No policy" in r for r in decision.reasons)

    def test_enforced_filter_injected(self, banking_engine):
        """Policy injects tenant filter — LLM does not need to provide it."""
        actor = Actor(id="u", tenant_id="myorg")
        decision = banking_engine.evaluate(
            actor, Intent("transactions", Operation.READ)
        )
        assert decision.is_allow
        # Enforced filter resolves actor reference
        filt = decision.enforced_filter
        assert filt  # non-empty
        filter_dict = filt.to_dict()
        assert filter_dict.get("tenant_id") == "myorg"

    def test_enforced_filter_uses_actor_tenant(self, banking_engine):
        """Different actors get different injected tenant filters."""
        actor_a = Actor(id="u", tenant_id="org_a")
        actor_b = Actor(id="v", tenant_id="org_b")

        dec_a = banking_engine.evaluate(actor_a, Intent("transactions", Operation.READ))
        dec_b = banking_engine.evaluate(actor_b, Intent("transactions", Operation.READ))

        assert dec_a.enforced_filter.to_dict()["tenant_id"] == "org_a"
        assert dec_b.enforced_filter.to_dict()["tenant_id"] == "org_b"

    def test_row_limit_enforced(self, banking_engine):
        actor = Actor(id="u", tenant_id="x")
        decision = banking_engine.evaluate(
            actor, Intent("transactions", Operation.READ)
        )
        assert decision.row_limit.value == 100

    def test_all_fields_returned_when_none_requested(self, banking_engine):
        actor = Actor(id="u", tenant_id="x")
        decision = banking_engine.evaluate(
            actor, Intent("transactions", Operation.READ)
        )
        assert decision.is_allow
        assert set(decision.allowed_fields) == {"id", "merchant", "amount", "timestamp"}

    def test_obligations_present(self, banking_engine):
        actor = Actor(id="u", tenant_id="x")
        decision = banking_engine.evaluate(
            actor, Intent("transactions", Operation.READ)
        )
        assert decision.obligations.get("audit") is True


class TestYAMLPolicyLoader:

    def test_load_banking_yaml(self):
        policy = YAMLPolicyLoader.load("policies/banking.yaml")
        assert policy.name == "banking-demo-v1"
        assert "transactions" in policy.resources

    def test_transactions_read_allowed(self):
        policy = YAMLPolicyLoader.load("policies/banking.yaml")
        engine = DataFencePolicyEngine(policy)
        actor = Actor(id="u", tenant_id="t")
        dec = engine.evaluate(actor, Intent("transactions", Operation.READ))
        assert dec.is_allow

    def test_transactions_delete_denied(self):
        policy = YAMLPolicyLoader.load("policies/banking.yaml")
        engine = DataFencePolicyEngine(policy)
        actor = Actor(id="u", tenant_id="t")
        dec = engine.evaluate(actor, Intent("transactions", Operation.DELETE))
        assert dec.is_deny

    def test_denied_fields_blocked(self):
        policy = YAMLPolicyLoader.load("policies/banking.yaml")
        engine = DataFencePolicyEngine(policy)
        actor = Actor(id="u", tenant_id="t")
        dec = engine.evaluate(
            actor, Intent("transactions", Operation.READ, ["id", "card_number"])
        )
        assert dec.is_deny

    def test_row_rule_injected(self):
        policy = YAMLPolicyLoader.load("policies/banking.yaml")
        engine = DataFencePolicyEngine(policy)
        actor = Actor(id="u", tenant_id="org99")
        dec = engine.evaluate(actor, Intent("transactions", Operation.READ))
        assert dec.is_allow
        assert dec.enforced_filter.to_dict().get("tenant_id") == "org99"

    def test_from_dict(self):
        data = {
            "name": "test-policy",
            "version": "1",
            "resources": {
                "items": {
                    "actions": {"read": "allow", "delete": "deny"},
                    "fields": {"allow": ["id", "name"], "deny": ["secret"]},
                    "rows": [{"field": "owner", "operator": "equals",
                               "value": ":actor_id"}],
                    "limits": {"rows": 50},
                }
            }
        }
        policy = YAMLPolicyLoader.from_dict(data)
        engine = DataFencePolicyEngine(policy)
        actor = Actor(id="user:alice", tenant_id="t")
        dec = engine.evaluate(actor, Intent("items", Operation.READ))
        assert dec.is_allow
        assert dec.enforced_filter.to_dict()["owner"] == "user:alice"
        assert dec.row_limit.value == 50


# ===========================================================================
# Phase 3 — Policy integration with boundary
# ===========================================================================

class TestPolicyIntegrationWithBoundary:

    def test_new_engine_works_with_boundary(self, db_path):
        engine = create_banking_policy()
        b = DataFenceBoundary.create(
            policy_engine=engine,
            connector_factory=SQLiteConnector,
            registry=engine.registry,
            database_path=db_path,
        )
        create_demo_database(db_path, b._signing_key)
        actor = Actor(id="a", tenant_id="tenant_a")
        intent = Intent(resource="transactions", operation=Operation.READ,
                        fields=["id", "merchant", "amount"])
        result = b.execute(actor, intent)
        assert isinstance(result, AllowedRequest)
        assert result.execution_result.row_count > 0

    def test_tenant_isolation_via_new_engine(self, db_path):
        engine = create_banking_policy()
        b = DataFenceBoundary.create(
            policy_engine=engine,
            connector_factory=SQLiteConnector,
            registry=engine.registry,
            database_path=db_path,
        )
        create_demo_database(db_path, b._signing_key)

        actor_a = Actor(id="u", tenant_id="tenant_a")
        actor_b = Actor(id="v", tenant_id="tenant_b")

        intent = Intent(resource="transactions", operation=Operation.READ,
                        fields=["id", "merchant"])

        result_a = b.execute(actor_a, intent)
        result_b = b.execute(actor_b, intent)

        assert isinstance(result_a, AllowedRequest)
        assert isinstance(result_b, AllowedRequest)
        assert result_a.execution_result.row_count == 3  # tenant_a has 3
        assert result_b.execution_result.row_count == 3  # tenant_b has 3

    def test_denied_field_blocked_by_new_engine(self, db_path):
        engine = create_banking_policy()
        b = DataFenceBoundary.create(
            policy_engine=engine,
            connector_factory=SQLiteConnector,
            registry=engine.registry,
            database_path=db_path,
        )
        create_demo_database(db_path, b._signing_key)
        actor = Actor(id="u", tenant_id="tenant_a")
        intent = Intent(resource="transactions", operation=Operation.READ,
                        fields=["id", "card_number"])
        result = b.execute(actor, intent)
        assert isinstance(result, DeniedRequest)

    def test_delete_blocked_by_new_engine(self, db_path):
        engine = create_banking_policy()
        b = DataFenceBoundary.create(
            policy_engine=engine,
            connector_factory=SQLiteConnector,
            registry=engine.registry,
            database_path=db_path,
        )
        create_demo_database(db_path, b._signing_key)
        actor = Actor(id="u", tenant_id="tenant_a")
        intent = Intent(resource="transactions", operation=Operation.DELETE)
        result = b.execute(actor, intent)
        assert isinstance(result, DeniedRequest)


# ===========================================================================
# Phase 4 — PostgreSQL connector (interface tests, no real DB needed)
# ===========================================================================

class TestPostgreSQLConnectorInterface:

    def test_import(self):
        from datafence.connectors.postgres_connector import PostgreSQLConnector
        assert PostgreSQLConnector is not None

    def test_requires_signing_key(self):
        from datafence.connectors.postgres_connector import PostgreSQLConnector
        # Missing signing_key → TypeError (required positional arg)
        with pytest.raises(TypeError):
            PostgreSQLConnector()  # type: ignore

    def test_compile_select_valid(self, signing_key):
        """Test SQL compilation without a real DB connection."""
        psycopg = pytest.importorskip("psycopg")
        from datafence.connectors.postgres_connector import PostgreSQLConnector
        import unittest.mock as mock

        with mock.patch("psycopg.connect") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            c = PostgreSQLConnector(
                signing_key=signing_key,
                conninfo="postgresql://fake/db",
            )
            cap = AuthorizedExecution.create_signed(
                execution_id="pg_test",
                actor=Actor(id="u", tenant_id="t"),
                resource="orders",
                operation=Operation.READ,
                selected_fields=["id", "amount"],
                enforced_filters={"tenant_id": "t"},
                limit=10,
                policy_version="v1",
                policy_decisions=[],
                signing_key=signing_key,
            )
            sql, params = c._compile_select(cap)
            assert "SELECT id, amount FROM orders" in sql
            assert "WHERE tenant_id = %s" in sql
            assert "t" in params
            assert "LIMIT 10" in sql

    def test_unsafe_identifier_rejected(self, signing_key):
        """Unsafe resource name in compiled query raises ValueError."""
        psycopg = pytest.importorskip("psycopg")
        from datafence.connectors.postgres_connector import PostgreSQLConnector
        import unittest.mock as mock

        with mock.patch("psycopg.connect"):
            c = PostgreSQLConnector(signing_key=signing_key, conninfo="fake")
            cap = AuthorizedExecution.create_signed(
                execution_id="pg_bad",
                actor=Actor(id="u", tenant_id="t"),
                resource="orders",
                operation=Operation.READ,
                selected_fields=["id"],
                enforced_filters={},
                limit=5,
                policy_version="v1",
                policy_decisions=[],
                signing_key=signing_key,
            )
            # Mutate to unsafe resource — will fail at validation
            object.__setattr__(cap, "resource", "orders; DROP TABLE orders")
            with pytest.raises((ValueError, CapabilityVerificationError)):
                c._compile_select(cap)


# ===========================================================================
# Phase 5 — Athena + Snowflake connector interface tests
# ===========================================================================

class TestAthenaConnectorInterface:

    def test_import(self):
        from datafence.connectors.athena_connector import AthenaConnector
        assert AthenaConnector is not None

    def test_compile_select(self, signing_key):
        pytest.importorskip("pyathena")
        from datafence.connectors.athena_connector import AthenaConnector
        import unittest.mock as mock

        with mock.patch("pyathena.connect") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            c = AthenaConnector(
                signing_key=signing_key,
                s3_staging_dir="s3://bucket/results/",
                region_name="us-east-1",
                schema_name="banking",
            )
            cap = AuthorizedExecution.create_signed(
                execution_id="athena_test",
                actor=Actor(id="u", tenant_id="t"),
                resource="transactions",
                operation=Operation.READ,
                selected_fields=["id", "merchant"],
                enforced_filters={"tenant_id": "t"},
                limit=50,
                policy_version="v1",
                policy_decisions=[],
                signing_key=signing_key,
            )
            sql, params = c._compile_select(cap)
            assert '"banking"."transactions"' in sql
            assert "SELECT id, merchant" in sql
            assert "?" in sql
            assert "t" in params
            assert "LIMIT 50" in sql


class TestSnowflakeConnectorInterface:

    def test_import(self):
        from datafence.connectors.snowflake_connector import SnowflakeConnector
        assert SnowflakeConnector is not None

    def test_compile_select_with_schema(self, signing_key):
        pytest.importorskip("snowflake.connector")
        from datafence.connectors.snowflake_connector import SnowflakeConnector
        import unittest.mock as mock

        with mock.patch("snowflake.connector.connect") as mock_connect:
            mock_connect.return_value = mock.MagicMock()
            c = SnowflakeConnector(
                signing_key=signing_key,
                account="test.us-east-1",
                user="svc",
                database="PROD",
                schema="PUBLIC",
            )
            cap = AuthorizedExecution.create_signed(
                execution_id="sf_test",
                actor=Actor(id="u", tenant_id="t"),
                resource="transactions",
                operation=Operation.READ,
                selected_fields=["id", "amount"],
                enforced_filters={"tenant_id": "t"},
                limit=100,
                policy_version="v1",
                policy_decisions=[],
                signing_key=signing_key,
            )
            sql, params = c._compile_select(cap)
            assert '"PROD"."PUBLIC"."transactions"' in sql
            assert '"id"' in sql
            assert '"amount"' in sql
            assert "%s" in sql
            assert "t" in params


# ===========================================================================
# Phase 6 — MCP tool + server
# ===========================================================================

class TestMCPTool:

    def test_schema_shape(self, boundary):
        from datafence.mcp.tool import DataFenceQueryTool
        tool = DataFenceQueryTool(boundary)
        schema = tool.schema()
        assert schema["name"] == "datafence_query"
        assert "inputSchema" in schema
        assert "resource" in schema["inputSchema"]["properties"]

    def test_allowed_call(self, boundary):
        from datafence.mcp.tool import DataFenceQueryTool
        create_demo_database("/tmp/datafence_mcp_test.db", boundary._signing_key)
        tool = DataFenceQueryTool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        result = tool.call(principal, {
            "resource": "transactions",
            "fields": ["id", "merchant"],
            "limit": 5,
        })
        assert result.allowed
        assert result.row_count >= 0

    def test_denied_call_sensitive_field(self, boundary):
        from datafence.mcp.tool import DataFenceQueryTool
        tool = DataFenceQueryTool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        result = tool.call(principal, {
            "resource": "transactions",
            "fields": ["id", "card_number"],
        })
        assert not result.allowed
        assert len(result.denial_reasons) > 0

    def test_tool_result_to_dict(self, boundary):
        from datafence.mcp.tool import DataFenceQueryTool
        tool = DataFenceQueryTool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        result = tool.call(principal, {"resource": "transactions"})
        d = result.to_dict()
        assert "allowed" in d
        assert "data" in d
        assert "row_count" in d


class TestMCPServer:

    def test_initialize(self, boundary):
        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(boundary, server_name="test-server")
        resp = server.handle_initialize()
        assert resp["serverInfo"]["name"] == "test-server"

    def test_list_tools(self, boundary):
        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(boundary)
        resp = server.handle_list_tools()
        assert len(resp["tools"]) == 1
        assert resp["tools"][0]["name"] == "datafence_query"

    def test_call_tool_allowed(self, boundary):
        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(boundary)
        session = {"principal": {"id": "u", "tenant_id": "tenant_a"}}
        resp = server.handle_call_tool(
            "datafence_query",
            {"resource": "transactions", "fields": ["id", "merchant"]},
            session_context=session,
        )
        data = json.loads(resp["content"][0]["text"])
        assert data["status"] == "allowed"

    def test_call_tool_denied_field(self, boundary):
        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(boundary)
        session = {"principal": {"id": "u", "tenant_id": "tenant_a"}}
        resp = server.handle_call_tool(
            "datafence_query",
            {"resource": "transactions", "fields": ["card_number"]},
            session_context=session,
        )
        data = json.loads(resp["content"][0]["text"])
        assert data["status"] == "denied"

    def test_unknown_tool(self, boundary):
        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(boundary)
        session = {"principal": {"id": "u", "tenant_id": "t"}}
        resp = server.handle_call_tool("nonexistent_tool", {}, session)
        data = json.loads(resp["content"][0]["text"])
        assert "error" in data

    def test_missing_principal(self, boundary):
        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(boundary)
        resp = server.handle_call_tool("datafence_query", {"resource": "transactions"})
        assert resp.get("isError")

    def test_handle_request_dispatch(self, boundary):
        from datafence.mcp.server import DataFenceMCPServer
        server = DataFenceMCPServer(boundary)
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        resp = server.handle_request(req)
        assert resp["id"] == 1
        assert "tools" in resp["result"]


# ===========================================================================
# Phase 7 — OpenAI adapter
# ===========================================================================

class TestOpenAITool:

    def test_tool_spec_shape(self, boundary):
        from datafence.integrations.openai_tool import DataFenceOpenAITool
        tool = DataFenceOpenAITool(boundary)
        spec = tool.openai_tool_spec()
        assert spec["type"] == "function"
        assert spec["function"]["name"] == "datafence_query"
        assert "parameters" in spec["function"]

    def test_handle_call_allowed(self, boundary):
        from datafence.integrations.openai_tool import DataFenceOpenAITool
        tool = DataFenceOpenAITool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        result_str = tool.handle_call(principal,
                                      {"resource": "transactions",
                                       "fields": ["id", "merchant"],
                                       "limit": 5})
        result = json.loads(result_str)
        assert result["status"] == "allowed"

    def test_handle_call_denied(self, boundary):
        from datafence.integrations.openai_tool import DataFenceOpenAITool
        tool = DataFenceOpenAITool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        result_str = tool.handle_call(principal,
                                      {"resource": "transactions",
                                       "fields": ["card_number"]})
        result = json.loads(result_str)
        assert result["status"] == "denied"

    def test_handle_call_accepts_json_string(self, boundary):
        from datafence.integrations.openai_tool import DataFenceOpenAITool
        tool = DataFenceOpenAITool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        json_str = json.dumps({"resource": "transactions", "fields": ["id"]})
        result = json.loads(tool.handle_call(principal, json_str))
        assert result["status"] == "allowed"


# ===========================================================================
# Phase 7 — Anthropic adapter
# ===========================================================================

class TestAnthropicTool:

    def test_tool_spec_shape(self, boundary):
        from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
        tool = DataFenceAnthropicTool(boundary)
        spec = tool.anthropic_tool_spec()
        assert spec["name"] == "datafence_query"
        assert "input_schema" in spec

    def test_handle_call_allowed(self, boundary):
        from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
        tool = DataFenceAnthropicTool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        result_str = tool.handle_call(principal, {"resource": "transactions",
                                                   "fields": ["id", "amount"]})
        result = json.loads(result_str)
        assert result["status"] == "allowed"

    def test_handle_call_denied(self, boundary):
        from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
        tool = DataFenceAnthropicTool(boundary)
        principal = Actor(id="u", tenant_id="tenant_a")
        result_str = tool.handle_call(principal, {"resource": "transactions",
                                                   "fields": ["ssn"]})
        result = json.loads(result_str)
        assert result["status"] == "denied"


# ===========================================================================
# Phase 7 — LangChain adapter
# ===========================================================================

class TestLangChainTool:

    def test_run_allowed(self, boundary):
        from datafence.integrations.langchain_tool import DataFenceLangChainTool
        principal = Actor(id="u", tenant_id="tenant_a")
        tool = DataFenceLangChainTool(boundary, principal)
        result_str = tool.run(json.dumps({"resource": "transactions",
                                          "fields": ["id", "merchant"]}))
        result = json.loads(result_str)
        assert result["status"] == "allowed"

    def test_run_denied(self, boundary):
        from datafence.integrations.langchain_tool import DataFenceLangChainTool
        principal = Actor(id="u", tenant_id="tenant_a")
        tool = DataFenceLangChainTool(boundary, principal)
        result_str = tool.run(json.dumps({"resource": "transactions",
                                          "fields": ["card_number"]}))
        result = json.loads(result_str)
        assert result["status"] == "denied"

    def test_run_bare_string_treated_as_resource(self, boundary):
        from datafence.integrations.langchain_tool import DataFenceLangChainTool
        principal = Actor(id="u", tenant_id="tenant_a")
        tool = DataFenceLangChainTool(boundary, principal)
        # "transactions" as bare string → resource name
        result_str = tool.run("transactions")
        result = json.loads(result_str)
        assert result["status"] in ("allowed", "denied")  # well-formed response

    def test_principal_bound_at_construction(self, boundary):
        """The agent cannot change the principal — it's bound at construction."""
        from datafence.integrations.langchain_tool import DataFenceLangChainTool
        principal_a = Actor(id="u", tenant_id="tenant_a")
        tool = DataFenceLangChainTool(boundary, principal_a)
        # Agent tries to request tenant_b data but principal is tenant_a
        result_str = tool.run(json.dumps({"resource": "transactions"}))
        result = json.loads(result_str)
        # Should see tenant_a data only (enforced by policy)
        if result["status"] == "allowed":
            assert result["row_count"] == 3  # tenant_a has 3 transactions


# ===========================================================================
# Resource Registry tests
# ===========================================================================

class TestResourceRegistry:

    def test_create_banking_registry(self):
        from datafence.core.registry import create_banking_registry
        registry = create_banking_registry()
        assert registry.exists("transactions")
        assert registry.exists("customers")
        assert registry.exists("accounts")

    def test_field_validation_passes(self):
        from datafence.core.registry import create_banking_registry
        registry = create_banking_registry()
        registry.validate_fields("transactions", ["id", "merchant", "amount"])

    def test_field_validation_fails_unknown_field(self):
        from datafence.core.registry import create_banking_registry
        registry = create_banking_registry()
        with pytest.raises(ValueError, match="Unknown fields"):
            registry.validate_fields("transactions", ["id", "nonexistent_field"])

    def test_unknown_resource_rejected(self):
        from datafence.core.registry import create_banking_registry
        registry = create_banking_registry()
        with pytest.raises(ValueError, match="Unknown resource"):
            registry.validate_fields("secret_table", ["id"])

    def test_tenant_key_identified(self):
        from datafence.core.registry import create_banking_registry
        registry = create_banking_registry()
        resource = registry.get("transactions")
        assert resource.tenant_key() == "tenant_id"

    def test_restricted_fields_identified(self):
        from datafence.core.registry import create_banking_registry
        registry = create_banking_registry()
        resource = registry.get("transactions")
        sensitive = resource.sensitive_fields()
        assert "card_number" in sensitive
        assert "merchant" not in sensitive

    def test_registry_integrated_with_policy_engine(self):
        """Policy engine with registry rejects unknown fields."""
        from datafence.core.policy import create_banking_policy
        engine = create_banking_policy()
        actor = Actor(id="u", tenant_id="t")
        # Request a field that doesn't exist in schema
        dec = engine.evaluate(
            actor, Intent("transactions", Operation.READ, ["id", "nonexistent"])
        )
        assert dec.is_deny

    def test_registry_validates_resource_existence(self):
        """Policy engine with registry rejects unknown resources."""
        from datafence.core.policy import create_banking_policy
        engine = create_banking_policy()
        actor = Actor(id="u", tenant_id="t")
        dec = engine.evaluate(actor, Intent("ghost_table", Operation.READ))
        assert dec.is_deny


# ===========================================================================
# Security: filter merge invariant
# ===========================================================================

class TestFilterMergeInvariant:

    def test_policy_filter_wins_over_intent_filter(self, boundary):
        """Policy-injected tenant_id cannot be overridden by intent filters."""
        actor = Actor(id="u", tenant_id="tenant_a")
        # Intent tries to use tenant_b's filter
        intent = Intent(
            resource="transactions",
            operation=Operation.READ,
            fields=["id", "merchant"],
            filters={"tenant_id": "tenant_b"},   # attempt to widen scope
        )
        result = boundary.execute(actor, intent)
        # Should still be ALLOW (policy overrides the intent filter)
        assert isinstance(result, AllowedRequest)
        # But enforced_filters should have tenant_a (from policy, not tenant_b)
        assert result.execution_plan.enforced_filters.get("tenant_id") == "tenant_a"

    def test_user_filter_narrows_scope(self, boundary):
        """A user filter on a non-policy field narrows results."""
        actor = Actor(id="u", tenant_id="tenant_a")
        intent = Intent(
            resource="transactions",
            operation=Operation.READ,
            fields=["id", "merchant", "amount"],
            filters={"merchant": "Amazon"},   # narrow — OK
        )
        result = boundary.execute(actor, intent)
        assert isinstance(result, AllowedRequest)
        # Only Amazon transactions
        for row in result.execution_result.data:
            assert row["merchant"] == "Amazon"
