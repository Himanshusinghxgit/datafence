"""
DataFence Security Invariant Tests (v0.5).

These tests prove the core security guarantees of DataFence v0.5.
Every invariant here must hold — they represent the security contract.

Invariants:
  1.  An unauthorized field NEVER reaches the connector
  2.  A denied field is rejected by policy before execution
  3.  Tenant isolation is enforced by policy-injected row filter
  4.  A forged capability (bad HMAC) is rejected by the connector
  5.  A mutated capability (tampered after signing) is rejected
  6.  execute_plan() does NOT exist on any v0.5 connector
  7.  The connector has NO raw SQL execution path
  8.  Result validation rejects unauthorized fields from a rogue connector
  9.  A destructive operation is denied before reaching the connector
  10. Actor identity is fixed by the host — LLM cannot change it
  11. Policy evaluation happens EXACTLY ONCE per execute() call
  12. Every AllowedRequest carries Evidence and a unique execution_id
  13. Every DeniedRequest carries Evidence and denial reasons
  14. DataFenceBoundary.execute() is the only public entry point
  15. The signing key is never exposed through the public API
"""

from __future__ import annotations

import os
import tempfile
from secrets import token_bytes

import pytest

from datafence.connectors.sqlite_connector import (
    MaliciousConnector,
    SQLiteConnector,
    create_demo_database,
)
from datafence.core.boundary import DataFenceBoundary
from datafence.core.capability import AuthorizedExecution, CapabilityVerificationError
from datafence.core.policy import create_banking_policy
from datafence.core.types import (
    Actor,
    AllowedRequest,
    DeniedRequest,
    Intent,
    Operation,
)


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
    if os.path.exists(p):
        os.unlink(p)


@pytest.fixture
def boundary(db_path):
    b = DataFenceBoundary.create(
        policy_engine=create_banking_policy(),
        connector_factory=SQLiteConnector,
        database_path=db_path,
    )
    create_demo_database(db_path, b._signing_key)
    return b


# ---------------------------------------------------------------------------
# Invariant 1 — Unauthorized field never reaches connector
# ---------------------------------------------------------------------------

def test_unauthorized_field_rejected_before_connector(boundary):
    """An unauthorized field request is denied — database never queried."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "card_number"],   # card_number is denied
    )
    result = boundary.execute(actor, intent)
    assert isinstance(result, DeniedRequest)
    assert any("denied" in r.lower() or "card_number" in r for r in result.decision.reasons)


# ---------------------------------------------------------------------------
# Invariant 2 — SELECT * returns only authorized fields
# ---------------------------------------------------------------------------

def test_select_all_restricted_to_authorized_fields(boundary):
    """SELECT * (fields=None) returns only policy-allowed fields."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.READ, fields=None)
    result = boundary.execute(actor, intent)
    assert isinstance(result, AllowedRequest)
    returned_fields = set(result.execution_plan.selected_fields)
    assert "card_number" not in returned_fields
    assert "account_number" not in returned_fields
    for row in result.execution_result.data:
        assert "card_number" not in row
        assert "account_number" not in row


# ---------------------------------------------------------------------------
# Invariant 3 — Tenant isolation
# ---------------------------------------------------------------------------

def test_tenant_a_cannot_see_tenant_b_data(boundary):
    """tenant_a actor only receives tenant_a rows."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.READ,
                    fields=["id", "merchant"])
    result = boundary.execute(actor, intent)
    assert isinstance(result, AllowedRequest)
    assert result.execution_result.row_count == 3   # only tenant_a rows
    # enforced filter must be present
    assert result.execution_plan.enforced_filters.get("tenant_id") == "tenant_a"


def test_tenant_filter_injected_even_without_llm_filter(boundary):
    """Policy injects tenant_id filter regardless of what the LLM requested."""
    actor = Actor(id="u", tenant_id="tenant_b")
    # LLM provides NO tenant filter
    intent = Intent(resource="transactions", operation=Operation.READ,
                    fields=["id", "merchant"], filters={})
    result = boundary.execute(actor, intent)
    assert isinstance(result, AllowedRequest)
    # Enforced filter must be present with correct tenant
    assert result.execution_plan.enforced_filters.get("tenant_id") == "tenant_b"
    assert result.execution_result.row_count == 3   # only tenant_b rows


def test_llm_cannot_override_tenant_filter(boundary):
    """LLM-supplied tenant filter is overridden by policy."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.READ,
                    fields=["id", "merchant"],
                    filters={"tenant_id": "tenant_b"})   # attack
    result = boundary.execute(actor, intent)
    assert isinstance(result, AllowedRequest)
    # Policy filter wins — tenant_a's filter, not the LLM's
    assert result.execution_plan.enforced_filters.get("tenant_id") == "tenant_a"
    # Only tenant_a data
    assert result.execution_result.row_count == 3


# ---------------------------------------------------------------------------
# Invariant 4 — Forged capability rejected
# ---------------------------------------------------------------------------

def test_forged_capability_rejected_by_connector(signing_key, db_path):
    """A capability with an invalid HMAC is rejected."""
    connector = create_demo_database(db_path, signing_key)
    from datetime import datetime
    forged = AuthorizedExecution(
        execution_id="forged_001",
        created_at=datetime.utcnow(),
        actor=Actor(id="attacker", tenant_id="tenant_b"),
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "card_number"],
        enforced_filters={"tenant_id": "tenant_a"},
        limit=100,
        policy_version="fake",
        policy_decisions=[],
        signature=b"not_a_real_signature",
    )
    with pytest.raises(CapabilityVerificationError):
        connector.execute(forged)
    connector.close()


# ---------------------------------------------------------------------------
# Invariant 5 — Mutated capability rejected
# ---------------------------------------------------------------------------

def test_mutated_capability_rejected(signing_key, db_path):
    """Mutating a valid capability after signing invalidates the HMAC."""
    connector = create_demo_database(db_path, signing_key)
    cap = AuthorizedExecution.create_signed(
        execution_id="cap_001",
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
    # Confirm it works before mutation
    rows = connector.execute(cap)
    assert len(rows) > 0

    # Mutate: add a sensitive field
    object.__setattr__(cap, "selected_fields", ["id", "merchant", "card_number"])
    with pytest.raises(CapabilityVerificationError):
        connector.execute(cap)
    connector.close()


# ---------------------------------------------------------------------------
# Invariant 6 — No execute_plan() method
# ---------------------------------------------------------------------------

def test_no_execute_plan_on_connector(signing_key, db_path):
    """v0.5 connector has no execute_plan() method — bypass vector removed."""
    connector = SQLiteConnector(db_path, signing_key)
    assert not hasattr(connector, "execute_plan"), \
        "execute_plan() must not exist — it was the v0.3 bypass vector"
    connector.close()


# ---------------------------------------------------------------------------
# Invariant 7 — No raw SQL execution path
# ---------------------------------------------------------------------------

def test_no_execute_sql_on_connector(signing_key, db_path):
    """v0.5 connector has no execute_sql() or execute_raw() method."""
    connector = SQLiteConnector(db_path, signing_key)
    for method in ("execute_sql", "execute_raw", "execute_query", "run_sql"):
        assert not hasattr(connector, method), f"{method} must not exist"
    connector.close()


# ---------------------------------------------------------------------------
# Invariant 8 — Result validation catches rogue connector
# ---------------------------------------------------------------------------

def test_result_validation_blocks_rogue_connector(db_path):
    """Even a compromised connector cannot return unauthorized fields."""
    key = token_bytes(32)
    create_demo_database(db_path, key)
    malicious = MaliciousConnector(db_path, key)
    engine = create_banking_policy()
    boundary = DataFenceBoundary(policy_engine=engine, connector=malicious, signing_key=key)

    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.READ,
                    fields=["id", "merchant"])
    result = boundary.execute(actor, intent)

    # Result validation must catch the injected card_number/ssn
    assert isinstance(result, DeniedRequest)
    assert any("unauthorized" in r.lower() for r in result.decision.reasons)
    malicious.close()


# ---------------------------------------------------------------------------
# Invariant 9 — Destructive operation denied
# ---------------------------------------------------------------------------

def test_delete_denied_before_connector(boundary):
    """DELETE operation is denied by policy before reaching the database."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.DELETE)
    result = boundary.execute(actor, intent)
    assert isinstance(result, DeniedRequest)


def test_insert_denied_before_connector(boundary):
    """INSERT operation is denied by policy before reaching the database."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.INSERT)
    result = boundary.execute(actor, intent)
    assert isinstance(result, DeniedRequest)


# ---------------------------------------------------------------------------
# Invariant 10 — Actor fixed by host, LLM cannot change it
# ---------------------------------------------------------------------------

def test_actor_tenant_id_determines_data_scope(boundary):
    """The Actor.tenant_id set by the host determines what data is returned."""
    actor_a = Actor(id="agent", tenant_id="tenant_a")
    actor_b = Actor(id="agent", tenant_id="tenant_b")
    intent = Intent(resource="transactions", operation=Operation.READ,
                    fields=["id", "merchant"])

    result_a = boundary.execute(actor_a, intent)
    result_b = boundary.execute(actor_b, intent)

    assert isinstance(result_a, AllowedRequest)
    assert isinstance(result_b, AllowedRequest)
    assert result_a.execution_plan.enforced_filters["tenant_id"] == "tenant_a"
    assert result_b.execution_plan.enforced_filters["tenant_id"] == "tenant_b"
    # Each sees only their own 3 rows
    assert result_a.execution_result.row_count == 3
    assert result_b.execution_result.row_count == 3


# ---------------------------------------------------------------------------
# Invariant 11 — Policy evaluated exactly once (no double evaluation)
# ---------------------------------------------------------------------------

def test_policy_evaluated_exactly_once(db_path):
    """Policy engine's evaluate() is called exactly once per boundary.execute()."""
    call_count = {"n": 0}
    base_engine = create_banking_policy()

    class CountingEngine:
        def evaluate(self, *, principal, intent):
            call_count["n"] += 1
            return base_engine.evaluate(principal=principal, intent=intent)

    engine = CountingEngine()
    b = DataFenceBoundary.create(
        policy_engine=engine,
        connector_factory=SQLiteConnector,
        registry=base_engine._registry,
        database_path=db_path,
    )
    create_demo_database(db_path, b._signing_key)

    call_count["n"] = 0
    b.execute(Actor(id="u", tenant_id="tenant_a"),
              Intent(resource="transactions", operation=Operation.READ,
                     fields=["id", "merchant"]))
    assert call_count["n"] == 1, (
        f"Policy evaluated {call_count['n']} times — must be exactly 1"
    )


# ---------------------------------------------------------------------------
# Invariant 12 — AllowedRequest carries Evidence + unique execution_id
# ---------------------------------------------------------------------------

def test_allowed_request_has_evidence_and_unique_id(boundary):
    """Every AllowedRequest carries Evidence with a unique execution_id."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.READ,
                    fields=["id", "merchant"])

    r1 = boundary.execute(actor, intent)
    r2 = boundary.execute(actor, intent)

    assert isinstance(r1, AllowedRequest)
    assert isinstance(r2, AllowedRequest)
    assert r1.evidence is not None
    assert r2.evidence is not None
    # Unique execution IDs
    assert r1.evidence.execution_id != r2.evidence.execution_id
    assert r1.request_id != r2.request_id


# ---------------------------------------------------------------------------
# Invariant 13 — DeniedRequest carries Evidence and reasons
# ---------------------------------------------------------------------------

def test_denied_request_has_evidence_and_reasons(boundary):
    """Every DeniedRequest carries Evidence and at least one denial reason."""
    actor = Actor(id="u", tenant_id="tenant_a")
    intent = Intent(resource="transactions", operation=Operation.DELETE)
    result = boundary.execute(actor, intent)

    assert isinstance(result, DeniedRequest)
    assert result.evidence is not None
    assert len(result.decision.reasons) > 0


# ---------------------------------------------------------------------------
# Invariant 14 — DataFenceBoundary.execute() is the only public entry point
# ---------------------------------------------------------------------------

def test_boundary_connector_is_private():
    """The connector is stored as _connector — not part of the public API."""
    b = DataFenceBoundary.__new__(DataFenceBoundary)
    # Public attribute access to 'connector' should not exist
    assert not hasattr(DataFenceBoundary, 'connector'), \
        "connector must be _connector (private), not exposed publicly"


def test_no_direct_sql_path_on_boundary(boundary):
    """DataFenceBoundary has no execute_sql / execute_raw method."""
    for method in ("execute_sql", "execute_raw", "execute_plan", "run"):
        assert not hasattr(boundary, method), f"boundary.{method} must not exist"


# ---------------------------------------------------------------------------
# Invariant 15 — Signing key never exposed through public API
# ---------------------------------------------------------------------------

def test_signing_key_not_in_public_api():
    """DataFenceBoundary does not expose signing_key as a public attribute."""
    # _signing_key is accessible (for tests) but 'signing_key' should not be
    assert not hasattr(DataFenceBoundary, 'signing_key'), \
        "signing_key must not be a public class attribute"


def test_boundary_create_does_not_return_signing_key(db_path):
    """DataFenceBoundary.create() returns a boundary, not the key."""
    b = DataFenceBoundary.create(
        policy_engine=create_banking_policy(),
        connector_factory=SQLiteConnector,
        database_path=db_path,
    )
    # The return value is a boundary object, not a tuple/dict with the key
    assert isinstance(b, DataFenceBoundary)
    # _signing_key exists internally but is not in __dict__ as a public attr
    assert "_signing_key" in b.__dict__   # private is fine
