"""
Tests for policy evaluator.

Tests both allowed and denied scenarios.
"""

import pytest

from datafence.core.context import Actor, ActorType, RequestContext
from datafence.core.decision import DecisionStatus
from datafence.core.request import ExecutionRequest, Operation
from datafence.policy.evaluator import PolicyEvaluator
from datafence.policy.models import (
    FieldPolicy,
    Limits,
    OperationPolicy,
    Policy,
    ResourcePolicy,
)


@pytest.fixture
def simple_policy():
    """Simple test policy."""
    return Policy(
        version="1",
        name="test-policy",
        resources={
            "users": ResourcePolicy(
                operations=OperationPolicy(allow=[Operation.READ], deny=[Operation.DELETE]),
                fields=FieldPolicy(
                    allow=["user_id", "username", "email"],
                    deny=["password_hash", "api_key"],
                ),
                limits=Limits(max_rows=100),
            )
        },
    )


@pytest.fixture
def row_filter_policy():
    """Policy with row-level filters."""
    return Policy(
        version="1",
        name="tenant-policy",
        resources={
            "transactions": ResourcePolicy(
                operations=OperationPolicy(allow=[Operation.READ]),
                fields=FieldPolicy(allow=["transaction_id", "customer_id", "amount"]),
                row_filters={"customer_id": "{{ actor.customer_id }}"},
            )
        },
    )


def test_allow_valid_request(simple_policy):
    """Test that valid requests are allowed."""
    evaluator = PolicyEvaluator(simple_policy)

    request = ExecutionRequest(
        actor=Actor(id="test-agent", type=ActorType.AGENT),
        operation=Operation.READ,
        resource="users",
        fields=["user_id", "username"],
    )

    context = RequestContext(actor=request.actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.ALLOW
    assert decision.policy_name == "test-policy"
    assert len(decision.checks) > 0


def test_deny_nonexistent_resource(simple_policy):
    """Test that requests for nonexistent resources are denied."""
    evaluator = PolicyEvaluator(simple_policy)

    request = ExecutionRequest(
        actor=Actor(id="test-agent", type=ActorType.AGENT),
        operation=Operation.READ,
        resource="nonexistent",
        fields=["field1"],
    )

    context = RequestContext(actor=request.actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.DENY
    assert "not found in policy" in decision.reasons[0]


def test_deny_disallowed_operation(simple_policy):
    """Test that disallowed operations are denied."""
    evaluator = PolicyEvaluator(simple_policy)

    request = ExecutionRequest(
        actor=Actor(id="test-agent", type=ActorType.AGENT),
        operation=Operation.DELETE,
        resource="users",
    )

    context = RequestContext(actor=request.actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.DENY
    assert "denied" in decision.reasons[0].lower()


def test_deny_disallowed_field(simple_policy):
    """Test that requests for denied fields are blocked."""
    evaluator = PolicyEvaluator(simple_policy)

    request = ExecutionRequest(
        actor=Actor(id="test-agent", type=ActorType.AGENT),
        operation=Operation.READ,
        resource="users",
        fields=["user_id", "password_hash"],  # password_hash is denied
    )

    context = RequestContext(actor=request.actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.DENY
    assert "password_hash" in decision.reasons[0]


def test_deny_field_not_in_allow_list(simple_policy):
    """Test that fields not in allow list are denied."""
    evaluator = PolicyEvaluator(simple_policy)

    request = ExecutionRequest(
        actor=Actor(id="test-agent", type=ActorType.AGENT),
        operation=Operation.READ,
        resource="users",
        fields=["user_id", "secret_field"],  # secret_field not in allow list
    )

    context = RequestContext(actor=request.actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.DENY
    assert "secret_field" in decision.reasons[0]


def test_row_filter_validation_success(row_filter_policy):
    """Test that row filters are validated correctly."""
    evaluator = PolicyEvaluator(row_filter_policy)

    actor = Actor(id="agent-123", type=ActorType.AGENT, attributes={"customer_id": "customer-123"})

    request = ExecutionRequest(
        actor=actor,
        operation=Operation.READ,
        resource="transactions",
        fields=["transaction_id", "amount"],
        filters={"customer_id": "customer-123"},  # Matches actor
    )

    context = RequestContext(actor=actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.ALLOW


def test_row_filter_validation_failure_missing(row_filter_policy):
    """Test that missing row filters cause denial."""
    evaluator = PolicyEvaluator(row_filter_policy)

    actor = Actor(id="agent-123", type=ActorType.AGENT, attributes={"customer_id": "customer-123"})

    request = ExecutionRequest(
        actor=actor,
        operation=Operation.READ,
        resource="transactions",
        fields=["transaction_id", "amount"],
        filters={},  # Missing customer_id filter
    )

    context = RequestContext(actor=actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.DENY
    assert "missing" in decision.reasons[0].lower()


def test_row_filter_validation_failure_mismatch(row_filter_policy):
    """Test that mismatched row filters cause denial (tenant isolation)."""
    evaluator = PolicyEvaluator(row_filter_policy)

    actor = Actor(id="agent-123", type=ActorType.AGENT, attributes={"customer_id": "customer-123"})

    request = ExecutionRequest(
        actor=actor,
        operation=Operation.READ,
        resource="transactions",
        fields=["transaction_id", "amount"],
        filters={"customer_id": "customer-456"},  # Different customer!
    )

    context = RequestContext(actor=actor)

    decision = evaluator.evaluate(request, context)

    assert decision.status == DecisionStatus.DENY
    assert "mismatch" in decision.reasons[0].lower()
