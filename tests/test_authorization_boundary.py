"""Authorization boundary integration tests."""

from __future__ import annotations

from secrets import token_bytes

import pytest

from datafence import (
    AuthorizedExecution,
    CapabilityVerifier,
    DataFenceBoundary,
    Intent,
    Operation,
    Principal,
)
from datafence.core.capability import CapabilityVerificationError
from datafence.core.policy import (
    ActionDecision,
    DataFencePolicy,
    DataFencePolicyEngine,
    ResourcePolicy,
    RowRule,
    YAMLPolicyLoader,
)
from datafence.core.registry import FieldDefinition, ResourceDefinition, ResourceRegistry
from datafence.core.resources import PredicateOperator
from datafence.errors import PolicyDeniedError


def make_boundary() -> tuple[DataFenceBoundary, bytes, ResourceRegistry]:
    registry = ResourceRegistry()
    registry.register(
        ResourceDefinition(
            "customers",
            fields={
                "id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "status": FieldDefinition("status", "string"),
            },
            supported_operations=("read",),
        )
    )
    policy = DataFencePolicy(
        "generic-policy",
        "1.0",
        {
            "customers": ResourcePolicy(
                "customers",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "status"],
                row_rules=[
                    RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id"),
                ],
                max_rows=25,
            )
        },
    )
    engine = DataFencePolicyEngine(policy, registry=registry)
    key = token_bytes(32)
    return DataFenceBoundary.create(engine, registry, key), key, registry


def test_authorize_returns_capability_without_connector():
    boundary, key, _ = make_boundary()
    capability = boundary.authorize(
        Principal("user:1", "tenant-a"),
        Intent("customers", Operation.READ, ["id", "status"]),
    )
    assert isinstance(capability, AuthorizedExecution)
    assert capability.resource == "customers"
    CapabilityVerifier(key).verify(capability)
    assert not hasattr(boundary, "execute")
    assert not hasattr(boundary, "_connector")


def test_customer_verifier_rejects_tampering():
    boundary, key, _ = make_boundary()
    capability = boundary.authorize(
        Principal("user:1", "tenant-a"), Intent("customers", Operation.READ)
    )
    import dataclasses

    tampered = dataclasses.replace(capability, resource="other_resource")
    with pytest.raises(CapabilityVerificationError):
        CapabilityVerifier(key).verify(tampered)


def test_policy_denial_never_produces_capability():
    boundary, _, _ = make_boundary()
    with pytest.raises(PolicyDeniedError):
        boundary.authorize(
            Principal("user:1", "tenant-a"),
            Intent("customers", Operation.INSERT),
        )


def test_registry_is_required_and_frozen():
    registry = ResourceRegistry()
    policy = DataFencePolicy("p", "1", {})
    with pytest.raises(ValueError):
        DataFencePolicyEngine(policy, registry=None)  # type: ignore[arg-type]
    boundary, _, registry = make_boundary()
    assert boundary.registry is registry
    with pytest.raises(RuntimeError):
        registry.register(ResourceDefinition("new_resource"))


def test_lossless_predicates_are_carried_to_customer_backend():
    boundary, key, _ = make_boundary()
    capability = boundary.authorize(
        Principal("user:1", "tenant-a"),
        Intent("customers", Operation.READ),
    )
    CapabilityVerifier(key).verify(capability)
    # Policy-enforced tenant predicate must be present
    assert any(p["field"] == "tenant_id" for p in capability.filter_constraints())


def test_unknown_yaml_operator_fails_closed():
    with pytest.raises(ValueError):
        YAMLPolicyLoader.from_dict(
            {
                "name": "p",
                "version": "1",
                "resources": {
                    "customers": {
                        "actions": {"read": "allow"},
                        "fields": {"allow": ["id"]},
                        "rows": [{"field": "id", "operator": "wat", "value": 1}],
                    }
                },
            }
        )


def test_actor_not_in_public_api():
    """Actor alias has been removed — Principal is the canonical type."""
    import datafence

    assert not hasattr(datafence, "Actor"), "Actor must not be in the public API — use Principal"
