"""
DataFence v0.1 — Security Regression: All Classical Attacks Blocked.

Verifies that the known attack vectors from pre-v1 are all blocked in v0.1.

Run from repo root:
    python attacks/verify_v01_blocks_attacks.py

Expected output: ALL ATTACKS BLOCKED
"""

from __future__ import annotations

import dataclasses
import sys
from secrets import token_bytes

from datafence import (
    ActionDecision,
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
    RowRule,
)
from datafence.core.resources import PredicateOperator
from datafence.errors import PolicyDeniedError


def _make_boundary(audience: str = "test") -> tuple[DataFenceBoundary, bytes]:
    registry = ResourceRegistry()
    registry.register(ResourceDefinition(
        "transactions",
        fields={
            "id":          FieldDefinition("id", "integer"),
            "tenant_id":   FieldDefinition("tenant_id", "string", is_tenant_key=True),
            "merchant":    FieldDefinition("merchant", "string"),
            "amount":      FieldDefinition("amount", "decimal"),
            "card_number": FieldDefinition("card_number", "string",
                                           classification=__import__("datafence").DataClassification.RESTRICTED),
        },
        supported_operations=("read",),
    ))
    policy = DataFencePolicy("test", "1.0", {"transactions": ResourcePolicy(
        "transactions",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id", "tenant_id", "merchant", "amount"],
        denied_fields=["card_number"],
        row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
        max_rows=100,
    )})
    engine = DataFencePolicyEngine(policy, registry=registry)
    key = token_bytes(32)
    return DataFenceBoundary.create(engine, registry, key, capability_audience=audience), key


passed = 0
failed = 0


def check(label: str, *, blocked: bool) -> None:
    global passed, failed
    status = "✅ BLOCKED" if blocked else "❌ NOT BLOCKED"
    print(f"  {status}  {label}")
    if blocked:
        passed += 1
    else:
        failed += 1


print("=" * 70)
print("  DataFence v0.1 — Security Attack Regression")
print("=" * 70)
print()

boundary, key = _make_boundary()
principal = Principal("user:alice", "tenant-a")

# ─────────────────────────────────────────────────────────────────────────────
# A. Capability forgery — constructing a capability without the signing key
# ─────────────────────────────────────────────────────────────────────────────
print("A. Capability forgery")

try:
    # Construct a fake capability dict and try to verify it
    fake_token = (
        '{"dfv":1,"execution_id":"forged","created_at":"2026-01-01T00:00:00+00:00",'
        '"actor_id":"attacker","actor_tenant_id":"evil","actor_roles":[],'
        '"actor_attributes":{},"resource":"transactions","operation":"read",'
        '"selected_fields":["id","card_number"],"predicates":[],"limit":999,'
        '"policy_version":"fake","policy_decisions":[],"obligations":{},'
        '"expires_at":"2099-01-01T00:00:00+00:00","audience":"test",'
        '"nonce":"aaa","sig":"' + "00" * 32 + '"}'
    )
    verifier = CapabilityVerifier(key, expected_audience="test")
    verifier.verify_token(fake_token)
    check("Forged token with wrong signature rejected", blocked=False)
except CapabilityVerificationError:
    check("Forged token with wrong signature rejected", blocked=True)

# ─────────────────────────────────────────────────────────────────────────────
# B. Capability tampering — modifying a valid capability
# ─────────────────────────────────────────────────────────────────────────────
print("\nB. Capability tampering")

cap = boundary.authorize(principal, Intent("transactions", Operation.READ, ["id", "merchant"]))
token = CapabilityToken.encode(cap)
import json as _json
data = _json.loads(token)

for field, val, label in [
    ("resource",          "employee_salaries", "resource field"),
    ("selected_fields",   ["id", "card_number"], "selected_fields"),
    ("actor_tenant_id",   "evil-tenant",         "tenant_id"),
    ("limit",             99999,                 "row limit"),
    ("actor_roles",       ["admin"],             "roles"),
    ("predicates",        [],                    "predicates (stripped)"),
]:
    tampered = dict(data)
    tampered[field] = val
    try:
        verifier = CapabilityVerifier(key, expected_audience="test")
        verifier.verify_token(_json.dumps(tampered))
        check(f"Tamper {label}", blocked=False)
    except CapabilityVerificationError:
        check(f"Tamper {label}", blocked=True)

# ─────────────────────────────────────────────────────────────────────────────
# C. Cross-tenant access — principal from tenant-a cannot read tenant-b
# ─────────────────────────────────────────────────────────────────────────────
print("\nC. Cross-tenant access")

cap_a = boundary.authorize(
    Principal("user:1", "tenant-a"),
    Intent("transactions", Operation.READ, ["id", "merchant"]),
)
predicates = cap_a.filter_constraints()
tenant_preds = [p for p in predicates if p["field"] == "tenant_id"]
check(
    "Policy-enforced tenant predicate present (tenant-a)",
    blocked=bool(tenant_preds and tenant_preds[0]["value"] == "tenant-a"),
)

# Agent tries to set tenant_id to tenant-b in intent
cap_cross = boundary.authorize(
    Principal("user:1", "tenant-a"),
    Intent("transactions", Operation.READ, filters={"tenant_id": "tenant-b"}),
)
cross_preds = [p for p in cap_cross.filter_constraints() if p["field"] == "tenant_id"]
check(
    "Agent-supplied tenant_id filter overridden by policy",
    blocked=not any(p["value"] == "tenant-b" for p in cross_preds),
)

# ─────────────────────────────────────────────────────────────────────────────
# D. Restricted field access
# ─────────────────────────────────────────────────────────────────────────────
print("\nD. Restricted field access")

try:
    boundary.authorize(
        principal,
        Intent("transactions", Operation.READ, fields=["id", "card_number"]),
    )
    check("RESTRICTED card_number denied in fields", blocked=False)
except PolicyDeniedError:
    check("RESTRICTED card_number denied in fields", blocked=True)

try:
    boundary.authorize(
        principal,
        Intent("transactions", Operation.READ, filters={"card_number": "1234"}),
    )
    check("RESTRICTED card_number denied as filter", blocked=False)
except PolicyDeniedError:
    check("RESTRICTED card_number denied as filter", blocked=True)

# ─────────────────────────────────────────────────────────────────────────────
# E. Unknown resource
# ─────────────────────────────────────────────────────────────────────────────
print("\nE. Unknown resource / operation")

try:
    boundary.authorize(principal, Intent("salary_data", Operation.READ))
    check("Unknown resource 'salary_data' denied", blocked=False)
except PolicyDeniedError:
    check("Unknown resource 'salary_data' denied", blocked=True)

try:
    boundary.authorize(principal, Intent("transactions", Operation.DELETE))
    check("Unsupported operation DELETE denied", blocked=False)
except PolicyDeniedError:
    check("Unsupported operation DELETE denied", blocked=True)

# ─────────────────────────────────────────────────────────────────────────────
# F. Short signing key
# ─────────────────────────────────────────────────────────────────────────────
print("\nF. Weak signing key")

try:
    reg2 = ResourceRegistry()
    reg2.register(ResourceDefinition(
        "things",
        fields={"id": FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True)},
        supported_operations=("read",),
    ))
    pol2 = DataFencePolicy("p", "1", {"things": ResourcePolicy(
        "things",
        actions={"read": ActionDecision.ALLOW},
        allowed_fields=["id"],
        row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
        max_rows=10,
    )})
    eng2 = DataFencePolicyEngine(pol2, registry=reg2)
    DataFenceBoundary.create(eng2, reg2, b"short_key")
    check("Short signing key rejected (< 32 bytes)", blocked=False)
except ValueError:
    check("Short signing key rejected (< 32 bytes)", blocked=True)

# ─────────────────────────────────────────────────────────────────────────────
# G. Wrong audience
# ─────────────────────────────────────────────────────────────────────────────
print("\nG. Audience mismatch")

b2, k2 = _make_boundary(audience="service-a")
cap2 = b2.authorize(principal, Intent("transactions", Operation.READ, ["id"]))
try:
    CapabilityVerifier(k2, expected_audience="service-b").verify(cap2)
    check("Wrong audience rejected", blocked=False)
except CapabilityVerificationError:
    check("Wrong audience rejected", blocked=True)

# ─────────────────────────────────────────────────────────────────────────────
# H. DataFenceBoundary has no execute() method
# ─────────────────────────────────────────────────────────────────────────────
print("\nH. Architecture boundary")

check(
    "DataFenceBoundary has no execute() method",
    blocked=not hasattr(boundary, "execute"),
)
check(
    "DataFenceBoundary stores no connector",
    blocked=not any(
        "connector" in a.lower() for a in vars(boundary)
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
print()
print("=" * 70)
print(f"  Passed: {passed}   Failed: {failed}")
if failed == 0:
    print("  ✅ All attacks blocked — v0.1 security regression passed.")
else:
    print("  ❌ SECURITY REGRESSION — some attacks not blocked!")
print("=" * 70)

sys.exit(0 if failed == 0 else 1)
