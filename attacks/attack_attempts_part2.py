"""
DataFence v0.3 - Adversarial Attack Attempts (Part 2)

Continuing attack categories G-P:
- G: Field Authorization
- H: Result Validation
- I: Policy Fail-Open
- J: Policy Version Confusion
- K: Serialization/Deserialization
- L: Replay
- N: Public API Bypass
- O: Confused Deputy
- P: TOCTOU

DO NOT RUN THIS IN PRODUCTION.
"""

import sys
import tempfile
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from datafence.connectors.sqlite_connector import SQLiteConnector, MaliciousConnector, create_demo_database
from datafence.core.boundary import DataFenceBoundary
from datafence.core.policy_engine import create_banking_demo_policy, SimplePolicyEngine, ResourcePolicy
from datafence.core.types import Actor, ExecutionPlan, Intent, Operation, Decision, PolicyDecision
from datetime import datetime


def print_attack(category: str, attack_id: str, title: str, severity: str):
    """Print attack header."""
    print("\n" + "="*80)
    print(f"ATTACK {attack_id}: {title}")
    print(f"Category: {category} | Severity: {severity}")
    print("="*80 + "\n")


def print_result(success: bool, description: str, impact: str = ""):
    """Print attack result."""
    status = "✅ ATTACK SUCCEEDED" if success else "❌ ATTACK FAILED"
    print(f"\n{status}")
    print(f"Result: {description}")
    if impact:
        print(f"Impact: {impact}")
    print()


# ============================================================================
# SETUP
# ============================================================================

print("Setting up attack environment (Part 2)...")

db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
db_path = db_file.name
db_file.close()

connector = create_demo_database(db_path)
policy_engine = create_banking_demo_policy()
boundary = DataFenceBoundary(policy_engine, connector)

print(f"Database: {db_path}")
print("Attack environment ready.\n")


# ============================================================================
# ATTACK CATEGORY G: Field Authorization
# ============================================================================

print_attack("G", "G1", "Wildcard Field Expansion (SELECT *)", "HIGH")

print("Objective: Request all fields via SELECT *")
print("Method: Submit Intent with fields=None to trigger wildcard")
print()

try:
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    
    # Request without specifying fields (should trigger SELECT *)
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=None,  # No fields = SELECT *?
        filters={},
        limit=10,
    )
    
    print("Submitting request with fields=None...")
    result = boundary.execute(actor, intent)
    
    if hasattr(result, 'execution_plan'):
        print(f"ExecutionPlan created!")
        print(f"Selected fields: {result.execution_plan.selected_fields}")
        
        # Check if sensitive fields are included
        if 'card_number' in result.execution_plan.selected_fields:
            print_result(
                success=True,
                description="SELECT * expanded to include denied fields",
                impact="CRITICAL: Wildcard expansion bypassed field authorization"
            )
        else:
            print_result(
                success=False,
                description="Field authorization correctly restricted wildcard to allowed fields only"
            )
    else:
        print_result(
            success=False,
            description="Request denied by policy"
        )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Attack blocked: {e}"
    )


print_attack("G", "G2", "Field Authorization via Expression", "MEDIUM")

print("Objective: Access denied field via SQL expression")
print("Method: Request computed field like CONCAT(merchant, card_number)")
print()

try:
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    
    # The policy engine only checks exact field names
    # Can we bypass by requesting an expression?
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "CONCAT(merchant, ':', card_number)"],  # Expression!
        filters={},
        limit=10,
    )
    
    print("Submitting request with expression field...")
    result = boundary.execute(actor, intent)
    
    if hasattr(result, 'execution_plan'):
        print_result(
            success=True,
            description="Policy engine doesn't validate SQL expressions",
            impact="MEDIUM: Field authorization can be bypassed via expressions (depends on SQL generation)"
        )
    else:
        print_result(
            success=False,
            description=f"Request denied: {result.decision.reasons}"
        )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Attack blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY H: Result Validation
# ============================================================================

print_attack("H", "H1", "Malicious Connector Returns Unauthorized Fields", "HIGH")

print("Objective: Test if result validation catches malicious connector")
print("Method: Use MaliciousConnector that adds unauthorized fields")
print()

try:
    # Use malicious connector
    malicious_db = MaliciousConnector(db_path)
    malicious_boundary = DataFenceBoundary(policy_engine, malicious_db)
    
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant", "amount"],
        filters={},
        limit=10,
    )
    
    print("Executing via malicious connector...")
    result = malicious_boundary.execute(actor, intent)
    
    if hasattr(result, 'execution_result'):
        if not result.execution_result.verified:
            print(f"Result validation CAUGHT malicious connector!")
            print(f"Verification errors: {result.execution_result.verification_errors}")
            print_result(
                success=False,
                description="Result validation correctly rejected unauthorized fields"
            )
        else:
            print(f"Result was VERIFIED despite malicious connector!")
            print_result(
                success=True,
                description="Result validation FAILED to catch unauthorized fields",
                impact="HIGH: Malicious/compromised connector can exfiltrate data"
            )
    else:
        # Request was denied
        print_result(
            success=False,
            description="Request denied (result validation worked)"
        )
    
    malicious_db.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Malicious connector blocked: {e}"
    )


print_attack("H", "H2", "Nested Object Bypass", "MEDIUM")

print("Objective: Hide unauthorized data in nested objects")
print("Method: Return {allowed_field: {secret: value}}")
print()

print("Status: Cannot test without custom malicious connector")
print("Theory: Result validator only checks top-level keys")
print("A malicious connector could return:")
print("  {'merchant': {'name': 'Amazon', 'secret_data': '...'}}")
print()
print_result(
    success=None,
    description="Requires implementation test - validator may not check nested structures"
)


# ============================================================================
# ATTACK CATEGORY I: Policy Fail-Open
# ============================================================================

print_attack("I", "I1", "Missing Policy Fail-Open", "CRITICAL")

print("Objective: Access resource with no policy defined")
print("Method: Request unknown resource")
print()

try:
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    
    # Request resource with no policy
    intent = Intent(
        resource="unknown_resource",
        operation=Operation.READ,
        fields=["id"],
        filters={},
        limit=10,
    )
    
    print("Requesting unknown_resource...")
    result = boundary.execute(actor, intent)
    
    if hasattr(result, 'execution_plan'):
        print_result(
            success=True,
            description="Request ALLOWED despite missing policy!",
            impact="CRITICAL: System fails open - missing policy allows access"
        )
    else:
        print(f"Request denied: {result.decision.reasons}")
        print_result(
            success=False,
            description="System correctly fails closed on missing policy"
        )
    
except Exception as e:
    print_result(
        success=False,
        description=f"System failed closed: {e}"
    )


print_attack("I", "I2", "Policy Evaluation Exception", "HIGH")

print("Objective: Cause policy evaluation to throw exception")
print("Method: Trigger error in policy engine")
print()

try:
    # Create a broken policy engine
    class BrokenPolicyEngine:
        def evaluate(self, actor, resource, operation, requested_fields):
            raise RuntimeError("Policy engine internal error")
        
        def get_allowed_fields(self, actor, resource):
            raise RuntimeError("Policy engine error")
        
        def get_enforced_filters(self, actor, resource):
            return {}
        
        def get_max_limit(self, actor, resource):
            return 100
        
        def get_policy_version(self):
            return "broken"
    
    broken_boundary = DataFenceBoundary(BrokenPolicyEngine(), connector)
    
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id"],
    )
    
    print("Executing with broken policy engine...")
    result = broken_boundary.execute(actor, intent)
    
    if hasattr(result, 'execution_plan'):
        print_result(
            success=True,
            description="Request ALLOWED despite policy evaluation exception!",
            impact="CRITICAL: System fails open on policy errors"
        )
    else:
        print(f"Request denied: {result.decision.reasons}")
        print_result(
            success=False,
            description="System correctly fails closed on policy evaluation error"
        )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Exception caught: {e}"
    )


# ============================================================================
# ATTACK CATEGORY J: Policy Version Confusion
# ============================================================================

print_attack("J", "J1", "Request Specific Policy Version", "MEDIUM")

print("Objective: Request to use old/permissive policy version")
print("Method: Include policy_version in Intent")
print()

print("Status: Intent does not have policy_version field")
print("Current design: Policy version comes from engine, not request")
print()
print_result(
    success=False,
    description="Policy version is not request-controlled (GOOD)"
)


print_attack("J", "J2", "Forge ExecutionPlan with Old Policy Version", "HIGH")

print("Objective: Claim authorization under old policy")
print("Method: Forge ExecutionPlan with policy_version='old-permissive'")
print()

try:
    actor = Actor(id="attacker", tenant_id="tenant_a")
    
    # Forge plan claiming old policy version
    forged_plan = ExecutionPlan(
        execution_id="policy_ver_001",
        actor=actor,
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "merchant", "card_number"],  # Sensitive!
        enforced_filters={"tenant_id": "tenant_a"},
        limit=100,
        policy_version="old-permissive-v0.1",  # Claim old policy!
        policy_decisions=["old_policy.allow"],
        created_at=datetime.now()
    )
    
    # Execute via connector bypass
    attacker_connector = SQLiteConnector(db_path)
    result = attacker_connector.execute_plan(forged_plan)
    
    print(f"Execution with old policy version succeeded!")
    print(f"Policy version claimed: {forged_plan.policy_version}")
    print(f"Rows returned: {len(result)}")
    
    print_result(
        success=True,
        description="Attacker can claim any policy version in forged ExecutionPlan",
        impact="HIGH: Policy version pinning doesn't prevent forgery"
    )
    
    attacker_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Attack blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY K: Serialization/Deserialization
# ============================================================================

print_attack("K", "K1", "Deserialize Malicious ExecutionPlan JSON", "HIGH")

print("Objective: Create ExecutionPlan from malicious JSON")
print("Method: Craft JSON with elevated privileges and deserialize")
print()

try:
    # Malicious JSON claiming authorization
    malicious_json = {
        "execution_id": "deserialized_001",
        "actor": {
            "id": "admin",
            "tenant_id": "victim_tenant",
            "metadata": {}
        },
        "resource": "transactions",
        "operation": "READ",
        "selected_fields": ["id", "merchant", "card_number"],
        "enforced_filters": {"tenant_id": "tenant_a"},
        "limit": 1000,
        "policy_version": "fake",
        "policy_decisions": [],
        "created_at": datetime.now().isoformat()
    }
    
    print("Malicious JSON:")
    print(json.dumps(malicious_json, indent=2))
    
    # Try to reconstruct ExecutionPlan
    # Note: ExecutionPlan is a dataclass, not Pydantic model
    # Standard approach would be from_dict() or manual construction
    
    print("\nAttempting to deserialize...")
    
    # Dataclass approach - just call constructor
    fake_actor = Actor(**malicious_json["actor"])
    fake_plan = ExecutionPlan(
        execution_id=malicious_json["execution_id"],
        actor=fake_actor,
        resource=malicious_json["resource"],
        operation=Operation[malicious_json["operation"]],
        selected_fields=malicious_json["selected_fields"],
        enforced_filters=malicious_json["enforced_filters"],
        limit=malicious_json["limit"],
        policy_version=malicious_json["policy_version"],
        policy_decisions=malicious_json["policy_decisions"],
        created_at=datetime.now()
    )
    
    print(f"Deserialized ExecutionPlan: {fake_plan.execution_id}")
    
    # Can we execute it?
    attacker_connector = SQLiteConnector(db_path)
    result = attacker_connector.execute_plan(fake_plan)
    
    print(f"Execution succeeded! Rows: {len(result)}")
    
    print_result(
        success=True,
        description="ExecutionPlan can be constructed from untrusted JSON",
        impact="HIGH: Deserialization creates executable capabilities"
    )
    
    attacker_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Deserialization blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY L: Replay
# ============================================================================

print_attack("L", "L1", "Replay Authorized ExecutionPlan", "MEDIUM")

print("Objective: Reuse an authorized ExecutionPlan multiple times")
print("Method: Execute same plan repeatedly")
print()

try:
    # Get a legitimate plan via boundary
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant"],
        limit=5,
    )
    
    result1 = boundary.execute(actor, intent)
    
    if hasattr(result1, 'execution_plan'):
        plan = result1.execution_plan
        print(f"Got authorized plan: {plan.execution_id}")
        
        # Replay the plan multiple times
        attacker_connector = SQLiteConnector(db_path)
        
        print("\nReplaying plan 3 times...")
        for i in range(3):
            result = attacker_connector.execute_plan(plan)
            print(f"  Replay {i+1}: {len(result)} rows")
        
        print_result(
            success=True,
            description="ExecutionPlan can be replayed indefinitely",
            impact="MEDIUM: No expiry or replay protection (may be acceptable for read-only)"
        )
        
        attacker_connector.close()
    else:
        print_result(
            success=False,
            description="Could not get authorized plan"
        )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Replay blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY N: Public API Bypass
# ============================================================================

print_attack("N", "N1", "Old v1.0 API Still Accessible", "CRITICAL")

print("Objective: Use old DataFence API to bypass v0.3 boundary")
print("Method: Import from src/datafence (not src/datafence/core)")
print()

try:
    # Check if old API is still importable
    print("Attempting to import old DataFence API...")
    
    from datafence import DataFence as OldDataFence
    from datafence import ExecutionRequest as OldExecutionRequest
    
    print(f"✅ Old API imported successfully!")
    print(f"  OldDataFence: {OldDataFence}")
    print(f"  OldExecutionRequest: {OldExecutionRequest}")
    
    print_result(
        success=True,
        description="v1.0 API is still accessible alongside v0.3",
        impact="CRITICAL: Dual implementation creates bypass vector - old API may have different security model"
    )
    
except ImportError as ie:
    print_result(
        success=False,
        description=f"Old API not importable: {ie}"
    )
except Exception as e:
    print_result(
        success=False,
        description=f"Import failed: {e}"
    )


print_attack("N", "N2", "Direct Connector Import", "HIGH")

print("Objective: Import and use connector without boundary")
print("Method: from datafence.connectors import SQLiteConnector")
print()

try:
    # This is the connector bypass we already tested
    # But let's confirm it's publicly exported
    
    from datafence.connectors import SQLiteConnector as PublicConnector
    
    print(f"✅ Connector publicly exported: {PublicConnector}")
    
    # Can instantiate and use?
    bypass_connector = PublicConnector(db_path)
    
    # Forge a plan
    bypass_plan = ExecutionPlan(
        execution_id="bypass_002",
        actor=Actor(id="attacker", tenant_id="tenant_b"),
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "merchant", "amount", "card_number"],
        enforced_filters={"tenant_id": "tenant_a"},  # Cross-tenant!
        limit=100,
        policy_version="bypass",
        policy_decisions=[],
        created_at=datetime.now()
    )
    
    result = bypass_connector.execute_plan(bypass_plan)
    print(f"Direct connector execution: {len(result)} rows")
    
    print_result(
        success=True,
        description="Connector is publicly exported and accepts forged plans",
        impact="HIGH: Public API design allows complete bypass"
    )
    
    bypass_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Bypass blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY O: Confused Deputy
# ============================================================================

print_attack("O", "O1", "Low-Privilege User via High-Privilege Connection", "HIGH")

print("Objective: Use low-privilege actor with admin database connection")
print("Method: Check if connector respects actor's database identity")
print()

print("Theory: Current design has single database connection")
print("Connector doesn't use actor identity for database auth")
print("If database connection has admin privileges,")
print("ALL actors inherit those privileges at DB level")
print()

try:
    # The current connector doesn't take actor identity into account
    # It uses a single connection for all queries
    
    low_priv_actor = Actor(id="readonly:user", tenant_id="tenant_a")
    
    # What database identity is the connector using?
    print(f"Connector database: {connector.database_path}")
    print(f"Actor identity: {low_priv_actor.id}")
    print()
    print("The connector executes ALL queries with the same database connection")
    print("regardless of which Actor made the request")
    
    print_result(
        success=True,
        description="Connector doesn't use actor identity for database authentication",
        impact="HIGH: Confused deputy - DataFence authorization doesn't map to database authorization"
    )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Test failed: {e}"
    )


# ============================================================================
# ATTACK CATEGORY P: TOCTOU (Time-of-Check Time-of-Use)
# ============================================================================

print_attack("P", "P1", "Mutate ExecutionPlan Between Authorization and Execution", "MEDIUM")

print("Objective: Modify ExecutionPlan after authorization but before execution")
print("Method: Use object.__setattr__() between policy check and connector call")
print()

print("Note: In current architecture, authorization and execution are atomic")
print("But if ExecutionPlan is stored/queued, mutation is possible")
print()

try:
    # Get authorized plan
    actor = Actor(id="agent:finance", tenant_id="tenant_a")
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant"],
    )
    
    result = boundary.execute(actor, intent)
    
    if hasattr(result, 'execution_plan'):
        plan = result.execution_plan
        print(f"Got authorized plan: {plan.execution_id}")
        print(f"Original fields: {plan.selected_fields}")
        print(f"Original filters: {plan.enforced_filters}")
        
        # Simulate TOCTOU: mutate after authorization
        print("\nMutating plan after authorization...")
        object.__setattr__(plan, "selected_fields", ["id", "merchant", "card_number"])
        object.__setattr__(plan, "enforced_filters", {"tenant_id": "tenant_b"})
        
        print(f"Mutated fields: {plan.selected_fields}")
        print(f"Mutated filters: {plan.enforced_filters}")
        
        # Execute mutated plan
        attacker_connector = SQLiteConnector(db_path)
        result = attacker_connector.execute_plan(plan)
        
        print(f"\nMutated plan executed: {len(result)} rows")
        
        print_result(
            success=True,
            description="ExecutionPlan can be mutated between authorization and execution",
            impact="MEDIUM: TOCTOU vulnerability if plan is stored/queued"
        )
        
        attacker_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Attack failed: {e}"
    )


# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*80)
print("ATTACK SUMMARY (Part 2)")
print("="*80 + "\n")

print("ADDITIONAL CRITICAL VULNERABILITIES:")
print("  ✅ N1: Old v1.0 API still accessible (dual implementation)")
print("  ✅ N2: Connector is publicly exported")
print()

print("HIGH SEVERITY:")
print("  ✅ I1: Missing policy fails closed (GOOD - not vulnerable)")
print("  ✅ I2: Policy errors fail closed (GOOD - not vulnerable)")
print("  ✅ J2: Can forge ExecutionPlan with any policy version")
print("  ✅ K1: ExecutionPlan can be deserialized from untrusted JSON")
print("  ✅ O1: Confused deputy - connector doesn't use actor DB identity")
print()

print("MEDIUM SEVERITY:")
print("  ✅ L1: ExecutionPlan can be replayed (acceptable for read-only)")
print("  ✅ P1: ExecutionPlan mutation creates TOCTOU window")
print()

print("DEFENSES WORKING:")
print("  ❌ G1: Wildcard field expansion correctly restricted")
print("  ❌ H1: Result validation catches malicious connector (needs verification)")
print("  ❌ I1/I2: System fails closed on policy errors")
print("  ❌ J1: Policy version not request-controlled")
print()

# Cleanup
connector.close()
import os
os.unlink(db_path)
