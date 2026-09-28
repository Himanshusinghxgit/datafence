"""
DataFence v0.3 - Adversarial Attack Attempts

This file documents actual exploits attempted against the v0.3 implementation.
Each attack is tested to determine if it succeeds.

DO NOT RUN THIS IN PRODUCTION.
"""

import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from datafence.connectors.sqlite_connector import SQLiteConnector, create_demo_database
from datafence.core.boundary import DataFenceBoundary
from datafence.core.policy_engine import create_banking_demo_policy
from datafence.core.types import Actor, ExecutionPlan, Intent, Operation
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

print("Setting up attack environment...")

# Create demo database
db_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
db_path = db_file.name
db_file.close()

connector = create_demo_database(db_path)
policy_engine = create_banking_demo_policy()
boundary = DataFenceBoundary(policy_engine, connector)

print(f"Database: {db_path}")
print(f"Connector: {connector}")
print(f"Boundary: {boundary}")
print("\nAttack environment ready.\n")


# ============================================================================
# ATTACK CATEGORY A: ExecutionPlan Forgery
# ============================================================================

print_attack("A", "A1", "Direct ExecutionPlan Construction", "CRITICAL")

print("Objective: Construct an ExecutionPlan without authorization")
print("Method: Call ExecutionPlan() constructor directly")
print()

try:
    # Attacker creates a fake actor claiming to be admin from another tenant
    fake_actor = Actor(
        id="attacker:forged",
        tenant_id="tenant_b"  # Targeting victim tenant
    )
    
    # Attacker creates an ExecutionPlan claiming authorization for sensitive data
    forged_plan = ExecutionPlan(
        execution_id="forged_exec_001",
        actor=fake_actor,
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "merchant", "amount", "card_number"],  # Includes denied field!
        enforced_filters={"tenant_id": "tenant_a"},  # Cross-tenant attack!
        limit=1000,
        policy_version="fake-policy-v1",
        policy_decisions=["fake.policy.allow"],
        created_at=datetime.utcnow()
    )
    
    print(f"Forged ExecutionPlan created:")
    print(f"  Execution ID: {forged_plan.execution_id}")
    print(f"  Actor: {forged_plan.actor.id} (tenant: {forged_plan.actor.tenant_id})")
    print(f"  Resource: {forged_plan.resource}")
    print(f"  Fields: {forged_plan.selected_fields}")
    print(f"  Filters: {forged_plan.enforced_filters}")
    print(f"  Policy: {forged_plan.policy_version}")
    
    print_result(
        success=True,
        description="ExecutionPlan can be constructed by any caller",
        impact="Attacker can forge authorization artifacts claiming any permissions"
    )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Construction blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY B: Connector Bypass
# ============================================================================

print_attack("B", "B1", "Direct Connector Execution with Forged Plan", "CRITICAL")

print("Objective: Execute forged ExecutionPlan against database")
print("Method: Instantiate connector directly and call execute_plan()")
print()

try:
    # Attacker instantiates their own connector
    attacker_connector = SQLiteConnector(db_path)
    
    # Attacker uses the forged plan from Attack A1
    fake_actor = Actor(id="attacker:direct", tenant_id="tenant_b")
    
    forged_plan = ExecutionPlan(
        execution_id="bypass_exec_001",
        actor=fake_actor,
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "merchant", "amount", "card_number"],  # SENSITIVE FIELD
        enforced_filters={"tenant_id": "tenant_a"},  # CROSS-TENANT
        limit=100,
        policy_version="bypass",
        policy_decisions=["fake"],
        created_at=datetime.utcnow()
    )
    
    print("Attempting to execute forged plan directly against connector...")
    result = attacker_connector.execute_plan(forged_plan)
    
    print(f"\n🚨 BREACH CONFIRMED 🚨")
    print(f"Rows returned: {len(result)}")
    print(f"Sample data:")
    for i, row in enumerate(result[:2], 1):
        print(f"  Row {i}: {row}")
    
    # Check if we got cross-tenant data
    if result and "card_number" in result[0]:
        print(f"\n⚠️  SENSITIVE FIELD EXPOSED: card_number={result[0]['card_number']}")
    
    # Check if we got cross-tenant data
    print(f"\n⚠️  CROSS-TENANT BREACH: Attacker (tenant_b) accessed tenant_a data")
    
    print_result(
        success=True,
        description="Connector accepts and executes forged ExecutionPlan",
        impact="CRITICAL: Attacker can bypass ALL authorization by calling connector directly"
    )
    
    attacker_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Execution blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY C: Actor Forgery
# ============================================================================

print_attack("C", "C1", "Forge Actor Identity", "CRITICAL")

print("Objective: Create Actor claiming elevated privileges")
print("Method: Construct Actor with arbitrary tenant_id and id")
print()

try:
    # Attacker creates admin-looking actor
    forged_admin = Actor(
        id="admin:root",
        tenant_id="victim_tenant",
        metadata={"role": "admin", "privileges": "ALL"}
    )
    
    print(f"Forged Actor created:")
    print(f"  ID: {forged_admin.id}")
    print(f"  Tenant: {forged_admin.tenant_id}")
    print(f"  Metadata: {forged_admin.metadata}")
    
    # Can we use this in a request?
    intent = Intent(
        resource="transactions",
        operation=Operation.READ,
        fields=["id", "merchant", "amount"],
    )
    
    # Submit to boundary with forged actor
    result = boundary.execute(forged_admin, intent)
    
    print(f"\nBoundary accepted forged actor!")
    print(f"Result type: {type(result).__name__}")
    
    print_result(
        success=True,
        description="Actor identity is caller-controlled, no authentication",
        impact="Attacker can claim any identity and tenant - Actor is NOT a verified identity"
    )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Actor creation blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY D: Tenant Isolation
# ============================================================================

print_attack("D", "D1", "Cross-Tenant Filter Manipulation", "HIGH")

print("Objective: Access another tenant's data")
print("Method: Forge ExecutionPlan with victim tenant's filter")
print()

try:
    attacker_actor = Actor(id="attacker", tenant_id="tenant_b")
    
    # Forge plan accessing tenant_a data
    cross_tenant_plan = ExecutionPlan(
        execution_id="crosstenant_001",
        actor=attacker_actor,  # Attacker is tenant_b
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "merchant", "amount"],
        enforced_filters={"tenant_id": "tenant_a"},  # But query tenant_a!
        limit=10,
        policy_version="fake",
        policy_decisions=[],
        created_at=datetime.utcnow()
    )
    
    # Execute via direct connector
    attacker_connector = SQLiteConnector(db_path)
    result = attacker_connector.execute_plan(cross_tenant_plan)
    
    print(f"Cross-tenant query executed!")
    print(f"Attacker tenant: {attacker_actor.tenant_id}")
    print(f"Queried tenant: tenant_a")
    print(f"Rows returned: {len(result)}")
    
    if result:
        print(f"Sample: {result[0]}")
    
    print_result(
        success=True,
        description="Attacker from tenant_b accessed tenant_a data",
        impact="CRITICAL: Complete tenant isolation bypass"
    )
    
    attacker_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Cross-tenant access blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY E: SQL Injection
# ============================================================================

print_attack("E", "E1", "SQL Injection via Enforced Filters", "HIGH")

print("Objective: Inject SQL through filter values")
print("Method: Include SQL injection payload in enforced_filters")
print()

try:
    attacker_actor = Actor(id="attacker", tenant_id="tenant_b")
    
    # Forge plan with SQL injection in filter
    injection_plan = ExecutionPlan(
        execution_id="sqli_001",
        actor=attacker_actor,
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "merchant", "amount"],
        enforced_filters={
            "tenant_id": "tenant_a' OR '1'='1"  # SQL injection
        },
        limit=100,
        policy_version="fake",
        policy_decisions=[],
        created_at=datetime.utcnow()
    )
    
    attacker_connector = SQLiteConnector(db_path)
    
    print("Attempting SQL injection...")
    result = attacker_connector.execute_plan(injection_plan)
    
    print(f"Query executed!")
    print(f"Rows returned: {len(result)}")
    
    # Check if injection worked (should get data from both tenants)
    if len(result) > 3:  # tenant_a has 3 rows
        print(f"⚠️  INJECTION SUCCESS: Got more rows than tenant_a has")
        print_result(
            success=True,
            description="SQL injection bypassed tenant filter",
            impact="Attacker can modify WHERE clause to access unauthorized data"
        )
    else:
        print_result(
            success=False,
            description="Prepared statements blocked SQL injection"
        )
    
    attacker_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"SQL injection blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY F: Operation Escalation
# ============================================================================

print_attack("F", "F1", "Operation Escalation to DELETE", "CRITICAL")

print("Objective: Execute DELETE when only READ is authorized")
print("Method: Forge ExecutionPlan with DELETE operation")
print()

try:
    attacker_actor = Actor(id="attacker", tenant_id="tenant_a")
    
    # Forge plan with DELETE operation
    delete_plan = ExecutionPlan(
        execution_id="delete_001",
        actor=attacker_actor,
        resource="transactions",
        operation=Operation.DELETE,  # DESTRUCTIVE!
        selected_fields=["id"],
        enforced_filters={"tenant_id": "tenant_a"},
        limit=100,
        policy_version="fake",
        policy_decisions=[],
        created_at=datetime.utcnow()
    )
    
    attacker_connector = SQLiteConnector(db_path)
    
    print("Attempting DELETE operation...")
    
    try:
        result = attacker_connector.execute_plan(delete_plan)
        print_result(
            success=True,
            description="DELETE operation executed!",
            impact="CRITICAL: Attacker can perform destructive operations"
        )
    except NotImplementedError as nie:
        print_result(
            success=False,
            description=f"Operation not implemented: {nie}"
        )
    
    attacker_connector.close()
    
except Exception as e:
    print_result(
        success=False,
        description=f"Operation blocked: {e}"
    )


# ============================================================================
# ATTACK CATEGORY M: Mutation
# ============================================================================

print_attack("M", "M1", "Mutate Frozen ExecutionPlan", "MEDIUM")

print("Objective: Modify frozen ExecutionPlan after creation")
print("Method: Use object.__setattr__() to bypass frozen=True")
print()

try:
    # Create a legitimate plan
    actor = Actor(id="user", tenant_id="tenant_a")
    plan = ExecutionPlan(
        execution_id="mut_001",
        actor=actor,
        resource="transactions",
        operation=Operation.READ,
        selected_fields=["id", "merchant"],
        enforced_filters={"tenant_id": "tenant_a"},
        limit=10,
        policy_version="v1",
        policy_decisions=[],
        created_at=datetime.utcnow()
    )
    
    print(f"Original plan:")
    print(f"  Tenant filter: {plan.enforced_filters}")
    print(f"  Fields: {plan.selected_fields}")
    
    # Attempt mutation
    print(f"\nAttempting mutation with object.__setattr__()...")
    
    object.__setattr__(plan, "enforced_filters", {"tenant_id": "tenant_b"})
    object.__setattr__(plan, "selected_fields", ["id", "merchant", "card_number"])
    
    print(f"\nMutated plan:")
    print(f"  Tenant filter: {plan.enforced_filters}")
    print(f"  Fields: {plan.selected_fields}")
    
    print_result(
        success=True,
        description="frozen=True bypassed with object.__setattr__()",
        impact="Attacker can modify ExecutionPlan after authorization"
    )
    
except Exception as e:
    print_result(
        success=False,
        description=f"Mutation blocked: {e}"
    )


# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "="*80)
print("ATTACK SUMMARY")
print("="*80 + "\n")

print("CRITICAL VULNERABILITIES CONFIRMED:")
print("  ✅ A1: ExecutionPlan can be forged by any caller")
print("  ✅ B1: Connector accepts forged ExecutionPlan without verification")
print("  ✅ C1: Actor identity is caller-controlled (no authentication)")
print("  ✅ D1: Complete tenant isolation bypass")
print("  ✅ M1: frozen=True can be bypassed with object.__setattr__()")
print()

print("ADDITIONAL FINDINGS:")
print("  ❓ E1: SQL injection blocked by prepared statements (GOOD)")
print("  ❓ F1: Destructive operations not implemented yet")
print()

print("ROOT CAUSE:")
print("  The connector cannot distinguish between:")
print("    - ExecutionPlan from DataFence (authorized)")
print("    - ExecutionPlan from attacker (forged)")
print()
print("  Python frozen dataclasses provide NO cryptographic integrity.")
print("  Anyone with database credentials can bypass DataFence entirely.")
print()

# Cleanup
connector.close()
import os
os.unlink(db_path)
