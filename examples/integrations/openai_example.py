"""
OpenAI function-calling integration example.

Demonstrates using DataFence with OpenAI's function/tool calling API.

Architecture::

    GPT-4 / GPT-4o
        │  tool call: {"name": "datafence_query", "arguments": {...}}
        ▼
    DataFenceOpenAITool.handle_call(principal, arguments_json)
        │  constructs Intent from model args (untrusted)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        │  Registry → Policy → AuthorizedExecution (signed)
        ▼
    JSON capability returned to caller
        │
        ▼  pass to your connector
    Customer-owned connector → enterprise data

Run with:
    pip install 'datafence[integrations]' openai
    export OPENAI_API_KEY=sk-...
    python openai_example.py
"""

from __future__ import annotations

import json
from secrets import token_bytes

from datafence import (
    ActionDecision,
    DataFenceBoundary,
    DataFencePolicy,
    DataFencePolicyEngine,
    FieldDefinition,
    Principal,
    ResourceDefinition,
    ResourcePolicy,
    ResourceRegistry,
    RowRule,
)
from datafence.core.resources import PredicateOperator
from datafence.integrations.openai_tool import DataFenceOpenAITool

# ---------------------------------------------------------------------------
# 1. Build the registry — what resources exist
# ---------------------------------------------------------------------------

def _make_boundary() -> tuple[DataFenceBoundary, bytes]:
    registry = ResourceRegistry()
    registry.register(
        ResourceDefinition(
            "orders",
            fields={
                "id":        FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "total":     FieldDefinition("total", "decimal"),
                "status":    FieldDefinition("status", "string"),
                "merchant":  FieldDefinition("merchant", "string"),
            },
            supported_operations=("read",),
        )
    )

    # 2. Define the policy — who can do what
    policy = DataFencePolicy(
        "orders-policy",
        "1.0",
        {
            "orders": ResourcePolicy(
                "orders",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "total", "status", "merchant"],
                row_rules=[
                    RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id"),
                ],
                max_rows=50,
            )
        },
    )
    engine = DataFencePolicyEngine(policy, registry=registry)

    # 3. Create the boundary — keep the key secret in production
    signing_key = token_bytes(32)
    boundary = DataFenceBoundary.create(
        engine, registry, signing_key,
        capability_audience="orders-service",
    )
    return boundary, signing_key


# ---------------------------------------------------------------------------
# Example A: direct tool call (no live OpenAI call required)
# ---------------------------------------------------------------------------

def example_direct_tool_call() -> None:
    """
    Demonstrate the authorization flow without a live OpenAI connection.

    This simulates what happens when the model issues a function call:
    the tool argument JSON becomes Intent; the Principal comes from your
    auth layer.
    """
    print("=" * 60)
    print("OpenAI DataFence Tool — direct call (no API key needed)")
    print("=" * 60)

    boundary, signing_key = _make_boundary()
    tool = DataFenceOpenAITool(boundary, tool_name="datafence_query")

    # Inspect the tool spec (sent to OpenAI in the `tools=` parameter)
    spec = tool.openai_tool_spec()
    print(f"\n1. Tool spec name  : {spec['function']['name']}")
    print(f"   Description     : {spec['function']['description'][:70]}...")

    # Simulate the arguments the model would produce
    model_arguments = json.dumps({
        "resource": "orders",
        "fields": ["id", "total", "status"],
        "filters": {"merchant": "Acme Corp"},
        "limit": 5,
    })

    # Principal from YOUR auth layer — never from model output
    principal = Principal(id="user:alice", tenant_id="tenant-acme")

    result_json = tool.handle_call(
        principal=principal,
        arguments_json=model_arguments,
    )
    result = json.loads(result_json)

    print(f"\n2. Authorization result: {result['status']}")
    if result["status"] == "authorized":
        print(f"   execution_id   : {result['execution_id']}")
        print(f"   resource       : {result['resource']}")
        print(f"   authorized fields: {result['fields']}")
        print(f"   predicates     : {result['predicates']}")
        print(f"   limit          : {result['limit']}")
        print()
        print("   → Pass this capability to YOUR connector for execution.")
        print("     DataFence does NOT execute the query.")
    else:
        print(f"   reasons: {result['reasons']}")

    # Show denial path: requesting a disallowed operation
    deny_args = json.dumps({"resource": "orders", "operation": "delete"})
    denied_json = tool.handle_call(principal=principal, arguments_json=deny_args)
    denied = json.loads(denied_json)
    print(f"\n3. Denial example — status: {denied['status']}")
    print(f"   reasons: {denied['reasons']}")


# ---------------------------------------------------------------------------
# Example B: live OpenAI call (requires OPENAI_API_KEY)
# ---------------------------------------------------------------------------

def example_with_live_openai() -> None:
    """
    Full end-to-end with a real OpenAI model.
    Requires: pip install openai && export OPENAI_API_KEY=sk-...
    """
    print("\n" + "=" * 60)
    print("OpenAI DataFence Tool — live model call")
    print("=" * 60)

    try:
        import openai
    except ImportError:
        print("⚠️  openai package not installed: pip install openai")
        return

    boundary, _ = _make_boundary()
    tool = DataFenceOpenAITool(boundary)

    # Principal from your auth layer
    principal = Principal(id="user:alice", tenant_id="tenant-acme")

    client = openai.OpenAI()
    messages = [{"role": "user", "content": "Show me my recent orders."}]

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=[tool.openai_tool_spec()],
            tool_choice="auto",
        )

        message = response.choices[0].message
        for tc in message.tool_calls or []:
            if tc.function.name == tool.tool_name:
                result_json = tool.handle_call(
                    principal=principal,
                    arguments_json=tc.function.arguments,
                )
                result = json.loads(result_json)
                print(f"\nModel requested: {tc.function.arguments}")
                print(f"Authorization  : {result['status']}")
                if result["status"] == "authorized":
                    print(f"Capability     : execution_id={result['execution_id']}")
                    print("→ Pass to your connector to retrieve data.")
                else:
                    print(f"Denied         : {result['reasons']}")

    except Exception as exc:
        print(f"⚠️  OpenAI error: {exc}")
        print("   Set OPENAI_API_KEY and try again.")


if __name__ == "__main__":
    example_direct_tool_call()
    example_with_live_openai()
    print("\n" + "=" * 60)
    print("✓ Example complete")
