"""
Anthropic Claude tool-use integration example.

Demonstrates using DataFence with Claude's tool use API.

Architecture::

    Claude 3.x
        │  tool_use block: {"name": "datafence_query", "input": {...}}
        ▼
    DataFenceAnthropicTool.handle_call(principal, tool_input)
        │  constructs Intent from block input (untrusted)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        │  Registry → Policy → AuthorizedExecution (signed)
        ▼
    JSON capability returned as tool_result
        │
        ▼  pass to your connector
    Customer-owned connector → enterprise data

Run with:
    pip install 'datafence[integrations]' anthropic
    export ANTHROPIC_API_KEY=sk-ant-...
    python claude_example.py
"""

from __future__ import annotations

import json
from secrets import token_bytes

from datafence import (
    DataFenceBoundary,
    DataFencePolicyEngine,
    FieldDefinition,
    Principal,
    ResourceDefinition,
    ResourceRegistry,
)
from datafence.core.resources import PredicateOperator
from datafence.integrations.anthropic_tool import DataFenceAnthropicTool

# ---------------------------------------------------------------------------
# Shared boundary setup
# ---------------------------------------------------------------------------

def _make_boundary() -> tuple[DataFenceBoundary, bytes]:
    registry = ResourceRegistry()
    registry.register(
        ResourceDefinition(
            "documents",
            fields={
                "id":        FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "title":     FieldDefinition("title", "string"),
                "author":    FieldDefinition("author", "string"),
                "category":  FieldDefinition("category", "string"),
            },
            supported_operations=("read",),
        )
    )
    from datafence import ActionDecision as _A
    from datafence import DataFencePolicy as _P
    from datafence import ResourcePolicy as _R
    from datafence import RowRule as _RR
    policy = _P(
        "docs-policy", "1.0",
        {
            "documents": _R(
                "documents",
                actions={"read": _A.ALLOW},
                allowed_fields=["id", "tenant_id", "title", "author", "category"],
                row_rules=[_RR("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=20,
            )
        },
    )
    engine = DataFencePolicyEngine(policy, registry=registry)
    signing_key = token_bytes(32)
    boundary = DataFenceBoundary.create(
        engine, registry, signing_key,
        capability_audience="docs-service",
    )
    return boundary, signing_key


# ---------------------------------------------------------------------------
# Example A: direct tool call (no live Anthropic call required)
# ---------------------------------------------------------------------------

def example_direct_tool_call() -> None:
    """
    Demonstrate the authorization flow without a live Anthropic connection.
    Simulates what happens when Claude issues a tool_use block.
    """
    print("=" * 60)
    print("Anthropic DataFence Tool — direct call (no API key needed)")
    print("=" * 60)

    boundary, _ = _make_boundary()
    tool = DataFenceAnthropicTool(boundary, tool_name="datafence_query")

    # Inspect the tool spec (sent to Claude in the `tools=` parameter)
    spec = tool.anthropic_tool_spec()
    print(f"\n1. Tool spec name  : {spec['name']}")
    print(f"   Description     : {spec['description'][:70]}...")

    # Simulate the input Claude would produce inside a tool_use block
    tool_input = {
        "resource": "documents",
        "fields": ["id", "title", "author"],
        "filters": {"category": "engineering"},
        "limit": 5,
    }

    # Principal from YOUR auth layer — never from Claude's output
    principal = Principal(id="user:bob", tenant_id="tenant-beta")

    result_json = tool.handle_call(principal=principal, tool_input=tool_input)
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

    # Show denial: requesting an unapproved operation
    denied_json = tool.handle_call(
        principal=principal,
        tool_input={"resource": "documents", "operation": "delete"},
    )
    denied = json.loads(denied_json)
    print(f"\n3. Denial example — status: {denied['status']}")
    print(f"   reasons: {denied['reasons']}")


# ---------------------------------------------------------------------------
# Example B: live Anthropic call (requires ANTHROPIC_API_KEY)
# ---------------------------------------------------------------------------

def example_with_live_claude() -> None:
    """
    Full end-to-end with a real Claude model.
    Requires: pip install anthropic && export ANTHROPIC_API_KEY=sk-ant-...
    """
    print("\n" + "=" * 60)
    print("Anthropic DataFence Tool — live model call")
    print("=" * 60)

    try:
        import anthropic
    except ImportError:
        print("⚠️  anthropic package not installed: pip install anthropic")
        return

    boundary, _ = _make_boundary()
    tool = DataFenceAnthropicTool(boundary)

    # Principal from your auth layer
    principal = Principal(id="user:bob", tenant_id="tenant-beta")

    client = anthropic.Anthropic()

    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            tools=[tool.anthropic_tool_spec()],
            messages=[{"role": "user", "content": "Show me recent engineering documents."}],
        )

        for block in response.content:
            if block.type == "tool_use":
                result_json = tool.handle_call(
                    principal=principal,
                    tool_input=block.input,
                )
                result = json.loads(result_json)
                print(f"\nClaude requested: {block.input}")
                print(f"Authorization   : {result['status']}")
                if result["status"] == "authorized":
                    print(f"Capability      : execution_id={result['execution_id']}")
                    print("→ Pass to your connector to retrieve data.")
                else:
                    print(f"Denied          : {result['reasons']}")

    except Exception as exc:
        print(f"⚠️  Anthropic error: {exc}")
        print("   Set ANTHROPIC_API_KEY and try again.")


if __name__ == "__main__":
    example_direct_tool_call()
    example_with_live_claude()
    print("\n" + "=" * 60)
    print("✓ Example complete")
