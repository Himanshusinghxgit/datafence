"""
LangChain integration example.

Demonstrates using DataFence as a LangChain tool so that a LangChain agent
must pass through the authorization boundary before accessing data.

Architecture::

    LangChain agent
        │  tool.run('{"resource": "reports", "fields": [...]}')
        ▼
    DataFenceLangChainTool._run(query_str)
        │  parses JSON → Intent (untrusted)
        ▼
    DataFenceBoundary.authorize(principal, intent)
        │  Registry → Policy → AuthorizedExecution (signed)
        ▼
    JSON capability returned to agent
        │
        ▼  application passes capability to connector
    Customer-owned connector → enterprise data

Key security property: the Principal is bound at tool construction time.
The LangChain agent cannot change or override it during the conversation.

Run with:
    pip install 'datafence[integrations]' langchain langchain-openai
    export OPENAI_API_KEY=sk-...
    python langchain_example.py
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
from datafence.integrations.langchain_tool import DataFenceLangChainTool

# ---------------------------------------------------------------------------
# Shared boundary setup
# ---------------------------------------------------------------------------

def _make_boundary() -> tuple[DataFenceBoundary, bytes]:
    registry = ResourceRegistry()
    registry.register(
        ResourceDefinition(
            "reports",
            fields={
                "id":        FieldDefinition("id", "integer"),
                "tenant_id": FieldDefinition("tenant_id", "string", is_tenant_key=True),
                "title":     FieldDefinition("title", "string"),
                "department": FieldDefinition("department", "string"),
                "period":    FieldDefinition("period", "string"),
            },
            supported_operations=("read",),
        )
    )
    policy = DataFencePolicy(
        "reports-policy", "1.0",
        {
            "reports": ResourcePolicy(
                "reports",
                actions={"read": ActionDecision.ALLOW},
                allowed_fields=["id", "tenant_id", "title", "department", "period"],
                row_rules=[RowRule("tenant_id", PredicateOperator.EQ, ":actor_tenant_id")],
                max_rows=25,
            )
        },
    )
    engine = DataFencePolicyEngine(policy, registry=registry)
    signing_key = token_bytes(32)
    boundary = DataFenceBoundary.create(
        engine, registry, signing_key,
        capability_audience="reports-service",
    )
    return boundary, signing_key


# ---------------------------------------------------------------------------
# Example A: direct tool use (no LangChain agent or API key needed)
# ---------------------------------------------------------------------------

def example_direct_tool_use() -> None:
    """
    Use DataFenceLangChainTool directly without a live LangChain agent.
    Shows the authorization flow end-to-end.
    """
    print("=" * 60)
    print("LangChain DataFence Tool — direct use (no API key needed)")
    print("=" * 60)

    boundary, _ = _make_boundary()

    # Principal is bound at construction — agent cannot change it
    principal = Principal(id="user:carol", tenant_id="tenant-gamma")
    tool = DataFenceLangChainTool(boundary=boundary, principal=principal)

    print(f"\n1. Tool name : {tool.name}")
    print(f"   Principal : {principal.id} / tenant={principal.tenant_id}")

    # Tool accepts a JSON string (what a LangChain agent would produce)
    query = json.dumps({
        "resource": "reports",
        "fields": ["id", "title", "department"],
        "limit": 5,
    })

    result_json = tool.run(query)
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

    # Show that the agent cannot override the principal's tenant
    tamper_query = json.dumps({
        "resource": "reports",
        "fields": ["id", "title"],
        "filters": {"tenant_id": "evil-tenant"},   # agent tries to change tenant
    })
    tamper_result = json.loads(tool.run(tamper_query))
    if tamper_result["status"] == "authorized":
        predicates = tamper_result.get("predicates", [])
        tenant_preds = [p for p in predicates if p["field"] == "tenant_id"]
        print(f"\n3. Tenant isolation check: {tenant_preds}")
        assert any(p["value"] == "tenant-gamma" for p in tenant_preds), (
            "Policy must enforce the real tenant, not the agent-supplied one"
        )
        print("   ✓ Policy-enforced tenant filter overrides agent's attempt")


# ---------------------------------------------------------------------------
# Example B: LangChain agent (requires OPENAI_API_KEY + langchain)
# ---------------------------------------------------------------------------

def example_with_langchain_agent() -> None:
    """
    Wire DataFenceLangChainTool into a real LangChain agent.
    Requires: pip install langchain langchain-openai && export OPENAI_API_KEY=sk-...
    """
    print("\n" + "=" * 60)
    print("LangChain DataFence Tool — live agent")
    print("=" * 60)

    try:
        from langchain.agents import AgentExecutor, create_openai_functions_agent
        from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder
        from langchain_openai import ChatOpenAI
    except ImportError:
        print("⚠️  LangChain not installed:")
        print("   pip install langchain langchain-openai")
        return

    boundary, _ = _make_boundary()

    # Principal bound here — agent cannot change it
    principal = Principal(id="user:carol", tenant_id="tenant-gamma")
    df_tool = DataFenceLangChainTool(boundary=boundary, principal=principal)

    try:
        lc_tool = df_tool.as_langchain_tool()
    except ImportError as exc:
        print(f"⚠️  {exc}")
        return

    try:
        llm = ChatOpenAI(model="gpt-4o", temperature=0)
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a helpful analyst. Use available tools to fetch data."),
            ("human", "{input}"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ])
        agent = create_openai_functions_agent(llm, [lc_tool], prompt)
        executor = AgentExecutor(agent=agent, tools=[lc_tool], verbose=False)

        response = executor.invoke({"input": "Show me the latest reports."})
        print(f"\nAgent response: {response['output']}")
        print("Note: the agent received a signed capability, not database rows.")

    except Exception as exc:
        print(f"⚠️  Agent error: {exc}")
        print("   Set OPENAI_API_KEY and try again.")


if __name__ == "__main__":
    example_direct_tool_use()
    example_with_langchain_agent()
    print("\n" + "=" * 60)
    print("✓ Example complete")
