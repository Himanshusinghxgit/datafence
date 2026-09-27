"""
Anthropic Claude integration example.

Demonstrates using DataFence with Claude tool use.
"""

from datafence import DataFence
from datafence.connectors import MemoryConnector
from datafence.integrations.anthropic_adapter import ClaudeAdapter, create_claude_agent

# Sample data
sample_data = {
    "transactions": [
        {
            "id": 1,
            "tenant_id": "acme",
            "customer_id": "cust_123",
            "amount": 100.00,
            "merchant": "Coffee Shop",
            "timestamp": "2024-01-15T10:30:00Z",
        },
        {
            "id": 2,
            "tenant_id": "acme",
            "customer_id": "cust_123",
            "amount": 250.00,
            "merchant": "Electronics Store",
            "timestamp": "2024-01-16T14:20:00Z",
        },
        {
            "id": 3,
            "tenant_id": "acme",
            "customer_id": "cust_456",
            "amount": 50.00,
            "merchant": "Restaurant",
            "timestamp": "2024-01-16T19:00:00Z",
        },
    ]
}


def example_manual():
    """Manual Claude tool use with DataFence."""
    print("=" * 60)
    print("Claude Manual Integration Example")
    print("=" * 60)

    # Setup DataFence
    connector = MemoryConnector(data=sample_data)
    fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

    # Create adapter
    adapter = ClaudeAdapter(fence)

    # Get tool schemas
    tools = adapter.get_tools()

    print(f"\n1. Generated {len(tools)} Claude tool(s):")
    for tool in tools:
        print(f"   - {tool['name']}: {tool['description']}")

    # Simulate Claude tool use
    print("\n2. Simulating Claude tool use...")
    tool_name = "read_transactions"
    tool_input = {
        "fields": ["id", "amount", "merchant"],
        "filters": {"customer_id": "cust_123"},
        "limit": 10,
    }

    # Execute through DataFence
    actor = {"id": "agent:banking-assistant", "tenant_id": "acme"}

    result = adapter.execute_tool(tool_name, tool_input, actor=actor)

    print(f"\n3. Result:")
    print(f"   Success: {result['success']}")
    if result["success"]:
        print(f"   Rows: {result['row_count']}")
        print(f"   Data: {result['data']}")
    else:
        print(f"   Error: {result['error']}")
        print(f"   Reasons: {result['reasons']}")

    # Create tool result block
    print("\n4. Creating tool result block for Claude...")
    tool_result = adapter.create_tool_result_block("tool_use_123", result)
    print(f"   Type: {tool_result['type']}")
    print(f"   Tool Use ID: {tool_result['tool_use_id']}")


def example_agent():
    """Simple agent with Claude and DataFence."""
    print("\n" + "=" * 60)
    print("Claude Agent Example")
    print("=" * 60)

    # Setup DataFence
    connector = MemoryConnector(data=sample_data)
    fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

    # Create agent (requires ANTHROPIC_API_KEY env var)
    try:
        agent = create_claude_agent(
            fence,
            model="claude-3-5-sonnet-20241022",
            system_prompt="You are a banking assistant. Help users query their transaction data securely.",
            max_tokens=1024,
        )

        # Use agent
        actor = {"id": "agent:banking-assistant", "tenant_id": "acme", "customer_id": "cust_123"}

        response = agent("Show me my recent transactions", actor=actor)

        print(f"\nAgent response: {response}")

    except ImportError:
        print("\n⚠️  Anthropic package not installed")
        print("Install with: pip install anthropic")
    except Exception as e:
        print(f"\n⚠️  Error: {e}")
        print("Make sure ANTHROPIC_API_KEY environment variable is set")


if __name__ == "__main__":
    # Run examples
    example_manual()

    print("\n" + "=" * 60)
    print("\nTo run the agent example, set ANTHROPIC_API_KEY and uncomment:")
    print("# example_agent()")

    print("\n" + "=" * 60)
    print("✓ Examples complete")
