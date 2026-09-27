"""
OpenAI integration example.

Demonstrates using DataFence with OpenAI function calling.
"""

from datafence import DataFence
from datafence.connectors import MemoryConnector
from datafence.integrations.openai_adapter import OpenAIAdapter, create_openai_agent

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
    """Manual OpenAI function calling with DataFence."""
    print("=" * 60)
    print("OpenAI Manual Integration Example")
    print("=" * 60)

    # Setup DataFence
    connector = MemoryConnector(data=sample_data)
    fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

    # Create adapter
    adapter = OpenAIAdapter(fence)

    # Get function schemas
    functions = adapter.get_functions()

    print(f"\n1. Generated {len(functions)} OpenAI function(s):")
    for func in functions:
        print(f"   - {func['name']}: {func['description']}")

    # Simulate OpenAI function call
    print("\n2. Simulating OpenAI function call...")
    function_call = {
        "name": "read_transactions",
        "arguments": '{"fields": ["id", "amount", "merchant"], "filters": {"customer_id": "cust_123"}, "limit": 10}',
    }

    # Execute through DataFence
    actor = {"id": "agent:banking-assistant", "tenant_id": "acme"}

    result = adapter.execute_function_call(function_call, actor=actor)

    print(f"\n3. Result:")
    print(f"   Success: {result['success']}")
    if result["success"]:
        print(f"   Rows: {result['row_count']}")
        print(f"   Data: {result['data']}")
    else:
        print(f"   Error: {result['error']}")
        print(f"   Reasons: {result['reasons']}")


def example_agent():
    """Simple agent with OpenAI and DataFence."""
    print("\n" + "=" * 60)
    print("OpenAI Agent Example")
    print("=" * 60)

    # Setup DataFence
    connector = MemoryConnector(data=sample_data)
    fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

    # Create agent (requires OPENAI_API_KEY env var)
    try:
        agent = create_openai_agent(
            fence,
            model="gpt-4",
            system_prompt="You are a banking assistant. Help users query their transaction data securely.",
        )

        # Use agent
        actor = {"id": "agent:banking-assistant", "tenant_id": "acme", "customer_id": "cust_123"}

        response = agent("Show me my recent transactions", actor=actor)

        print(f"\nAgent response: {response}")

    except ImportError:
        print("\n⚠️  OpenAI package not installed")
        print("Install with: pip install openai")
    except Exception as e:
        print(f"\n⚠️  Error: {e}")
        print("Make sure OPENAI_API_KEY environment variable is set")


def example_streaming():
    """Streaming responses with function calls."""
    print("\n" + "=" * 60)
    print("OpenAI Streaming Example")
    print("=" * 60)

    connector = MemoryConnector(data=sample_data)
    fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

    from datafence.integrations.openai_adapter import OpenAIStreamingAdapter

    adapter = OpenAIStreamingAdapter(fence)

    print("\nStreaming adapter created")
    print("Use adapter.process_stream_chunk() to handle streaming responses")
    print("See OpenAI streaming docs for full implementation")


if __name__ == "__main__":
    # Run examples
    example_manual()

    print("\n" + "=" * 60)
    print("\nTo run the agent example, set OPENAI_API_KEY and uncomment:")
    print("# example_agent()")

    example_streaming()

    print("\n" + "=" * 60)
    print("✓ Examples complete")
