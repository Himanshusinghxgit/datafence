"""
LangChain integration example.

Demonstrates using DataFence as LangChain tools.
"""

from datafence import DataFence
from datafence.connectors import MemoryConnector
from datafence.integrations.langchain_tool import DataFenceTool, create_datafence_tools

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
    ]
}


def example_single_tool():
    """Using DataFence as a single generic tool."""
    print("=" * 60)
    print("LangChain Single Tool Example")
    print("=" * 60)

    # Setup DataFence
    connector = MemoryConnector(data=sample_data)
    fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

    # Create actor
    actor = {"id": "agent:banking-assistant", "tenant_id": "acme"}

    # Create tool
    tool = DataFenceTool(fence=fence, actor=actor)

    print(f"\n1. Tool created: {tool.name}")
    print(f"   Description: {tool.description}")

    # Use tool directly
    print("\n2. Using tool directly...")
    result = tool._run(
        resource="transactions",
        fields=["id", "amount", "merchant"],
        filters={"customer_id": "cust_123"},
        limit=10,
    )

    print(f"   Result: {result}")


def example_resource_tools():
    """Creating resource-specific tools."""
    print("\n" + "=" * 60)
    print("LangChain Resource-Specific Tools Example")
    print("=" * 60)

    # Setup DataFence
    connector = MemoryConnector(data=sample_data)
    fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

    # Create actor
    actor = {"id": "agent:banking-assistant", "tenant_id": "acme"}

    # Create resource-specific tools
    tools = create_datafence_tools(fence, actor=actor)

    print(f"\n1. Created {len(tools)} resource-specific tool(s):")
    for tool in tools:
        print(f"   - {tool.name}: {tool.description}")

    # Use a tool
    if tools:
        print(f"\n2. Using {tools[0].name}...")
        result = tools[0]._run(
            fields=["id", "amount", "merchant"], filters={"customer_id": "cust_123"}, limit=10
        )
        print(f"   Result: {result}")


def example_agent():
    """LangChain agent with DataFence tools."""
    print("\n" + "=" * 60)
    print("LangChain Agent Example")
    print("=" * 60)

    try:
        from langchain_openai import ChatOpenAI
        from langchain.agents import AgentExecutor, create_openai_functions_agent
        from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder

        # Setup DataFence
        connector = MemoryConnector(data=sample_data)
        fence = DataFence.from_yaml("../../policies/banking.yaml", connector)

        # Create actor
        actor = {"id": "agent:banking-assistant", "tenant_id": "acme"}

        # Create tools
        tools = create_datafence_tools(fence, actor=actor)

        # Create LLM
        llm = ChatOpenAI(model="gpt-4", temperature=0)

        # Create prompt
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system", "You are a helpful banking assistant with access to transaction data."),
                ("human", "{input}"),
                MessagesPlaceholder(variable_name="agent_scratchpad"),
            ]
        )

        # Create agent
        agent = create_openai_functions_agent(llm, tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

        # Use agent
        print("\n1. Agent created with DataFence tools")
        print(f"   Tools: {[tool.name for tool in tools]}")

        response = agent_executor.invoke(
            {"input": "Show me transactions for customer cust_123"}
        )

        print(f"\n2. Agent response: {response['output']}")

    except ImportError:
        print("\n⚠️  LangChain packages not installed")
        print("Install with: pip install langchain langchain-openai")
    except Exception as e:
        print(f"\n⚠️  Error: {e}")
        print("Make sure OPENAI_API_KEY environment variable is set")


if __name__ == "__main__":
    # Run examples
    example_single_tool()
    example_resource_tools()

    print("\n" + "=" * 60)
    print("\nTo run the agent example, set OPENAI_API_KEY and uncomment:")
    print("# example_agent()")

    print("\n" + "=" * 60)
    print("✓ Examples complete")
