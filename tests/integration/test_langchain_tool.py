"""
Tests for LangChain integration.
"""

import json
import pytest
from unittest.mock import Mock

from datafence import DataFence
from datafence.connectors import MemoryConnector

# Try to import LangChain components
try:
    from datafence.integrations.langchain_tool import (
        DataFenceTool,
        create_datafence_tools,
    )

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False


@pytest.fixture
def sample_data():
    """Sample in-memory data."""
    return {
        "transactions": [
            {"id": 1, "tenant_id": "acme", "amount": 100.0, "merchant": "Coffee"},
            {"id": 2, "tenant_id": "acme", "amount": 250.0, "merchant": "Store"},
        ]
    }


@pytest.fixture
def fence(sample_data, tmp_path):
    """Create DataFence instance with sample policy."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("""
version: "1"
policy:
  name: test-policy
  resources:
    transactions:
      operations:
        allow: [read]
      fields:
        allow: [id, amount, merchant]
      limits:
        max_rows: 100
""")
    connector = MemoryConnector(data=sample_data)
    return DataFence.from_yaml(str(policy_file), connector)


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_datafence_tool_initialization(fence):
    """Test DataFenceTool initialization."""
    actor = {"id": "test", "tenant_id": "acme"}
    tool = DataFenceTool(fence=fence, actor=actor)

    assert tool.name == "query_data"
    assert "query data" in tool.description.lower()
    assert tool.fence == fence
    assert tool.actor == actor


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_datafence_tool_run(fence):
    """Test running DataFenceTool."""
    actor = {"id": "test", "tenant_id": "acme"}
    tool = DataFenceTool(fence=fence, actor=actor)

    result = tool._run(
        resource="transactions",
        fields=["id", "amount"],
        filters={"tenant_id": "acme"},
        limit=10,
    )

    result_dict = json.loads(result)
    assert result_dict["success"] is True
    assert result_dict["row_count"] == 2


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_datafence_tool_run_denied(fence):
    """Test running DataFenceTool with denied request."""
    actor = {"id": "test", "tenant_id": "acme"}
    tool = DataFenceTool(fence=fence, actor=actor)

    result = tool._run(
        resource="transactions",
        fields=["id", "password"],  # password not allowed
        limit=10,
    )

    result_dict = json.loads(result)
    assert result_dict["success"] is False
    assert "reasons" in result_dict or "error" in result_dict


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
async def test_datafence_tool_arun(fence):
    """Test async execution of DataFenceTool."""
    actor = {"id": "test", "tenant_id": "acme"}
    tool = DataFenceTool(fence=fence, actor=actor)

    result = await tool._arun(
        resource="transactions", fields=["id", "amount"], limit=10
    )

    result_dict = json.loads(result)
    assert result_dict["success"] is True


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_create_datafence_tools(fence):
    """Test creating resource-specific tools."""
    actor = {"id": "test", "tenant_id": "acme"}
    tools = create_datafence_tools(fence, actor=actor)

    assert len(tools) == 1
    assert tools[0].name == "query_transactions"
    assert "transactions" in tools[0].description.lower()


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_create_datafence_tools_with_context(fence):
    """Test creating tools with additional context."""
    actor = {"id": "test", "tenant_id": "acme"}
    context = {"customer_id": "cust_123"}

    tools = create_datafence_tools(fence, actor=actor, context=context)

    assert len(tools) == 1
    assert tools[0].context == context


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_resource_specific_tool_run(fence):
    """Test running resource-specific tool."""
    actor = {"id": "test", "tenant_id": "acme"}
    tools = create_datafence_tools(fence, actor=actor)

    tool = tools[0]
    result = tool._run(fields=["id", "amount"], filters={"tenant_id": "acme"}, limit=10)

    result_dict = json.loads(result)
    assert result_dict["success"] is True
    assert result_dict["row_count"] == 2


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_create_tools_no_resources(sample_data):
    """Test creating tools when policy has no resources."""
    # Create policy with no resources
    from datafence.policy.models import Policy, ResourceConfig

    policy = Policy(name="empty", resources={})

    connector = MemoryConnector(data=sample_data)
    fence = DataFence(policy=policy, connector=connector)

    actor = {"id": "test", "tenant_id": "acme"}
    tools = create_datafence_tools(fence, actor=actor)

    # Should create generic tool
    assert len(tools) == 1
    assert tools[0].name == "query_data"


@pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="LangChain not installed")
def test_tool_error_handling(fence):
    """Test error handling in tool execution."""
    actor = {"id": "test", "tenant_id": "acme"}
    tool = DataFenceTool(fence=fence, actor=actor)

    # Try to query non-existent resource
    result = tool._run(resource="nonexistent", fields=["id"], limit=10)

    result_dict = json.loads(result)
    assert result_dict["success"] is False
    assert "error" in result_dict


def test_import_error_handling():
    """Test proper error when LangChain not installed."""
    if LANGCHAIN_AVAILABLE:
        pytest.skip("LangChain is installed")

    # Should raise ImportError when trying to use without LangChain
    with pytest.raises(ImportError):
        from datafence.integrations.langchain_tool import create_datafence_tools
