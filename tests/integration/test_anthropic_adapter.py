"""
Tests for Anthropic Claude adapter.
"""

import pytest
from unittest.mock import Mock, patch

from datafence import DataFence
from datafence.connectors import MemoryConnector
from datafence.integrations.anthropic_adapter import (
    ClaudeAdapter,
    create_claude_agent,
)


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


def test_adapter_initialization(fence):
    """Test adapter initialization."""
    adapter = ClaudeAdapter(fence)
    assert adapter.fence == fence


def test_get_tools(fence):
    """Test tool schema generation."""
    adapter = ClaudeAdapter(fence)
    tools = adapter.get_tools()

    assert len(tools) == 1
    assert tools[0]["name"] == "read_transactions"
    assert "description" in tools[0]
    assert "input_schema" in tools[0]

    # Check input schema structure
    schema = tools[0]["input_schema"]
    assert schema["type"] == "object"
    assert "fields" in schema["properties"]
    assert "filters" in schema["properties"]
    assert "limit" in schema["properties"]

    # Check field enum
    field_items = schema["properties"]["fields"]["items"]
    assert set(field_items["enum"]) == {"id", "amount", "merchant"}


def test_execute_tool(fence):
    """Test executing tool."""
    adapter = ClaudeAdapter(fence)

    tool_name = "read_transactions"
    tool_input = {"fields": ["id", "amount"], "filters": {"tenant_id": "acme"}, "limit": 10}

    actor = {"id": "test", "tenant_id": "acme"}
    result = adapter.execute_tool(tool_name, tool_input, actor)

    assert result["success"] is True
    assert result["row_count"] == 2
    assert len(result["data"]) == 2


def test_execute_tool_with_context(fence):
    """Test executing tool with additional context."""
    adapter = ClaudeAdapter(fence)

    tool_name = "read_transactions"
    tool_input = {"fields": ["id", "amount"], "limit": 10}
    actor = {"id": "test", "tenant_id": "acme"}
    context = {"customer_id": "cust_123"}

    result = adapter.execute_tool(tool_name, tool_input, actor, context=context)

    assert result["success"] is True


def test_execute_tool_denied(fence):
    """Test tool execution that gets denied."""
    adapter = ClaudeAdapter(fence)

    tool_name = "read_transactions"
    tool_input = {"fields": ["id", "password"]}  # password not allowed

    actor = {"id": "test", "tenant_id": "acme"}
    result = adapter.execute_tool(tool_name, tool_input, actor)

    assert result["success"] is False
    assert "reasons" in result


def test_execute_tool_unsupported(fence):
    """Test executing unsupported tool."""
    adapter = ClaudeAdapter(fence)

    tool_name = "delete_transactions"  # Not supported
    tool_input = {}

    actor = {"id": "test", "tenant_id": "acme"}

    with pytest.raises(Exception):
        adapter.execute_tool(tool_name, tool_input, actor)


def test_create_tool_result_block(fence):
    """Test creating tool result block."""
    adapter = ClaudeAdapter(fence)

    tool_use_id = "tool_use_123"
    result = {"success": True, "data": [{"id": 1}], "row_count": 1}

    tool_result = adapter.create_tool_result_block(tool_use_id, result)

    assert tool_result["type"] == "tool_result"
    assert tool_result["tool_use_id"] == tool_use_id
    assert "content" in tool_result

    import json

    content = json.loads(tool_result["content"])
    assert content["success"] is True


@patch("datafence.integrations.anthropic_adapter.anthropic")
def test_create_claude_agent_missing_anthropic(mock_anthropic, fence):
    """Test creating agent when anthropic package not installed."""
    with patch("datafence.integrations.anthropic_adapter.anthropic", None):
        with pytest.raises(ImportError):
            create_claude_agent(fence)


@patch("datafence.integrations.anthropic_adapter.anthropic")
def test_create_claude_agent(mock_anthropic, fence):
    """Test creating Claude agent."""
    # Mock Anthropic client
    mock_client = Mock()
    mock_anthropic.Anthropic.return_value = mock_client

    # Mock response with text
    mock_response = Mock()
    mock_response.stop_reason = "end_turn"
    mock_response.content = [Mock()]
    mock_response.content[0].type = "text"
    mock_response.content[0].text = "Here are your transactions"

    mock_client.messages.create.return_value = mock_response

    agent = create_claude_agent(fence, model="claude-3-5-sonnet-20241022")

    assert callable(agent)

    # Test agent call
    actor = {"id": "test", "tenant_id": "acme"}
    response = agent("Show me transactions", actor)

    assert response == "Here are your transactions"
    mock_client.messages.create.assert_called()


@patch("datafence.integrations.anthropic_adapter.anthropic")
def test_create_claude_agent_with_tool_use(mock_anthropic, fence):
    """Test Claude agent with tool use."""
    # Mock Anthropic client
    mock_client = Mock()
    mock_anthropic.Anthropic.return_value = mock_client

    # First response with tool use
    mock_tool_use_response = Mock()
    mock_tool_use_response.stop_reason = "tool_use"
    mock_tool_use_response.content = [Mock()]
    mock_tool_use_response.content[0].type = "tool_use"
    mock_tool_use_response.content[0].id = "tool_123"
    mock_tool_use_response.content[0].name = "read_transactions"
    mock_tool_use_response.content[0].input = {"fields": ["id", "amount"], "limit": 10}

    # Second response with final text
    mock_final_response = Mock()
    mock_final_response.stop_reason = "end_turn"
    mock_final_response.content = [Mock()]
    mock_final_response.content[0].type = "text"
    mock_final_response.content[0].text = "Found 2 transactions"

    mock_client.messages.create.side_effect = [mock_tool_use_response, mock_final_response]

    agent = create_claude_agent(fence)

    actor = {"id": "test", "tenant_id": "acme"}
    response = agent("Show me transactions", actor)

    assert response == "Found 2 transactions"
    assert mock_client.messages.create.call_count == 2
