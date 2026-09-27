"""
Tests for OpenAI adapter.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock

from datafence import DataFence
from datafence.connectors import MemoryConnector
from datafence.integrations.openai_adapter import (
    OpenAIAdapter,
    OpenAIStreamingAdapter,
    create_openai_agent,
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
    adapter = OpenAIAdapter(fence)
    assert adapter.fence == fence


def test_get_functions(fence):
    """Test function schema generation."""
    adapter = OpenAIAdapter(fence)
    functions = adapter.get_functions()

    assert len(functions) == 1
    assert functions[0]["name"] == "read_transactions"
    assert "description" in functions[0]
    assert "parameters" in functions[0]

    # Check parameters structure
    params = functions[0]["parameters"]
    assert params["type"] == "object"
    assert "fields" in params["properties"]
    assert "filters" in params["properties"]
    assert "limit" in params["properties"]

    # Check field enum
    field_items = params["properties"]["fields"]["items"]
    assert set(field_items["enum"]) == {"id", "amount", "merchant"}


def test_execute_function_call_dict(fence):
    """Test executing function call with dict input."""
    adapter = OpenAIAdapter(fence)

    function_call = {
        "name": "read_transactions",
        "arguments": json.dumps(
            {"fields": ["id", "amount"], "filters": {"tenant_id": "acme"}, "limit": 10}
        ),
    }

    actor = {"id": "test", "tenant_id": "acme"}
    result = adapter.execute_function_call(function_call, actor)

    assert result["success"] is True
    assert result["verified"] is True
    assert result["row_count"] == 2
    assert len(result["data"]) == 2


def test_execute_function_call_object(fence):
    """Test executing function call with object input."""
    adapter = OpenAIAdapter(fence)

    # Mock OpenAI function call object
    function_call = Mock()
    function_call.name = "read_transactions"
    function_call.arguments = json.dumps({"fields": ["id", "amount"], "limit": 10})

    actor = {"id": "test", "tenant_id": "acme"}
    result = adapter.execute_function_call(function_call, actor)

    assert result["success"] is True
    assert result["verified"] is True
    assert "data" in result


def test_execute_function_call_denied(fence):
    """Test function call that gets denied by policy."""
    adapter = OpenAIAdapter(fence)

    # Try to request denied field
    function_call = {
        "name": "read_transactions",
        "arguments": json.dumps({"fields": ["id", "password"]}),  # password not allowed
    }

    actor = {"id": "test", "tenant_id": "acme"}
    result = adapter.execute_function_call(function_call, actor)

    assert result["success"] is False
    assert result["verified"] is False
    assert "reasons" in result


def test_execute_function_call_invalid_json(fence):
    """Test function call with invalid JSON arguments."""
    adapter = OpenAIAdapter(fence)

    function_call = {
        "name": "read_transactions",
        "arguments": "invalid json{",
    }

    actor = {"id": "test", "tenant_id": "acme"}

    with pytest.raises(Exception):
        adapter.execute_function_call(function_call, actor)


def test_execute_function_call_unsupported_function(fence):
    """Test function call with unsupported function name."""
    adapter = OpenAIAdapter(fence)

    function_call = {
        "name": "delete_transactions",  # Not a read_ function
        "arguments": json.dumps({}),
    }

    actor = {"id": "test", "tenant_id": "acme"}

    with pytest.raises(Exception):
        adapter.execute_function_call(function_call, actor)


def test_create_tool_message(fence):
    """Test creating tool message for OpenAI."""
    adapter = OpenAIAdapter(fence)

    result = {"success": True, "data": [{"id": 1}], "row_count": 1}
    message = adapter.create_tool_message(result)

    assert message["role"] == "function"
    assert "content" in message
    content = json.loads(message["content"])
    assert content["success"] is True


def test_streaming_adapter_initialization(fence):
    """Test streaming adapter initialization."""
    adapter = OpenAIStreamingAdapter(fence)
    assert adapter.fence == fence
    assert adapter._function_call_buffer == {"name": None, "arguments": ""}


def test_streaming_adapter_text_chunk(fence):
    """Test processing text chunk."""
    adapter = OpenAIStreamingAdapter(fence)

    chunk = Mock()
    chunk.choices = [Mock()]
    chunk.choices[0].delta = Mock()
    chunk.choices[0].delta.content = "Hello"
    chunk.choices[0].finish_reason = None

    text_delta, function_call = adapter.process_stream_chunk(chunk)

    assert text_delta == "Hello"
    assert function_call is None


def test_streaming_adapter_function_chunk(fence):
    """Test processing function call chunk."""
    adapter = OpenAIStreamingAdapter(fence)

    # First chunk with name
    chunk1 = Mock()
    chunk1.choices = [Mock()]
    chunk1.choices[0].delta = Mock()
    chunk1.choices[0].delta.function_call = Mock()
    chunk1.choices[0].delta.function_call.name = "read_transactions"
    chunk1.choices[0].delta.function_call.arguments = ""
    chunk1.choices[0].finish_reason = None

    text_delta, function_call = adapter.process_stream_chunk(chunk1)
    assert text_delta is None
    assert function_call is None

    # Second chunk with arguments
    chunk2 = Mock()
    chunk2.choices = [Mock()]
    chunk2.choices[0].delta = Mock()
    chunk2.choices[0].delta.function_call = Mock()
    chunk2.choices[0].delta.function_call.arguments = '{"limit": 10}'
    delattr(chunk2.choices[0].delta.function_call, "name")
    chunk2.choices[0].finish_reason = None

    text_delta, function_call = adapter.process_stream_chunk(chunk2)
    assert text_delta is None
    assert function_call is None

    # Final chunk
    chunk3 = Mock()
    chunk3.choices = [Mock()]
    chunk3.choices[0].delta = Mock()
    chunk3.choices[0].finish_reason = "function_call"

    text_delta, function_call = adapter.process_stream_chunk(chunk3)
    assert text_delta is None
    assert function_call is not None
    assert function_call["name"] == "read_transactions"
    assert function_call["arguments"] == '{"limit": 10}'


@patch("datafence.integrations.openai_adapter.openai")
def test_create_openai_agent_missing_openai(mock_openai, fence):
    """Test creating agent when openai package not installed."""
    mock_openai = None

    with patch("datafence.integrations.openai_adapter.openai", None):
        with pytest.raises(ImportError):
            create_openai_agent(fence)


@patch("datafence.integrations.openai_adapter.openai")
def test_create_openai_agent(mock_openai, fence):
    """Test creating OpenAI agent."""
    # Mock OpenAI response
    mock_response = Mock()
    mock_response.choices = [Mock()]
    mock_response.choices[0].message = {"content": "Here are your transactions"}
    mock_openai.ChatCompletion.create.return_value = mock_response

    agent = create_openai_agent(fence, model="gpt-4")

    assert callable(agent)

    # Test agent call
    actor = {"id": "test", "tenant_id": "acme"}
    response = agent("Show me transactions", actor)

    assert response == "Here are your transactions"
    mock_openai.ChatCompletion.create.assert_called()
