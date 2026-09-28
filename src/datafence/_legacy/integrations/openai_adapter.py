"""
OpenAI function calling adapter for DataFence.

Converts DataFence policies into OpenAI function schemas and handles execution.
"""

import json
from typing import Any, Callable

try:
    import openai
except ImportError:
    openai = None

from datafence.core.engine import DataFence
from datafence.core.request import ExecutionRequest, Operation
from datafence.errors import DataFenceError


class OpenAIAdapter:
    """
    Adapter for OpenAI function calling with DataFence security.

    Converts DataFence policies to OpenAI function schemas and enforces
    security policies when functions are called.

    Example:
        fence = DataFence.from_yaml("policy.yaml", connector)
        adapter = OpenAIAdapter(fence)

        # Get function schemas for OpenAI
        functions = adapter.get_functions()

        # Call OpenAI with functions
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Show me transactions"}],
            functions=functions
        )

        # Execute function call through DataFence
        if response.choices[0].message.get("function_call"):
            result = adapter.execute_function_call(
                response.choices[0].message.function_call,
                actor={"id": "user:123", "tenant_id": "acme"}
            )
    """

    def __init__(self, fence: DataFence):
        """
        Initialize OpenAI adapter.

        Args:
            fence: Configured DataFence instance
        """
        self.fence = fence

    def get_functions(self) -> list[dict[str, Any]]:
        """
        Generate OpenAI function schemas from DataFence policies.

        Returns:
            List of OpenAI function schemas
        """
        functions = []

        # Get all resources from policy
        if not self.fence.policy or not self.fence.policy.resources:
            return functions

        for resource_name, resource_config in self.fence.policy.resources.items():
            # Create a function for each allowed operation
            allowed_ops = resource_config.operations.get("allow", [])

            if "read" in allowed_ops or Operation.READ.value in allowed_ops:
                functions.append(self._create_read_function(resource_name, resource_config))

        return functions

    def _create_read_function(
        self, resource_name: str, resource_config: Any
    ) -> dict[str, Any]:
        """
        Create OpenAI function schema for reading a resource.

        Args:
            resource_name: Name of the resource
            resource_config: Resource configuration from policy

        Returns:
            OpenAI function schema
        """
        # Get allowed fields
        allowed_fields = resource_config.fields.get("allow", [])

        # Build field descriptions
        field_properties = {}
        for field in allowed_fields:
            field_properties[field] = {
                "type": "boolean",
                "description": f"Include {field} field in results",
            }

        # Build function schema
        function_schema = {
            "name": f"read_{resource_name}",
            "description": f"Read data from {resource_name} table with security enforcement",
            "parameters": {
                "type": "object",
                "properties": {
                    "fields": {
                        "type": "array",
                        "items": {"type": "string", "enum": allowed_fields},
                        "description": f"Fields to retrieve. Allowed: {', '.join(allowed_fields)}",
                    },
                    "filters": {
                        "type": "object",
                        "description": "Filter conditions as key-value pairs",
                        "additionalProperties": {"type": "string"},
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of rows to return",
                        "minimum": 1,
                        "maximum": resource_config.limits.get("max_rows", 1000)
                        if hasattr(resource_config, "limits")
                        else 1000,
                    },
                },
                "required": [],
            },
        }

        return function_schema

    def execute_function_call(
        self,
        function_call: dict[str, Any] | Any,
        actor: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute OpenAI function call through DataFence.

        Args:
            function_call: Function call from OpenAI response (has 'name' and 'arguments')
            actor: Actor information (id, tenant_id, etc.)
            context: Additional context for policy evaluation

        Returns:
            Execution result with data and metadata

        Raises:
            DataFenceError: If execution fails or is denied
        """
        # Handle both dict and object types
        if hasattr(function_call, "name"):
            function_name = function_call.name
            arguments_str = function_call.arguments
        else:
            function_name = function_call["name"]
            arguments_str = function_call["arguments"]

        # Parse arguments
        try:
            arguments = json.loads(arguments_str)
        except json.JSONDecodeError as e:
            raise DataFenceError(f"Invalid function arguments: {e}") from e

        # Extract operation and resource from function name
        # Expected format: read_<resource_name>
        if not function_name.startswith("read_"):
            raise DataFenceError(f"Unsupported function: {function_name}")

        resource_name = function_name[5:]  # Remove "read_" prefix

        # Build DataFence request
        request_dict = {
            "actor": actor,
            "operation": "read",
            "resource": resource_name,
            "fields": arguments.get("fields"),
            "filters": arguments.get("filters", {}),
            "limit": arguments.get("limit"),
        }

        if context:
            request_dict["context"] = context

        # Execute through DataFence
        result = self.fence.execute(request_dict)

        # Format response for OpenAI
        if result.verified:
            return {
                "success": True,
                "data": result.data,
                "row_count": len(result.data),
                "evidence": {
                    "decision": result.decision.decision.value,
                    "applied_policies": result.decision.applied_policies,
                },
            }
        else:
            return {
                "success": False,
                "error": "Access denied",
                "reasons": result.decision.reasons,
                "decision": result.decision.decision.value,
            }

    def create_tool_message(self, result: dict[str, Any]) -> dict[str, str]:
        """
        Create OpenAI tool/function message from result.

        Args:
            result: Result from execute_function_call

        Returns:
            Message dict for OpenAI API
        """
        return {"role": "function", "content": json.dumps(result)}


class OpenAIStreamingAdapter(OpenAIAdapter):
    """
    Adapter for OpenAI streaming with function calls.

    Handles streaming responses and collects function calls.
    """

    def __init__(self, fence: DataFence):
        """Initialize streaming adapter."""
        super().__init__(fence)
        self._function_call_buffer = {"name": None, "arguments": ""}

    def process_stream_chunk(
        self, chunk: Any
    ) -> tuple[str | None, dict[str, Any] | None]:
        """
        Process streaming chunk and detect function calls.

        Args:
            chunk: Stream chunk from OpenAI

        Returns:
            Tuple of (text_delta, complete_function_call)
        """
        delta = chunk.choices[0].delta

        # Text content
        if hasattr(delta, "content") and delta.content:
            return delta.content, None

        # Function call
        if hasattr(delta, "function_call") and delta.function_call:
            fc = delta.function_call

            # Function name
            if hasattr(fc, "name") and fc.name:
                self._function_call_buffer["name"] = fc.name

            # Arguments (streamed incrementally)
            if hasattr(fc, "arguments") and fc.arguments:
                self._function_call_buffer["arguments"] += fc.arguments

        # Check if function call is complete (end of stream)
        if chunk.choices[0].finish_reason == "function_call":
            complete_call = self._function_call_buffer.copy()
            self._function_call_buffer = {"name": None, "arguments": ""}
            return None, complete_call

        return None, None


def create_openai_agent(
    fence: DataFence,
    model: str = "gpt-4",
    system_prompt: str | None = None,
    api_key: str | None = None,
) -> Callable[[str, dict[str, Any]], str]:
    """
    Create a simple OpenAI agent with DataFence security.

    Args:
        fence: DataFence instance
        model: OpenAI model name
        system_prompt: System prompt for the agent
        api_key: OpenAI API key (uses env var if not provided)

    Returns:
        Agent function that takes (message, actor) and returns response

    Example:
        agent = create_openai_agent(fence, system_prompt="You are a helpful assistant.")
        response = agent("Show me transactions", actor={"id": "user:123", "tenant_id": "acme"})
    """
    if openai is None:
        raise ImportError("openai package required. Install with: pip install openai")

    adapter = OpenAIAdapter(fence)
    functions = adapter.get_functions()

    if api_key:
        openai.api_key = api_key

    def agent(message: str, actor: dict[str, Any], context: dict[str, Any] | None = None) -> str:
        """
        Send message and get response with function calling.

        Args:
            message: User message
            actor: Actor information
            context: Additional context

        Returns:
            Agent response
        """
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": message})

        # Call OpenAI
        response = openai.ChatCompletion.create(
            model=model, messages=messages, functions=functions if functions else None
        )

        message_obj = response.choices[0].message

        # Handle function call
        if message_obj.get("function_call"):
            # Execute function through DataFence
            result = adapter.execute_function_call(
                message_obj.function_call, actor=actor, context=context
            )

            # Add function result to messages
            messages.append(message_obj)
            messages.append(adapter.create_tool_message(result))

            # Get final response
            response = openai.ChatCompletion.create(model=model, messages=messages)

            return response.choices[0].message.content

        # Direct response (no function call)
        return message_obj.content

    return agent
