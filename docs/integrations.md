# Integration Guide

DataFence integrates with popular AI frameworks to provide a secure authorization
boundary between the AI agent and your enterprise data.

## Security model recap

In every integration, the ownership split is the same:

| Who controls it | What it is |
|---|---|
| Your application | `Principal` — authenticated user/service identity |
| AI agent / model | `Intent` — untrusted request (resource, fields, filters) |
| DataFence | Authorization decision + signed `AuthorizedExecution` |
| Your connector | Actual data access (you own this) |

The AI **never controls** the principal.  The principal **always** comes from
your application's authentication layer.

---

## Installation

```bash
# Core only (no AI framework dependencies)
pip install datafence

# With AI integration adapters
pip install 'datafence[integrations]'   # openai, anthropic, langchain

# REST API server
pip install 'datafence[api]'

# CLI tool
pip install 'datafence[cli]'
```

---

## OpenAI function-calling

```python
from datafence.integrations.openai_tool import DataFenceOpenAITool
from datafence.core.principal import Principal
import openai

tool = DataFenceOpenAITool(boundary)

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Show me my recent orders"}],
    tools=[tool.openai_tool_spec()],
)

for tool_call in response.choices[0].message.tool_calls or []:
    if tool_call.function.name == tool.tool_name:
        # Principal comes from YOUR auth layer — never from the model
        principal = Principal(id="user:alice", tenant_id="acme")
        result_json = tool.handle_call(
            principal=principal,
            arguments_json=tool_call.function.arguments,
        )
        # result_json contains the signed capability.
        # Pass it to your connector for execution.
        # my_connector.execute(deserialize_capability(result_json))
```

`handle_call` returns a JSON string with the authorization result:

```json
{
  "status": "authorized",
  "execution_id": "exec_abc123",
  "resource": "orders",
  "operation": "read",
  "fields": ["id", "total", "status"],
  "predicates": [{"field": "tenant_id", "operator": "=", "value": "acme"}],
  "limit": 10
}
```

On denial:

```json
{"status": "denied", "reasons": ["Operation 'delete' is not permitted"]}
```

---

## Anthropic / Claude tool use

```python
from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
from datafence.core.principal import Principal
import anthropic

tool = DataFenceAnthropicTool(boundary)

client = anthropic.Anthropic()
response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    tools=[tool.anthropic_tool_spec()],
    messages=[{"role": "user", "content": "Show me my recent orders"}],
)

for block in response.content:
    if block.type == "tool_use":
        principal = Principal(id="user:alice", tenant_id="acme")
        result_json = tool.handle_call(
            principal=principal,
            tool_input=block.input,
        )
        # Pass the capability to your connector.
```

---

## LangChain

```python
from datafence.integrations.langchain_tool import DataFenceLangChainTool
from datafence.core.principal import Principal

# The principal is bound at construction — the agent cannot change it.
principal = Principal(id="user:alice", tenant_id="acme")
tool = DataFenceLangChainTool(boundary=boundary, principal=principal)

# Direct use:
result_json = tool.run('{"resource": "orders", "fields": ["id", "total"], "limit": 5}')

# Or wrap as a proper LangChain BaseTool (requires langchain installed):
lc_tool = tool.as_langchain_tool()
```

The principal is fixed at construction time.  A LangChain agent running the
tool cannot choose or modify it.

---

## MCP (Model Context Protocol)

```python
from datafence.mcp.server import DataFenceMCPServer
from datafence.core.principal import Principal

def my_auth_resolver(session_context: dict) -> Principal:
    """
    Map authenticated session context → Principal.
    This function owns authentication; DataFence never authenticates.
    """
    token = session_context["verified_token"]   # pre-verified by transport
    user = your_auth_system.verify(token)
    return Principal(id=f"user:{user.id}", tenant_id=user.tenant_id)

server = DataFenceMCPServer(
    boundary=boundary,
    server_name="my-datafence",
    principal_resolver=my_auth_resolver,   # REQUIRED — no default
)

# Transport adapter calls:
response = server.handle_call_tool(
    tool_name="datafence_query",
    arguments={"resource": "orders", "fields": ["id", "total"]},
    session_context={"verified_token": "..."},   # from transport, not agent JSON
)
```

`principal_resolver` is **required**.  Omitting it raises `TypeError` at
construction time.  The agent's JSON arguments are never used as identity.

An allowed MCP response contains the authorization result:

```json
{
  "status": "authorized",
  "capability": {
    "execution_id": "exec_abc123",
    "resource": "orders",
    "selected_fields": ["id", "total"],
    "predicates": [...],
    "limit": 10
  },
  "request_id": "exec_abc123",
  "evidence_id": "exec_abc123"
}
```

No database rows are returned through the MCP layer.

---

## REST API

Start the API server (requires `datafence[api]`):

```bash
datafence api --host 0.0.0.0 --port 8000
```

### `POST /authorize`

Authorize an intent and receive a signed capability.

```bash
curl -X POST http://localhost:8000/authorize \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"resource": "orders", "fields": ["id", "total"], "limit": 5}'
```

Response:

```json
{
  "status": "authorized",
  "execution_id": "exec_abc123",
  "resource": "orders",
  "operation": "read",
  "fields": ["id", "total"],
  "predicates": [{"field": "tenant_id", "operator": "=", "value": "acme"}],
  "limit": 5,
  "expires_at": "2026-10-02T17:00:00Z"
}
```

The API server resolves the principal from the `Authorization` header.
The body is untrusted Intent only.

---

## Security invariants across all integrations

1. **Principal is always application-owned** — comes from your auth layer, not the AI.
2. **Agent controls only Intent** — resource, fields, filters are treated as untrusted.
3. **DataFence returns a capability, not data** — the model never sees database rows.
4. **Connector executes, DataFence authorizes** — they are separate concerns.
5. **All capabilities are HMAC-signed** — tampering is detected by the connector.

---

## Further reading

- [Architecture](architecture.md) — full security model
- [Connector Guide](connectors.md) — implementing your connector
- [examples/](../examples/) — runnable end-to-end examples
