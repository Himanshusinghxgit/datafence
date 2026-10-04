# DataFence Integration Examples

Examples demonstrating how to use DataFence with popular AI frameworks.

## Security model recap

In every integration, the principal comes from **your auth layer**, not the AI:

```
AI framework (proposes Intent)
        ↓
DataFenceBoundary.authorize(principal, intent)
        ↓
AuthorizedExecution  ← signed capability
        ↓
Your connector  ← executes, you own this
        ↓
Enterprise data
```

DataFence returns a signed authorization capability — not database rows.

---

## Installation

```bash
# Core only
pip install datafence

# With AI framework adapters
pip install 'datafence[integrations]'   # openai, anthropic, langchain

# REST API server
pip install 'datafence[api]'

# CLI tool
pip install 'datafence[cli]'
```

---

## Examples

### 1. OpenAI function-calling (`openai_example.py`)

```bash
export OPENAI_API_KEY=sk-...
python openai_example.py
```

Uses `DataFenceOpenAITool` to expose the authorization boundary as an OpenAI
function-calling tool.  The model's function call arguments become untrusted
`Intent`; the `Principal` is provided by your application.

```python
from datafence.integrations.openai_tool import DataFenceOpenAITool
from datafence.core.principal import Principal

tool = DataFenceOpenAITool(boundary)

# In your message loop, when the model calls the tool:
principal = Principal(id="user:alice", tenant_id="acme")   # from YOUR auth
result_json = tool.handle_call(
    principal=principal,
    arguments_json=tool_call.function.arguments,   # from the model
)
# result_json contains the signed capability — pass it to your connector.
```

---

### 2. Anthropic Claude tool use (`claude_example.py`)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python claude_example.py
```

Uses `DataFenceAnthropicTool` to expose the boundary as a Claude tool_use
tool.  The `tool_input` dict from Claude is untrusted `Intent`; the
`Principal` is provided by your application.

```python
from datafence.integrations.anthropic_tool import DataFenceAnthropicTool
from datafence.core.principal import Principal

tool = DataFenceAnthropicTool(boundary)

for block in response.content:
    if block.type == "tool_use":
        principal = Principal(id="user:alice", tenant_id="acme")
        result_json = tool.handle_call(principal=principal, tool_input=block.input)
        # result_json contains the signed capability.
```

---

### 3. LangChain tool (`langchain_example.py`)

```bash
export OPENAI_API_KEY=sk-...
python langchain_example.py
```

Uses `DataFenceLangChainTool`.  The `Principal` is **bound at construction
time** — a LangChain agent cannot change it during the conversation.

```python
from datafence.integrations.langchain_tool import DataFenceLangChainTool
from datafence.core.principal import Principal

principal = Principal(id="user:alice", tenant_id="acme")   # bound here
tool = DataFenceLangChainTool(boundary=boundary, principal=principal)

# Direct use:
result_json = tool.run('{"resource": "orders", "fields": ["id", "total"]}')

# Or as a proper LangChain tool (requires langchain installed):
lc_tool = tool.as_langchain_tool()
```

---

### 4. REST API (`api_example.py`)

```bash
# Start the authorization server
datafence api

# In another terminal, run the client example
python api_example.py
```

The API server exposes a `POST /authorize` endpoint.  The caller sends
`Intent` in the body; the server resolves the `Principal` from the
`Authorization: Bearer` header.  The response is a signed capability,
**not database rows**.

```bash
curl -X POST http://localhost:8000/authorize \
  -H "Authorization: Bearer your-session-token" \
  -H "Content-Type: application/json" \
  -d '{"resource": "orders", "fields": ["id", "total"], "limit": 5}'
```

---

### 5. CLI (`cli_example.sh`)

```bash
chmod +x cli_example.sh
./cli_example.sh
```

---

## Troubleshooting

```bash
# Missing integrations package
pip install 'datafence[integrations]'

# Missing API server
pip install 'datafence[api]'

# Missing CLI
pip install 'datafence[cli]'

# Missing framework keys
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Further reading

- [Connector Guide](../../docs/connectors.md) — implementing your connector
- [Integration Guide](../../docs/integrations.md) — full integration patterns
- [Architecture](../../docs/architecture.md) — security model
