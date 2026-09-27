# Integration Guide

DataFence integrates with popular AI frameworks and tools to provide seamless security enforcement.

## Overview

DataFence provides integrations for:

1. **OpenAI** - Function calling with GPT-4 and other models
2. **Anthropic Claude** - Tool use with Claude 3.5
3. **LangChain** - Custom tools for agent workflows
4. **CLI** - Command-line tool for development and testing
5. **REST API** - HTTP API for any language/platform

All integrations maintain the same security guarantees as direct DataFence usage.

## Installation

```bash
# All integrations
pip install 'datafence[all]'

# Specific integrations
pip install 'datafence[integrations]'  # OpenAI, Claude, LangChain
pip install 'datafence[cli]'           # CLI tool
pip install 'datafence[api]'           # REST API

# Individual frameworks
pip install datafence openai           # OpenAI only
pip install datafence anthropic        # Claude only
pip install datafence langchain        # LangChain only
```

## OpenAI Integration

### Function Calling Adapter

The OpenAI adapter converts DataFence policies into OpenAI function schemas.

```python
from datafence import DataFence
from datafence.integrations.openai_adapter import OpenAIAdapter

fence = DataFence.from_yaml("policy.yaml", connector)
adapter = OpenAIAdapter(fence)

# Get function schemas for OpenAI
functions = adapter.get_functions()

# Use with OpenAI
import openai
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
```

### Simple Agent Helper

For quick prototyping:

```python
from datafence.integrations.openai_adapter import create_openai_agent

agent = create_openai_agent(
    fence,
    model="gpt-4",
    system_prompt="You are a helpful assistant."
)

response = agent(
    "Show me transactions for customer 123",
    actor={"id": "user:123", "tenant_id": "acme"}
)
```

### Streaming Support

Handle streaming responses with function calls:

```python
from datafence.integrations.openai_adapter import OpenAIStreamingAdapter

adapter = OpenAIStreamingAdapter(fence)

for chunk in openai.ChatCompletion.create(..., stream=True):
    text_delta, function_call = adapter.process_stream_chunk(chunk)
    
    if text_delta:
        print(text_delta, end="")
    
    if function_call:
        # Execute function
        result = adapter.execute_function_call(
            function_call,
            actor=actor
        )
```

### Schema Generation

DataFence automatically generates function schemas from policies:

**Policy:**
```yaml
resources:
  transactions:
    operations:
      allow: [read]
    fields:
      allow: [id, amount, merchant, timestamp]
```

**Generated Function:**
```json
{
  "name": "read_transactions",
  "description": "Read data from transactions table with security enforcement",
  "parameters": {
    "type": "object",
    "properties": {
      "fields": {
        "type": "array",
        "items": {"type": "string", "enum": ["id", "amount", "merchant", "timestamp"]}
      },
      "filters": {"type": "object"},
      "limit": {"type": "integer"}
    }
  }
}
```

## Anthropic Claude Integration

### Tool Use Adapter

The Claude adapter converts policies into Claude tool schemas.

```python
from datafence import DataFence
from datafence.integrations.anthropic_adapter import ClaudeAdapter

fence = DataFence.from_yaml("policy.yaml", connector)
adapter = ClaudeAdapter(fence)

# Get tool schemas
tools = adapter.get_tools()

# Use with Claude
import anthropic
client = anthropic.Anthropic()

response = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    tools=tools,
    messages=[{"role": "user", "content": "Show me transactions"}]
)

# Execute tool use
if response.stop_reason == "tool_use":
    for block in response.content:
        if block.type == "tool_use":
            result = adapter.execute_tool(
                block.name,
                block.input,
                actor={"id": "user:123", "tenant_id": "acme"}
            )
```

### Simple Agent Helper

```python
from datafence.integrations.anthropic_adapter import create_claude_agent

agent = create_claude_agent(
    fence,
    model="claude-3-5-sonnet-20241022",
    system_prompt="You are a helpful assistant.",
    max_tokens=1024
)

response = agent(
    "Show me recent transactions",
    actor={"id": "user:123", "tenant_id": "acme"}
)
```

### Multi-Turn Tool Use

Claude may use tools multiple times in a conversation:

```python
adapter = ClaudeAdapter(fence)
messages = [{"role": "user", "content": "Compare transactions"}]

while True:
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        messages=messages,
        tools=tools
    )
    
    if response.stop_reason != "tool_use":
        break
    
    # Process all tool uses
    tool_results = []
    for block in response.content:
        if block.type == "tool_use":
            result = adapter.execute_tool(block.name, block.input, actor)
            tool_results.append(
                adapter.create_tool_result_block(block.id, result)
            )
    
    # Continue conversation
    messages.append({"role": "assistant", "content": response.content})
    messages.append({"role": "user", "content": tool_results})
```

## LangChain Integration

### Generic Tool

Single tool for all resources:

```python
from datafence.integrations.langchain_tool import DataFenceTool

tool = DataFenceTool(
    fence=fence,
    actor={"id": "user:123", "tenant_id": "acme"}
)

# Use with any LangChain agent
from langchain.agents import create_openai_functions_agent
agent = create_openai_functions_agent(llm, [tool], prompt)
```

### Resource-Specific Tools

Better descriptions for each resource:

```python
from datafence.integrations.langchain_tool import create_datafence_tools

tools = create_datafence_tools(
    fence,
    actor={"id": "user:123", "tenant_id": "acme"}
)

# Each resource gets its own tool
# e.g., query_transactions, query_users, etc.
agent = create_openai_functions_agent(llm, tools, prompt)
```

### With LangChain Agents

```python
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain.prompts import ChatPromptTemplate, MessagesPlaceholder

llm = ChatOpenAI(model="gpt-4")
tools = create_datafence_tools(fence, actor=actor)

prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful assistant."),
    ("human", "{input}"),
    MessagesPlaceholder(variable_name="agent_scratchpad"),
])

agent = create_openai_functions_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools)

response = agent_executor.invoke({"input": "Show me transactions"})
```

### Async Support

```python
# Async execution
result = await tool._arun(
    resource="transactions",
    fields=["id", "amount"],
    limit=10
)
```

## CLI Tool

### Installation

The CLI is available after installing with the `cli` extra:

```bash
pip install 'datafence[cli]'
datafence --help
```

### Commands

#### Initialize Policy

```bash
datafence init --output policy.yaml
```

Creates a sample policy file to get started.

#### Validate Policy

```bash
datafence validate policy.yaml
datafence validate policy.yaml --verbose
```

Checks YAML syntax, schema compliance, and logical consistency.

#### Describe Resource

```bash
datafence describe policy.yaml --resource transactions
datafence describe policy.yaml -r users --format json
```

Shows resource configuration from policy.

#### Test Request

```bash
# Dry-run (check without executing)
datafence test policy.yaml request.json --dry-run

# Full execution
datafence test policy.yaml request.json --connector sqlite --database data.db

# Verbose output
datafence test policy.yaml request.json --dry-run --verbose
```

Tests a request against the policy.

**Request Format (JSON):**
```json
{
  "actor": {
    "id": "agent:test",
    "tenant_id": "acme"
  },
  "operation": "read",
  "resource": "transactions",
  "fields": ["id", "amount"],
  "filters": {"customer_id": "123"},
  "limit": 10
}
```

#### Export to Framework Format

```bash
# OpenAI functions
datafence export policy.yaml --framework openai

# Claude tools
datafence export policy.yaml --framework claude -o tools.json
```

Generates framework-specific schemas from policy.

### CI/CD Integration

Use the CLI in continuous integration:

```bash
#!/bin/bash
# .github/workflows/validate-policy.sh

# Validate all policies
for policy in policies/*.yaml; do
    echo "Validating $policy"
    datafence validate "$policy" || exit 1
done

# Test against sample requests
for request in tests/requests/*.json; do
    echo "Testing $request"
    datafence test policies/main.yaml "$request" --dry-run || exit 1
done
```

## REST API

### Starting the Server

#### From Command Line

```bash
# Basic
python -m datafence.api policy.yaml

# Custom port
python -m datafence.api policy.yaml --port 8080

# With authentication
python -m datafence.api policy.yaml --api-key secret-key-123
```

#### From Python

```python
from datafence import DataFence
from datafence.api import run_api

fence = DataFence.from_yaml("policy.yaml", connector)
run_api(fence, port=8000, api_keys={"secret-key-123"})
```

#### With FastAPI Directly

```python
from datafence.api import create_api
import uvicorn

fence = DataFence.from_yaml("policy.yaml", connector)
app = create_api(
    fence,
    api_keys={"secret-key-123"},
    enable_cors=True,
    title="My DataFence API"
)

uvicorn.run(app, host="0.0.0.0", port=8000)
```

### API Endpoints

#### Execute Query

```http
POST /execute
Authorization: Bearer secret-key-123
Content-Type: application/json

{
  "actor": {"id": "user:123", "tenant_id": "acme"},
  "operation": "read",
  "resource": "transactions",
  "fields": ["id", "amount", "merchant"],
  "filters": {"customer_id": "123"},
  "limit": 10
}
```

Response:
```json
{
  "success": true,
  "verified": true,
  "data": [...],
  "row_count": 3,
  "decision": "allow",
  "evidence_hash": "abc123...",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### Describe Resource

```http
POST /describe
Authorization: Bearer secret-key-123
Content-Type: application/json

{
  "resource": "transactions"
}
```

#### Get Policy

```http
GET /policy
Authorization: Bearer secret-key-123
```

#### Get Resource Policy

```http
GET /policy/resources/transactions
Authorization: Bearer secret-key-123
```

#### Health Check

```http
GET /health
```

### Client Examples

#### cURL

```bash
curl -X POST http://localhost:8000/execute \
  -H "Authorization: Bearer secret-key-123" \
  -H "Content-Type: application/json" \
  -d '{
    "actor": {"id": "user:123", "tenant_id": "acme"},
    "operation": "read",
    "resource": "transactions",
    "limit": 10
  }'
```

#### Python

```python
import requests

response = requests.post(
    "http://localhost:8000/execute",
    headers={"Authorization": "Bearer secret-key-123"},
    json={
        "actor": {"id": "user:123", "tenant_id": "acme"},
        "operation": "read",
        "resource": "transactions",
        "limit": 10
    }
)

print(response.json())
```

#### JavaScript

```javascript
const response = await fetch('http://localhost:8000/execute', {
  method: 'POST',
  headers: {
    'Authorization': 'Bearer secret-key-123',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    actor: {id: 'user:123', tenant_id: 'acme'},
    operation: 'read',
    resource: 'transactions',
    limit: 10
  })
});

const result = await response.json();
console.log(result);
```

### OpenAPI Documentation

When the API is running, visit:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### Production Deployment

#### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY policy.yaml .
COPY src/ ./src/

ENV API_KEY=your-secret-key

CMD ["python", "-m", "datafence.api", "policy.yaml", "--port", "8000", "--api-key", "${API_KEY}"]
```

#### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: datafence-api
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: datafence
        image: datafence-api:latest
        ports:
        - containerPort: 8000
        env:
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: datafence-secrets
              key: api-key
```

#### Nginx Reverse Proxy

```nginx
upstream datafence {
    server localhost:8000;
    server localhost:8001;
    server localhost:8002;
}

server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://datafence;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Considerations

### Authentication

All integrations support actor-based authentication:

```python
actor = {
    "id": "user:123",           # Unique user identifier
    "tenant_id": "acme",        # Tenant for isolation
    "type": "user",             # Actor type
    "roles": ["viewer"],        # Optional roles
    "customer_id": "cust_456"   # Optional attributes
}
```

### API Keys

For the REST API, use strong API keys:

```python
import secrets

# Generate secure API key
api_key = secrets.token_urlsafe(32)

# Use in production
run_api(fence, api_keys={api_key})
```

### Rate Limiting

Add rate limiting middleware (example with FastAPI):

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = create_api(fence, api_keys=api_keys)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/execute")
@limiter.limit("10/minute")
async def execute_with_limit(request: Request, ...):
    ...
```

### Logging

All integrations support audit logging:

```python
import logging

logging.basicConfig(
    filename='datafence.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# DataFence will log all executions
fence = DataFence.from_yaml("policy.yaml", connector)
```

## Best Practices

1. **Use resource-specific tools** - Better performance and clearer descriptions
2. **Set appropriate timeouts** - Prevent long-running queries
3. **Validate policies in CI/CD** - Use CLI in automated testing
4. **Monitor API usage** - Track costs and performance
5. **Use authentication in production** - Never expose APIs without auth
6. **Cache schemas** - Regenerate only when policies change
7. **Handle errors gracefully** - AI frameworks may retry
8. **Log all executions** - Maintain audit trail
9. **Test with dry-run** - Validate before executing
10. **Keep policies simple** - Easier to maintain and faster to evaluate

## Next Steps

- See [examples/integrations/](../examples/integrations/) for working code
- Review [Policy Guide](policies.md) for policy configuration
- Check [Architecture](architecture.md) for system design
- Read framework-specific documentation for advanced features
