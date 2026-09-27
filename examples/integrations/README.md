# DataFence Integration Examples

Examples demonstrating DataFence integration with popular AI frameworks and tools.

## Installation

Install DataFence with integration dependencies:

```bash
# All integrations
pip install 'datafence[all]'

# Individual integrations
pip install 'datafence[integrations]'  # OpenAI, Claude, LangChain
pip install 'datafence[cli]'           # CLI tool
pip install 'datafence[api]'           # REST API
```

## Examples

### 1. OpenAI Function Calling

Use DataFence with OpenAI's function calling API.

```bash
export OPENAI_API_KEY=your-key
python openai_example.py
```

**Features:**
- Automatic function schema generation from policies
- Secure execution through DataFence
- Support for streaming responses
- Simple agent helper function

**Use case:** AI assistants that query databases with automatic security enforcement.

### 2. Anthropic Claude Tool Use

Use DataFence with Claude's tool use API.

```bash
export ANTHROPIC_API_KEY=your-key
python claude_example.py
```

**Features:**
- Tool schema generation from policies
- Multi-turn tool use support
- Simple agent helper function
- Proper tool result formatting

**Use case:** Claude-powered agents accessing secure data sources.

### 3. LangChain Tools

Use DataFence as LangChain tools in agent workflows.

```bash
export OPENAI_API_KEY=your-key
python langchain_example.py
```

**Features:**
- Generic tool for all resources
- Resource-specific tools for better descriptions
- Async support
- Works with any LangChain agent

**Use case:** LangChain agent applications with enterprise data access.

### 4. CLI Tool

Command-line interface for policy management and testing.

```bash
# Make executable
chmod +x cli_example.sh

# Run examples
./cli_example.sh
```

**Commands:**
- `datafence init` - Create sample policy
- `datafence validate` - Validate policy file
- `datafence describe` - Show resource details
- `datafence test` - Test requests (dry-run or execute)
- `datafence export` - Export to framework schemas

**Use case:** Policy development, validation, and testing workflow.

### 5. REST API

Run DataFence as a REST API service.

```bash
# Start server
python -m datafence.api ../../policies/banking.yaml --port 8000 --api-key secret-123

# In another terminal, run client
python api_example.py
```

**Features:**
- OpenAPI/Swagger documentation
- API key authentication
- CORS support
- Health checks
- Policy introspection

**Use case:** Multi-language clients, microservices, remote access.

## Quick Start Guide

### OpenAI Integration

```python
from datafence import DataFence
from datafence.integrations.openai_adapter import create_openai_agent

fence = DataFence.from_yaml("policy.yaml", connector)
agent = create_openai_agent(fence, model="gpt-4")

response = agent(
    "Show me transactions",
    actor={"id": "user:123", "tenant_id": "acme"}
)
```

### Claude Integration

```python
from datafence import DataFence
from datafence.integrations.anthropic_adapter import create_claude_agent

fence = DataFence.from_yaml("policy.yaml", connector)
agent = create_claude_agent(fence, model="claude-3-5-sonnet-20241022")

response = agent(
    "Show me transactions",
    actor={"id": "user:123", "tenant_id": "acme"}
)
```

### LangChain Integration

```python
from datafence import DataFence
from datafence.integrations.langchain_tool import create_datafence_tools

fence = DataFence.from_yaml("policy.yaml", connector)
tools = create_datafence_tools(fence, actor={"id": "user:123", "tenant_id": "acme"})

# Use with any LangChain agent
from langchain.agents import create_openai_functions_agent
agent = create_openai_functions_agent(llm, tools, prompt)
```

### CLI Usage

```bash
# Validate policy
datafence validate policy.yaml

# Test request
datafence test policy.yaml request.json --dry-run

# Export to OpenAI format
datafence export policy.yaml --framework openai -o functions.json
```

### REST API

```python
from datafence import DataFence
from datafence.api import run_api

fence = DataFence.from_yaml("policy.yaml", connector)
run_api(fence, port=8000, api_keys={"secret-key"})
```

Then use any HTTP client:
```bash
curl -X POST http://localhost:8000/execute \
  -H "Authorization: Bearer secret-key" \
  -H "Content-Type: application/json" \
  -d '{
    "actor": {"id": "user:123", "tenant_id": "acme"},
    "operation": "read",
    "resource": "transactions",
    "fields": ["id", "amount"],
    "limit": 10
  }'
```

## Architecture

All integrations follow the same pattern:

```
┌─────────────────┐
│   AI Framework  │  (OpenAI, Claude, LangChain)
│   (proposes)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Adapter      │  Converts framework-specific format
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   DataFence     │  Enforces policies
│   (decides)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Connector     │  Executes query
└─────────────────┘
```

**Key principle:** The AI proposes actions, adapters translate, DataFence decides and enforces.

## Security Notes

1. **Adapters don't bypass security** - All requests go through DataFence policy enforcement
2. **Actor information required** - Every request must include actor context
3. **Policies apply consistently** - Same policies across all integrations
4. **Evidence preserved** - All executions generate audit trails
5. **API keys for production** - Use authentication for REST API in production

## Troubleshooting

### Import Errors

```python
# Error: No module named 'openai'
pip install 'datafence[integrations]'

# Error: No module named 'click'
pip install 'datafence[cli]'

# Error: No module named 'fastapi'
pip install 'datafence[api]'
```

### Authentication Errors

```bash
# OpenAI
export OPENAI_API_KEY=your-key

# Claude
export ANTHROPIC_API_KEY=your-key

# API server
python -m datafence.api policy.yaml --api-key your-secret
```

### Policy Errors

```bash
# Validate policy first
datafence validate policy.yaml --verbose

# Test request without execution
datafence test policy.yaml request.json --dry-run
```

## Production Considerations

### OpenAI/Claude Agents
- Set appropriate timeouts
- Handle rate limits
- Log all executions
- Monitor API costs
- Cache policy schemas

### LangChain
- Use resource-specific tools for better performance
- Set tool descriptions clearly
- Handle tool errors gracefully
- Consider async execution

### CLI
- Integrate into CI/CD for policy validation
- Use in pre-commit hooks
- Automate testing with sample requests

### REST API
- Use API key authentication
- Enable rate limiting (add middleware)
- Deploy behind reverse proxy (nginx, etc.)
- Monitor endpoints
- Use HTTPS in production
- Consider horizontal scaling

## Next Steps

1. **Choose your framework** - Start with the integration matching your stack
2. **Review the policy** - Check `../../policies/` for policy examples
3. **Run the examples** - Test with sample data first
4. **Adapt to your use case** - Modify for your data sources and policies
5. **Deploy to production** - Follow security best practices

## Resources

- [DataFence Documentation](../../README.md)
- [Policy Guide](../../docs/policies.md)
- [Connector Guide](../../docs/connectors.md)
- [Architecture](../../docs/architecture.md)
- [OpenAI Function Calling](https://platform.openai.com/docs/guides/function-calling)
- [Claude Tool Use](https://docs.anthropic.com/claude/docs/tool-use)
- [LangChain Tools](https://python.langchain.com/docs/modules/agents/tools/)
