# DataFence

> **A deterministic security boundary between AI agents and enterprise data.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/yourusername/datafence/releases)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-77%20passing-success.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-78%25-yellowgreen.svg)](tests/)

## The Problem

Enterprise organizations want to use LLMs against sensitive data. But LLMs are probabilistic—they can hallucinate, generate incorrect queries, request unauthorized data, or cross tenant boundaries.

**You cannot secure probabilistic systems with probabilistic controls.**

## The Solution

```text
        LLM/Agent
             │
             │ proposes
             ▼
       ┌──────────┐
       │DataFence │  ← Deterministic enforcement
       │          │  ← Policy-based authorization
       │ ENFORCES │  ← Column & row-level security
       └────┬─────┘  ← Provenance & evidence
            │
            │ executes only what is allowed
            ▼
    Enterprise Data
```

DataFence sits between AI agents and your data systems, enforcing deterministic security policies **before** any data access occurs.

### Key Principle

> **The model proposes. DataFence decides.**

## Quick Start

```bash
pip install datafence
```

```python
from datafence import DataFence
from datafence.connectors import SQLiteConnector

# Load policy
fence = DataFence.from_yaml(
    "policy.yaml",
    connector=SQLiteConnector("data.db")
)

# Execute request
result = fence.execute({
    "actor": {
        "id": "agent:finance-assistant",
        "tenant_id": "acme-corp"
    },
    "operation": "read",
    "resource": "transactions",
    "fields": ["transaction_id", "merchant", "amount", "timestamp"],
    "filters": {
        "customer_id": "123"
    }
})

# Check result
if result.verified:
    print(f"Data: {result.data}")
    print(f"Evidence: {result.evidence}")
else:
    print(f"Denied: {result.decision.reasons}")
```

## What DataFence Provides

### Core Features (Phase 1)
✅ **Policy Enforcement** - YAML-based, version-controlled security policies  
✅ **Authorization** - Actor-based access control  
✅ **Column-Level Security** - Restrict specific fields (e.g., no `card_number`)  
✅ **Row-Level Security** - Enforce tenant isolation and data filtering  
✅ **Operation Controls** - Block dangerous operations (DELETE, DROP, etc.)  
✅ **Provenance** - Track data lineage and access  
✅ **Evidence Generation** - Cryptographic proof of policy compliance  
✅ **Audit Logging** - Complete audit trail of all requests  

### Advanced Security (Phase 2 - NEW!)
✅ **SQL Query Firewall** - Block SQL injection, dangerous operations, comment attacks  
✅ **PII Detection** - Identify emails, phones, SSNs, credit cards, API keys  
✅ **PII Redaction** - Multiple strategies (MASK, TOKEN, PARTIAL, REMOVE)  
✅ **Query Validation** - Parse and validate SQL with sqlparse (not regex)  
✅ **Defense in Depth** - Multiple independent security layers  

## Policy Example

```yaml
version: "1"
policy:
  name: banking-transactions

resources:
  transactions:
    operations:
      allow: [read]
      deny: [insert, update, delete]
    
    fields:
      allow:
        - transaction_id
        - customer_id
        - merchant
        - amount
        - currency
        - timestamp
      deny:
        - card_number
        - cvv
        - account_number
    
    row_filters:
      customer_id: "{{ actor.customer_id }}"
    
    limits:
      max_rows: 1000
      max_date_range_days: 90
```

## Architecture

DataFence operates as a **deterministic enforcement layer**:

1. **Request Normalization** - Convert AI intent to structured request
2. **Policy Resolution** - Load and validate applicable policies
3. **Authorization** - Verify actor permissions
4. **Resource Validation** - Check resource access
5. **Field Validation** - Enforce column-level security
6. **Row Validation** - Apply tenant isolation and filters
7. **Query Validation** - Parse and validate SQL operations
8. **Execution** - Run query through connector
9. **Result Validation** - Verify returned data matches policy
10. **Provenance** - Generate evidence and audit trail

## What DataFence Is NOT

❌ A replacement for IAM  
❌ A replacement for database permissions  
❌ A guarantee of LLM correctness  
❌ A prompt injection detector  
❌ An LLM output moderation tool  

DataFence is an **additional deterministic enforcement layer** that works with your existing security infrastructure.

## Security Model

DataFence protects against:

- Unauthorized column access
- Unauthorized row access
- Cross-tenant data access
- Dangerous SQL operations
- Excessive query scope
- PII leakage
- Privilege escalation
- Data exfiltration

**Critical**: DataFence enforces security even if the LLM is compromised. The security boundary does not depend on the model.

## Connectors

- ✅ **Memory** - In-memory testing
- ✅ **SQLite** - Local development
- ✅ **PostgreSQL** - Production with connection pooling
- ✅ **Amazon Athena** - AWS data lakes with S3
- ✅ **Snowflake** - Cloud data warehouse

### Installation

```bash
# Core + SQLite
pip install datafence

# With production connectors
pip install 'datafence[postgres]'    # PostgreSQL
pip install 'datafence[athena]'      # Amazon Athena
pip install 'datafence[snowflake]'   # Snowflake
pip install 'datafence[all]'         # All connectors
```

### Configuration

```python
# PostgreSQL
from datafence.connectors import PostgreSQLConnector

connector = PostgreSQLConnector(
    host="localhost",
    port=5432,
    database="mydb",
    user="user",
    password="password"
)

# Amazon Athena
from datafence.connectors import AthenaConnector

connector = AthenaConnector(
    database="mydatabase",
    s3_output_location="s3://my-bucket/results/",
    region_name="us-east-1"
)

# Snowflake
from datafence.connectors import SnowflakeConnector

connector = SnowflakeConnector(
    account="myaccount",
    user="myuser",
    password="mypassword",
    database="MYDB",
    warehouse="COMPUTE_WH"
)

# Or use environment variables / config files
from datafence.connectors.config import ConnectorConfig

config = ConnectorConfig.from_env()  # or from_yaml("config.yaml")
connector = ConnectorConfig.create_connector("postgres", config["postgres"])
```

## Integrations

DataFence integrates seamlessly with popular AI frameworks:

- ✅ **OpenAI** - Function calling with GPT-4
- ✅ **Anthropic Claude** - Tool use with Claude 3.5
- ✅ **LangChain** - Custom tools for agent workflows
- ✅ **Langflow** - Visual AI workflow builder with custom components
- ✅ **CLI** - Command-line tool for development
- ✅ **REST API** - HTTP API for any language

```bash
# Install integrations
pip install 'datafence[integrations]'  # OpenAI, Claude, LangChain
pip install 'datafence[langflow]'      # Langflow custom components
pip install 'datafence[cli]'           # CLI tool
pip install 'datafence[api]'           # REST API
pip install 'datafence[all]'           # Everything
```

### Langflow Integration (NEW!)

DataFence provides custom components for Langflow that sit between your LLM and database:

```
User Query → LLM Agent → DataFence Security → Database → Protected Response
```

**Flow**: LLM proposes database queries → DataFence enforces policies → Database executes → DataFence validates results

See [Langflow Integration Guide](docs/LANGFLOW_INTEGRATION.md) and [examples/langflow/](examples/langflow/) for details.

See [Integration Guide](docs/integrations.md) for other frameworks.

## Examples

See the [examples/](examples/) directory for:

- **basic/** - Simple policy and request examples
- **banking/** - Banking transaction assistant
- **compromised-agent/** - Security against compromised AI
- **multi-tenant/** - Tenant isolation patterns
- **integrations/** - OpenAI, Claude, LangChain, CLI, API examples
- **langflow/** - Langflow custom component with visual workflow examples

## Documentation

- [Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Policy Guide](docs/policies.md)
- [Connector Development](docs/connectors.md)
- [Provenance & Evidence](docs/provenance.md)

## Development

```bash
# Clone repository
git clone https://github.com/yourusername/datafence.git
cd datafence

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check src tests
ruff format src tests

# Type checking
mypy src
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Security

Report security vulnerabilities to [security@datafence.dev](mailto:security@datafence.dev).

See [SECURITY.md](SECURITY.md) for our security policy.

---

**Let AI reason. Let DataFence enforce.**
