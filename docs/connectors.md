# Connector Guide

DataFence connectors execute validated requests against data systems.

## Available Connectors

### Memory Connector
In-memory testing, no external dependencies.

```python
from datafence.connectors import MemoryConnector

connector = MemoryConnector(data={
    "users": [
        {"id": 1, "name": "Alice", "tenant_id": "acme"},
        {"id": 2, "name": "Bob", "tenant_id": "acme"},
    ]
})
```

### SQLite Connector
Local development and testing.

```python
from datafence.connectors import SQLiteConnector

connector = SQLiteConnector("data.db")
```

### PostgreSQL Connector
Production databases with connection pooling.

**Installation:**
```bash
pip install 'datafence[postgres]'
```

**Features:**
- Connection pooling (psycopg3 + psycopg_pool)
- Prepared statements (SQL injection prevention)
- Proper identifier quoting
- Transaction support
- Dict-based results

**Usage:**
```python
from datafence.connectors import PostgreSQLConnector

connector = PostgreSQLConnector(
    host="localhost",
    port=5432,
    database="mydb",
    user="myuser",
    password="mypassword",
    min_pool_size=2,
    max_pool_size=10,
    timeout=30.0
)

# Or use connection string
connector = PostgreSQLConnector(
    connection_string="postgresql://user:pass@localhost:5432/mydb"
)

# Use with context manager
with connector:
    result = connector.execute(request)
```

**Environment Variables:**
```bash
export DATAFENCE_POSTGRES_HOST=localhost
export DATAFENCE_POSTGRES_PORT=5432
export DATAFENCE_POSTGRES_DATABASE=mydb
export DATAFENCE_POSTGRES_USER=myuser
export DATAFENCE_POSTGRES_PASSWORD=mypassword
```

### Amazon Athena Connector
Query S3 data lakes with SQL.

**Installation:**
```bash
pip install 'datafence[athena]'
```

**Features:**
- Query S3 data with standard SQL
- Automatic result pagination
- Query execution tracking
- S3 result location management
- AWS credentials from environment/profile

**Usage:**
```python
from datafence.connectors import AthenaConnector

connector = AthenaConnector(
    database="mydatabase",
    s3_output_location="s3://my-bucket/query-results/",
    region_name="us-east-1",
    workgroup="primary",
    poll_interval=1.0,
    max_wait_time=300.0
)

# With AWS credentials
connector = AthenaConnector(
    database="mydatabase",
    s3_output_location="s3://my-bucket/results/",
    aws_access_key_id="YOUR_KEY",
    aws_secret_access_key="YOUR_SECRET",
    region_name="us-east-1"
)

# Or use AWS profile
connector = AthenaConnector(
    database="mydatabase",
    s3_output_location="s3://my-bucket/results/",
    profile_name="my-profile",
    region_name="us-east-1"
)
```

**Environment Variables:**
```bash
export DATAFENCE_ATHENA_DATABASE=mydatabase
export DATAFENCE_ATHENA_S3_OUTPUT=s3://my-bucket/results/
export DATAFENCE_ATHENA_REGION=us-east-1
export DATAFENCE_ATHENA_WORKGROUP=primary

# AWS credentials (standard)
export AWS_PROFILE=my-profile
# OR
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
```

### Snowflake Connector
Cloud data warehouse queries.

**Installation:**
```bash
pip install 'datafence[snowflake]'
```

**Features:**
- Connection pooling
- Multiple authentication methods (password, key-pair, SSO)
- Warehouse and schema management
- Proper error handling
- Dict-based results

**Usage:**
```python
from datafence.connectors import SnowflakeConnector

# Password authentication
connector = SnowflakeConnector(
    account="myaccount",
    user="myuser",
    password="mypassword",
    database="MYDB",
    schema="PUBLIC",
    warehouse="COMPUTE_WH",
    role="SYSADMIN",
    timeout=300
)

# SSO authentication
connector = SnowflakeConnector(
    account="myaccount",
    user="myuser@company.com",
    authenticator="externalbrowser",
    database="MYDB",
    warehouse="COMPUTE_WH"
)

# Key-pair authentication
with open("private_key.pem", "rb") as f:
    private_key = f.read()

connector = SnowflakeConnector(
    account="myaccount",
    user="myuser",
    private_key=private_key,
    database="MYDB",
    warehouse="COMPUTE_WH"
)
```

**Environment Variables:**
```bash
export DATAFENCE_SNOWFLAKE_ACCOUNT=myaccount
export DATAFENCE_SNOWFLAKE_USER=myuser
export DATAFENCE_SNOWFLAKE_PASSWORD=mypassword
export DATAFENCE_SNOWFLAKE_DATABASE=MYDB
export DATAFENCE_SNOWFLAKE_SCHEMA=PUBLIC
export DATAFENCE_SNOWFLAKE_WAREHOUSE=COMPUTE_WH
```

## Configuration Management

### Using ConnectorConfig

```python
from datafence.connectors.config import ConnectorConfig

# Load from environment
config = ConnectorConfig.from_env()
connector = ConnectorConfig.create_connector("postgres", config["postgres"])

# Load from YAML
config = ConnectorConfig.from_yaml("config.yaml")
connector = ConnectorConfig.create_connector("athena", config["athena"])

# Load from connection string
config = ConnectorConfig.from_connection_string(
    "postgresql://user:pass@localhost:5432/mydb"
)
connector = ConnectorConfig.create_connector("postgres", config["postgres"])
```

### YAML Configuration

```yaml
# config.yaml
postgres:
  host: localhost
  port: 5432
  database: mydb
  user: myuser
  password: mypassword
  min_pool_size: 2
  max_pool_size: 10

athena:
  database: mydatabase
  s3_output_location: s3://my-bucket/results/
  region_name: us-east-1
  workgroup: primary

snowflake:
  account: myaccount
  user: myuser
  password: mypassword
  database: MYDB
  schema: PUBLIC
  warehouse: COMPUTE_WH
```

### Connection Strings

```python
# PostgreSQL
"postgresql://user:pass@localhost:5432/mydb"

# Athena
"athena://mydatabase?s3_output=s3://bucket/path&region=us-east-1"

# Snowflake
"snowflake://user:pass@account/database?warehouse=WH&schema=PUBLIC"
```

## Connector Interface

All connectors implement the `DataConnector` interface:

```python
class DataConnector:
    def execute(
        self,
        request: ExecutionRequest,
        allowed_fields: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Execute validated request."""
        ...
    
    def describe(self, resource: str) -> dict[str, Any]:
        """Get resource metadata."""
        ...
    
    def close(self) -> None:
        """Close connections."""
        ...
    
    def __enter__(self) -> "DataConnector":
        """Context manager entry."""
        ...
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        ...
```

## Security Features

### SQL Injection Prevention

All production connectors use parameterized queries:

```python
# PostgreSQL and Snowflake use %s placeholders
query = "SELECT * FROM users WHERE tenant_id = %s"
cursor.execute(query, [tenant_id])

# Identifiers are properly quoted
"SELECT \"user_id\", \"email\" FROM \"users\""
```

### Connection Security

- **PostgreSQL**: SSL/TLS support via connection string
- **Athena**: AWS IAM authentication
- **Snowflake**: Multiple auth methods (password, key-pair, SSO)

### Connection Pooling

- **PostgreSQL**: psycopg3 ConnectionPool (configurable min/max)
- **Athena**: Managed by boto3
- **Snowflake**: Built-in connection pooling

### Timeout Protection

All connectors support query timeouts:
- **PostgreSQL**: `statement_timeout`
- **Athena**: `max_wait_time`
- **Snowflake**: `STATEMENT_TIMEOUT_IN_SECONDS`

## Testing

See `tests/manual/` for manual testing scripts:

```bash
# PostgreSQL (with Docker)
docker run --name datafence-postgres -e POSTGRES_PASSWORD=testpass -p 5432:5432 -d postgres
python tests/manual/test_postgres_manual.py

# Athena (requires AWS account)
python tests/manual/test_athena_manual.py

# Snowflake (requires Snowflake account)
python tests/manual/test_snowflake_manual.py
```

## Troubleshooting

### PostgreSQL

**Error: "psycopg not installed"**
```bash
pip install 'datafence[postgres]'
```

**Error: "Connection refused"**
- Check PostgreSQL is running: `pg_isready`
- Verify host/port: `psql -h localhost -p 5432 -U user -d database`
- Check firewall rules

**Error: "role does not exist"**
- Create user: `CREATE USER myuser WITH PASSWORD 'mypassword';`
- Grant permissions: `GRANT ALL ON DATABASE mydb TO myuser;`

### Athena

**Error: "boto3 not installed"**
```bash
pip install 'datafence[athena]'
```

**Error: "Access Denied"**
- Check IAM permissions: `athena:StartQueryExecution`, `athena:GetQueryResults`, `s3:PutObject`, `s3:GetObject`
- Verify S3 bucket policy
- Check workgroup permissions

**Error: "Database not found"**
- Run `SHOW DATABASES` in Athena console
- Verify AWS region matches database location

### Snowflake

**Error: "snowflake-connector-python not installed"**
```bash
pip install 'datafence[snowflake]'
```

**Error: "Incorrect username or password"**
- Verify account identifier format: `account.region.cloud` (e.g., `xy12345.us-east-1.aws`)
- Check MFA requirements
- Try SSO: `authenticator="externalbrowser"`

**Error: "Database does not exist"**
- Run `SHOW DATABASES;` in Snowflake
- Check role permissions: `GRANT USAGE ON DATABASE mydb TO ROLE myrole;`

**Error: "Warehouse not found"**
- Run `SHOW WAREHOUSES;`
- Check warehouse state: `ALTER WAREHOUSE compute_wh RESUME;`

## Best Practices

1. **Use connection pooling** - Set appropriate min/max pool sizes for PostgreSQL
2. **Set timeouts** - Prevent runaway queries
3. **Use environment variables** - Never hardcode credentials
4. **Close connections** - Use context managers (`with connector:`)
5. **Monitor costs** - Athena charges per TB scanned, Snowflake per warehouse compute time
6. **Test in staging** - Use manual test scripts before production
7. **Enable SSL/TLS** - For PostgreSQL connections
8. **Use IAM roles** - For Athena when running on AWS
9. **Rotate credentials** - Regular password/key rotation
10. **Audit logging** - Enable database audit logs

## Next Steps

- See [Policy Guide](policies.md) for policy configuration
- See [Architecture](architecture.md) for system design
- See [examples/](../examples/) for usage patterns
