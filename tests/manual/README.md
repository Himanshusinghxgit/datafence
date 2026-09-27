# Manual Testing Scripts

These scripts test the production connectors with real databases. **Not for automated CI/CD**.

## Quick Start

### PostgreSQL
```bash
# Start Docker container
docker run --name datafence-postgres -e POSTGRES_PASSWORD=testpass -p 5432:5432 -d postgres

# Install and run
pip install 'datafence[postgres]'
export DATAFENCE_POSTGRES_HOST=localhost
export DATAFENCE_POSTGRES_PORT=5432
export DATAFENCE_POSTGRES_DATABASE=postgres
export DATAFENCE_POSTGRES_USER=postgres
export DATAFENCE_POSTGRES_PASSWORD=testpass
python tests/manual/test_postgres_manual.py
```

### Amazon Athena
```bash
# Install
pip install 'datafence[athena]'

# Configure AWS credentials (choose one)
export AWS_PROFILE=your-profile
# OR
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret

# Set Athena config
export DATAFENCE_ATHENA_DATABASE=your_database
export DATAFENCE_ATHENA_S3_OUTPUT=s3://your-bucket/results/
export DATAFENCE_ATHENA_REGION=us-east-1
export TEST_TABLE_NAME=your_table

python tests/manual/test_athena_manual.py
```

### Snowflake
```bash
# Install
pip install 'datafence[snowflake]'

# Configure
export DATAFENCE_SNOWFLAKE_ACCOUNT=your_account
export DATAFENCE_SNOWFLAKE_USER=your_user
export DATAFENCE_SNOWFLAKE_PASSWORD=your_password
export DATAFENCE_SNOWFLAKE_DATABASE=your_database
export DATAFENCE_SNOWFLAKE_WAREHOUSE=your_warehouse
export DATAFENCE_SNOWFLAKE_SCHEMA=PUBLIC
export TEST_TABLE_NAME=YOUR_TABLE

python tests/manual/test_snowflake_manual.py
```

## What Gets Tested

- Connection establishment
- Table metadata retrieval (describe)
- Basic queries with filters
- Field restrictions (policy simulation)
- LIMIT clauses
- SQL injection prevention (PostgreSQL)
- Parameterized queries
- Connection pooling
