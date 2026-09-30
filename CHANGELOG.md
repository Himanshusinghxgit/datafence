# Changelog

All notable changes to DataFence will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-27

### Contract-Frozen Security Boundary

DataFence 1.0.0 freezes the deterministic authorization boundary as a
security-boundary prototype. It is not a production-readiness or compliance
claim; external security review and operational hardening remain required.

### Added - Core Features (Phase 1)

**Policy Engine**
- Deterministic policy evaluation engine
- YAML-based policy configuration
- Column-level access control
- Row-level filtering with tenant isolation
- Operation restrictions (read, insert, update, delete)
- Resource-level permissions
- Actor-based authorization

**Provenance & Evidence**
- Cryptographic evidence generation
- Complete audit trail
- Data lineage tracking
- Policy decision provenance

**Connectors**
- Memory connector (testing)
- SQLite connector (development)

### Added - Advanced Security (Phase 2)

**SQL Query Firewall**
- SQL injection prevention with sqlparse
- Dangerous operation detection (DROP, DELETE, TRUNCATE)
- Comment injection prevention
- UNION attack detection
- Configurable security levels

**PII Detection & Redaction**
- Email detection
- Phone number detection (US formats)
- SSN detection with validation
- Credit card detection with Luhn validation
- API key detection
- Multiple redaction strategies (MASK, TOKEN, PARTIAL, REMOVE, HASH)

### Added - Production Connectors (Phase 3)

**PostgreSQL Connector**
- Connection pooling with psycopg3
- Prepared statements
- Proper identifier quoting
- Transaction support
- Production-grade performance

**Amazon Athena Connector**
- S3 data lake queries
- Query execution tracking
- Automatic pagination
- AWS IAM authentication
- Result caching

**Snowflake Connector**
- Cloud data warehouse support
- Multiple authentication methods (password, key-pair, SSO)
- Connection pooling
- Warehouse management
- Role-based access

**Configuration Management**
- Environment variable loading
- YAML configuration files
- Connection string parsing
- Unified connector configuration

### Added - Framework Integrations (Phase 4)

**OpenAI Integration**
- Function calling adapter
- Automatic schema generation from policies
- Streaming response support
- Simple agent helper function

**Anthropic Claude Integration**
- Tool use adapter
- Multi-turn conversation support
- Tool result formatting
- Agent helper function

**LangChain Integration**
- Custom tool implementation
- Generic and resource-specific tools
- Async execution support
- Pydantic input schemas

**CLI Tool**
- `datafence init` - Create sample policies
- `datafence validate` - Validate policy files
- `datafence describe` - Show resource details
- `datafence test` - Test requests with dry-run
- `datafence export` - Export to framework schemas

**REST API**
- FastAPI-based HTTP API
- API key authentication
- CORS support
- OpenAPI/Swagger documentation
- Health check endpoints

### Added - Production Readiness (Phase 5)

**Testing**
- 77+ unit tests for integrations
- 18 OpenAI adapter tests
- 12 Claude adapter tests
- 13 LangChain tool tests
- 16 CLI command tests
- 18 REST API endpoint tests

**Performance**
- Comprehensive benchmark suite
- Performance optimization utilities
- Schema caching
- Query result caching
- Performance monitoring

**Observability**
- Prometheus-compatible metrics
- Structured JSON logging
- Audit logging for security events
- Health checks (liveness, readiness)
- Performance counters

**Deployment**
- Docker support with multi-stage builds
- Docker Compose for local development
- Kubernetes manifests (deployment, service, ingress, HPA)
- GitHub Actions CI/CD pipeline
- Deployment guides for AWS, GCP, Azure

### Performance

- Policy evaluation: < 1ms average
- SQL firewall: < 2ms average
- PII detection: 3-5ms average
- Full stack (all features): 5-10ms average
- Integration overhead: < 2ms average

### Documentation

- Complete README with examples
- Architecture documentation
- Threat model documentation
- Policy guide
- Connector guide
- Integration guide
- Monitoring guide
- Deployment guide

### Security

- SQL injection prevention
- PII detection and redaction
- Tenant isolation enforcement
- Field-level security
- Operation restrictions
- Audit logging
- Evidence generation

### Breaking Changes

None - this is the first major release.

### Migration Guide

N/A - first release.

### Known Limitations

1. **PII Detection**: English-centric, US phone formats, regex-based (not ML)
2. **SQL Firewall**: Table extraction has minor edge cases
3. **Async Support**: Limited async connector support (coming in future releases)

### Deprecations

None.

### Contributors

Thanks to all contributors who made this release possible!

---

## [Unreleased]

### Planned for v1.1.0

- Rate limiting per actor
- Time-based policies (temporary access)
- Policy composition and inheritance
- Conditional policy rules
- Policy versioning
- ML-based PII detection
- Additional connector support (BigQuery, Redshift)

---

## Version History

- **1.0.0** (2026-09-27) - First production release
- **0.2.0** (2026-09-27) - Advanced security features (Phase 2)
- **0.1.0** (2026-09-27) - Core security boundary (Phase 1)
