# Deployment Guide

DataFence is an **authorization library**, not an execution engine.
Deploying DataFence means deploying *your application* that uses DataFence
to authorize AI agent data access requests before passing signed capabilities
to your own data connectors.

---

## What DataFence provides

- `DataFenceBoundary.authorize(principal, intent)` → `AuthorizedExecution`
- `CapabilityToken.encode(capability)` → portable signed token
- `CapabilityVerifier.verify_token(token)` → verified capability
- Optional REST API adapter (`datafence[api]`) via FastAPI

## What you supply

- Your authentication layer (resolves Bearer tokens → `Principal`)
- Your registry (what resources exist)
- Your policy (who can access what)
- Your connector (executes the signed capability against your data source)
- Your signing key (store in a secrets manager, not environment variables in production)

---

## Docker

### Build

```bash
docker build -t my-datafence-api:0.1.0 .
```

### Application entrypoint

Create an application module that wires your boundary:

```python
# my_app/main.py
from secrets import token_bytes
from datafence import DataFenceBoundary, DataFencePolicyEngine, YAMLPolicyLoader
from datafence.api import create_api
from datafence.core.principal import Principal
from datafence.core.registry import ResourceRegistry

registry = ResourceRegistry()
# ... register your resources ...

policy = YAMLPolicyLoader.load("/app/policies/policy.yaml")
engine = DataFencePolicyEngine(policy, registry=registry)

signing_key = load_key_from_secrets_manager()   # your responsibility
boundary = DataFenceBoundary.create(engine, registry, signing_key,
                                    capability_audience="my-service")

def my_resolver(credentials) -> Principal:
    user = verify_token(credentials.credentials)   # your auth system
    return Principal(id=f"user:{user.id}", tenant_id=user.tenant_id)

app = create_api(boundary, principal_resolver=my_resolver)
```

```bash
docker run -d \
  -p 8000:8000 \
  -v $(pwd)/policies:/app/policies:ro \
  --name my-datafence-api \
  my-datafence-api:0.1.0 \
  uvicorn my_app.main:app --host 0.0.0.0 --port 8000
```

---

## Kubernetes

```bash
kubectl create namespace datafence
kubectl apply -f kubernetes/ -n datafence
```

See `kubernetes/` for manifests. Override the Deployment `CMD` with your
application server entrypoint.

---

## Signing key management

The signing key is an HMAC-SHA256 shared secret (minimum 32 bytes).
Any holder of the key can both sign and verify capabilities.

**Recommended:**
- Generate with `python -c "import secrets; print(secrets.token_hex(32))"`
- Store in your secrets manager (AWS Secrets Manager, GCP Secret Manager, Vault)
- Load at startup — never hardcode or commit it
- Rotate periodically — update both the boundary and all connectors simultaneously

---

## REST API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check |
| `/authorize` | POST | Authorize an intent; returns signed CapabilityToken |
| `/describe/{resource}` | GET | Resource schema |
| `/policy` | GET | Policy name, version, resource count |

The `/authorize` response includes a `token` field — the portable signed
`CapabilityToken` that your connector uses:

```json
{
  "status": "authorized",
  "token": "{\"dfv\":1,\"execution_id\":\"exec_...\",\"sig\":\"...\"}",
  "execution_id": "exec_...",
  "resource": "orders",
  "fields": ["id", "total"],
  "predicates": [{"field": "tenant_id", "operator": "=", "value": "acme"}],
  "limit": 10
}
```

Your connector verifies the token:

```python
from datafence.core.capability import CapabilityVerifier

verifier = CapabilityVerifier(signing_key, expected_audience="my-service")
capability = verifier.verify_token(response["token"])
result = my_connector.execute(capability)
```

---

## Security checklist

- [ ] Signing key from secrets manager (not environment or code)
- [ ] Bearer token validation in `principal_resolver`
- [ ] CORS restricted to known origins
- [ ] Non-root container user
- [ ] Read-only root filesystem
- [ ] TLS termination at load balancer or ingress
- [ ] Policy reviewed and tested before deployment
- [ ] Connector verifies capability signature before executing
