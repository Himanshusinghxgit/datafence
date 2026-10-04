# Monitoring Guide

## What DataFence exposes

DataFence is an authorization library, not an execution engine.
It does not ship a monitoring framework, metrics collector, or Prometheus
exporter.  Observability is implemented by the **host application**, which
has full control over the transport, logging infrastructure, and metrics
stack.

What DataFence provides that you can observe:

| Observable | How to access it |
|---|---|
| Authorization decision (allow/deny) | The return value / exception of `boundary.authorize()` |
| Denial reasons | `PolicyDeniedError.args[0]` |
| Capability metadata | Fields on `AuthorizedExecution` |
| Execution ID | `capability.execution_id` (unique per authorization event) |
| Principal + tenant | `capability.actor.id`, `capability.actor.tenant_id` |
| Authorized fields | `capability.selected_fields` |
| Enforced predicates | `capability.filter_constraints()` |
| Policy version | `capability.policy_version` |
| Expiry | `capability.expires_at` |
| Audience | `capability.audience` |

---

## Structured audit logging

Wrap `boundary.authorize()` in your application's logging layer:

```python
import logging
import time
from datafence import DataFenceBoundary, Principal, Intent, Operation
from datafence.errors import PolicyDeniedError

logger = logging.getLogger("datafence.audit")

def authorized_query(boundary: DataFenceBoundary,
                     principal: Principal,
                     intent: Intent) -> "AuthorizedExecution":
    start = time.monotonic()
    try:
        capability = boundary.authorize(principal, intent)
        logger.info(
            "authorization.allowed",
            extra={
                "execution_id":   capability.execution_id,
                "actor_id":       capability.actor.id,
                "tenant_id":      capability.actor.tenant_id,
                "resource":       capability.resource,
                "operation":      capability.operation.value,
                "fields":         capability.selected_fields,
                "policy_version": capability.policy_version,
                "duration_ms":    round((time.monotonic() - start) * 1000, 2),
            },
        )
        return capability
    except PolicyDeniedError as exc:
        logger.warning(
            "authorization.denied",
            extra={
                "actor_id":   principal.id,
                "tenant_id":  principal.tenant_id,
                "resource":   intent.resource,
                "operation":  intent.operation.value,
                "reasons":    str(exc),
                "duration_ms": round((time.monotonic() - start) * 1000, 2),
            },
        )
        raise
```

Output (JSON formatter configured separately):

```json
{
  "event": "authorization.allowed",
  "execution_id": "exec_a1b2c3d4",
  "actor_id": "user:alice",
  "tenant_id": "tenant-acme",
  "resource": "orders",
  "operation": "read",
  "fields": ["id", "total", "status"],
  "policy_version": "orders-v1 / 1.0",
  "duration_ms": 1.3
}
```

---

## Metrics

DataFence does not instrument itself.  Add counters in your wrapper:

```python
# Pseudocode — use your preferred metrics library (Prometheus, StatsD, etc.)

from prometheus_client import Counter, Histogram

ALLOW = Counter("datafence_authorizations_allowed_total",
                "Authorizations granted", ["resource", "tenant"])
DENY  = Counter("datafence_authorizations_denied_total",
                "Authorizations denied",  ["resource", "tenant"])
LATENCY = Histogram("datafence_authorization_duration_seconds",
                    "Authorization latency", ["resource"])

def authorized_query(boundary, principal, intent):
    with LATENCY.labels(resource=intent.resource).time():
        try:
            cap = boundary.authorize(principal, intent)
            ALLOW.labels(resource=intent.resource,
                         tenant=principal.tenant_id).inc()
            return cap
        except PolicyDeniedError:
            DENY.labels(resource=intent.resource,
                        tenant=principal.tenant_id).inc()
            raise
```

---

## Health checks

DataFence has no runtime state to health-check beyond the boundary being
instantiated.  A simple liveness check for a service embedding DataFence:

```python
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health() -> dict:
    return {"status": "ok"}

@app.get("/ready")
def ready(boundary: DataFenceBoundary = Depends(get_boundary)) -> dict:
    # If boundary.registry is frozen and accessible, DataFence is ready.
    return {
        "ready": boundary.registry.is_frozen,
        "resources": list(boundary.registry.resources.keys()),
    }
```

---

## Audit trail recommendations

Each `AuthorizedExecution` is cryptographically unique (HMAC + nonce).
Store `execution_id` in your audit log when the connector executes it.
This creates an end-to-end trace:

```
authorization event  →  execution_id  →  connector execution log
```

Fields to capture per authorization event:

- `execution_id` — correlates authorization to connector execution
- `actor_id`, `tenant_id` — who authorized
- `resource`, `operation` — what was requested
- `selected_fields` — what fields were permitted
- `predicates` — what row-level filters were enforced
- `policy_version` — which policy version made the decision
- `expires_at` — when the capability expires
- `timestamp` (your system clock) — when the event occurred

---

## Alerting recommendations

Since you own the metrics layer, alert on patterns relevant to your
organization.  Common signals:

| Signal | Metric to watch |
|---|---|
| Sudden spike in denials for a tenant | `datafence_authorizations_denied_total{tenant="..."}` |
| Requests for restricted fields | Log `reasons` containing `"denied_fields"` |
| Unusual operation types | Filter on `operation=delete` or `insert` |
| High authorization latency | p95 of `datafence_authorization_duration_seconds` |
| Expired capabilities rejected by connector | Connector-side metric |

---

## Further reading

- [Architecture](architecture.md) — security model and trust boundaries
- [Threat Model](threat-model.md) — attack surface and residual risks
- [Connector Guide](connectors.md) — connector-side verification and execution
