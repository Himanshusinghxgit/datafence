# DataFence Security Model

## Core Security Invariant

An untrusted AI agent must never be able to cause an enterprise data connector
to execute an operation that DataFence has not explicitly authorized.

## Trust Boundaries

### Untrusted (attacker-controlled)

| Component | Notes |
|-----------|-------|
| LLM / AI agent | Intent originates here — treat all Intent fields as attacker-controlled |
| MCP tool arguments | Agent-supplied JSON — untrusted |
| HTTP request payload | Untrusted |
| `Intent.resource` | Validated against registry |
| `Intent.fields` | Validated against registry and policy |
| `Intent.filters` | Validated; policy filters take priority |
| `Intent.limit` | Capped by policy |

### Trusted

| Component | Notes |
|-----------|-------|
| Application authentication layer | Produces the Principal |
| `Actor` / `Principal` | Provided by the application, never the LLM |
| DataFence authorization boundary | `DataFenceBoundary` |
| Policy configuration | YAML or programmatic |
| Registry configuration | Must be kept in sync with the actual data source |
| HMAC signing key | Must be kept secret; never logged or exposed to the LLM |

### Partially Trusted

| Component | Notes |
|-----------|-------|
| Customer connector | Should verify the capability before executing |
| Downstream database | Protected by row/field policy, but not by DataFence itself |
| External services | Outside DataFence's scope |

---

## Security Properties

### 1. Authorization is mandatory

`DataFenceBoundary.authorize()` is the **only** path from Intent to
AuthorizedExecution. There is no `execute_raw()`, `bypass()`, or legacy path
that skips policy evaluation.

### 2. Fail-closed

Every error path results in denial, never silent allow:
- Unknown resource → deny
- Unknown field → deny
- Unsupported operation → deny
- Restricted field in filter → deny
- Malformed policy decision → `PolicyError`
- Policy evaluation exception → `PolicyError`
- Missing signing key → `ValueError`

### 3. HMAC-signed capabilities

Every `AuthorizedExecution` carries an HMAC-SHA256 signature covering all
security-relevant fields. The signature uses length-prefixed canonicalization
to prevent ambiguity attacks.

Forging or tampering with any field invalidates the signature. The customer
connector must verify the signature before executing.

### 4. Lossless predicates

Policy predicates (`amount > 1000`, `status IN ["active", "pending"]`) are
preserved with their full operator and operands through to the connector.
They are never silently coerced to equality (`amount = 1000`).

### 5. Tenant isolation

Row-level tenant filters are injected by the policy engine — the LLM cannot
override them. Even if the agent supplies `filters={"tenant_id": "other"}`,
the policy-enforced tenant filter takes priority.

### 6. Identity cannot come from the LLM

The `Actor` / `Principal` is always provided by the application's
authentication layer. DataFence never trusts an LLM to declare its own identity,
role, or tenant.

### 7. Registry immutability

The `ResourceRegistry` is frozen before the boundary is created. After freeze,
`register()` raises `RuntimeError`. New resources cannot be introduced at
runtime to bypass policy validation.

---

## Known Limitations

### Nonce / Replay

The `nonce` field makes every capability unique per issuance. However,
DataFence does not maintain nonce state. **Replay prevention** (rejecting a
previously consumed capability) is the customer connector's responsibility
and requires a nonce store.

### Schema Drift

The ResourceRegistry describes the expected schema. If the underlying
database adds or removes fields independently of the registry, DataFence
cannot detect this. The registry must be kept in sync with the data source.

### Runtime Compromise (Threat Model C)

DataFence does not protect against a full Python runtime compromise where
an attacker has code-execution access to the process. The HMAC signing key
can be extracted via Python introspection. This is explicitly out of scope.

### Transport Authentication (MCP)

The MCP server provides a `principal_resolver` hook, but the mechanism for
authenticating MCP sessions is the application's responsibility. DataFence
cannot guarantee MCP transport-level authentication is correctly implemented.

### Registry/Policy Synchronization

DataFence trusts the policy configuration as provided. If a policy allows
access to a field that should be sensitive but is misconfigured, DataFence
will authorize access. Regular policy reviews are necessary.

---

## Reporting Vulnerabilities

If you discover a security vulnerability in DataFence, please open a
GitHub issue with the label `security` or contact the maintainers directly.

Do not disclose security vulnerabilities publicly until a fix is available.
