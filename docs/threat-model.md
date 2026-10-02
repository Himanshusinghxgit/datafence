# DataFence Threat Model

## Scope

This threat model covers the DataFence authorization boundary only.
Infrastructure, LLM providers, application code outside DataFence, and the
customer's database are out of scope but noted where relevant.

---

## Threat Model A — Untrusted LLM / Agent

**Threat**: A malicious or compromised AI agent attempts to:
- Access data outside its authorization (e.g. another tenant's records)
- Access restricted fields (e.g. card numbers, SSNs)
- Perform unauthorized operations (e.g. DELETE)
- Supply forged identity (e.g. `actor.id = "admin"`)
- Inject raw SQL into a DataFence connector

**DataFence mitigations**:
- ✅ Intent is validated against ResourceRegistry (unknown resources/fields → deny)
- ✅ Policy evaluation enforces action, field, and row-level rules
- ✅ Row filters are injected by policy; the LLM cannot override them
- ✅ Principal comes from the application auth layer, not the LLM
- ✅ No connector in DataFence core accepts raw SQL from an agent
- ✅ AuthorizedExecution is HMAC-signed; a connector verifies before executing

---

## Threat Model B — Compromised Application Code

**Threat**: Application code attempts to construct a fake AuthorizedExecution
or manipulate one to bypass DataFence policy.

**DataFence mitigations**:
- ✅ `AuthorizedExecution` is a frozen dataclass — immutable after creation
- ✅ `AuthorizedExecution._create_signed()` is the only construction path
- ✅ Any field modification invalidates the HMAC signature
- ✅ The connector's `CapabilityVerifier` will reject a tampered capability
- ✅ `DataFenceBoundary` direct construction is blocked (must use `.create()`)

**Residual risk**: Code with access to the signing key could construct a
valid capability. Key management is the application's responsibility.

---

## Threat Model C — Runtime Compromise

**Threat**: An attacker has code-execution access inside the Python process
and can read memory, extract the signing key, or monkey-patch DataFence.

**DataFence position**: This is explicitly **out of scope**. No Python library
can protect against a full runtime compromise. Defense at this level requires
OS-level isolation, HSMs, or hardware security primitives.

---

## Threat Model D — Policy Misconfiguration

**Threat**: An administrator misconfigures the policy (e.g. accidentally
allows access to sensitive fields, uses an overly permissive row filter).

**DataFence mitigations**:
- ✅ DataClassification on fields (RESTRICTED fields trigger extra validation)
- ✅ Unknown operators in YAML fail-closed (no silent fallback to EQ)
- ✅ Registry/policy mismatch at boundary construction is caught

**Residual risk**: DataFence trusts the policy as written. Regular policy
reviews, least-privilege defaults, and automated policy testing are recommended.

---

## Threat Model E — Capability Replay

**Threat**: An attacker captures a valid AuthorizedExecution and replays it
later (or to a different service).

**DataFence mitigations**:
- ✅ Expiry (`expires_at`) limits the validity window (default 5 minutes)
- ✅ Audience binding prevents cross-service replay
- ✅ Nonce provides uniqueness per issuance

**Residual risk**: Within the TTL window, a captured capability can be
replayed unless the connector implements nonce tracking. Replay prevention
across requests is a connector responsibility, not a DataFence core feature.

---

## Threat Model F — Schema Drift

**Threat**: The underlying database adds a sensitive column after the
DataFence registry is configured. The registry doesn't know about it, so
policy cannot protect it.

**DataFence position**: DataFence protects only what the registry describes.
The registry must be kept in sync with the data source.

**Mitigation**: Treat registry updates as a security change requiring review.
Add CI checks that compare registry definitions against the live schema.

---

## Attack Surface Summary

| Attack Vector | DataFence Defense | Residual Risk |
|---------------|------------------|---------------|
| LLM supplies own identity | Principal from app auth only | None in normal deployment |
| LLM requests unauthorized field | Registry + policy deny | None |
| LLM requests unauthorized tenant data | Policy-injected row filter | None |
| LLM supplies raw SQL | No raw SQL path exists | None |
| Tampered capability | HMAC verification | Signing key compromise |
| Forged capability | HMAC verification | Signing key compromise |
| Expired capability replayed | Expiry check | Within TTL window |
| Cross-service capability use | Audience binding | None |
| Within-TTL replay | — | Nonce store (connector responsibility) |
| Schema drift | — | Registry must be kept in sync |
| Runtime process compromise | — | Out of scope |
| Policy misconfiguration | DataClassification, unknown-op fail-closed | Operator error |
