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

## Threat Model B — Compromised Application Code / Malicious PolicyEngine

**Threat**: Application code or a custom ``PolicyEngine`` attempts to construct
a fake ``AuthorizedExecution`` or cause the boundary to sign an unsafe capability:
- returning RESTRICTED fields in ``allowed_fields``
- returning unknown fields not in the registry
- omitting the mandatory tenant predicate
- using a non-EQ operator on the tenant key
- injecting a cross-tenant value in the tenant predicate
- referencing RESTRICTED fields in ``enforced_filter``
- returning an excessive row limit
- returning an empty ``allowed_fields`` in an ALLOW decision

**DataFence mitigations**:
- ✅ ``AuthorizedExecution`` is frozen and deeply immutable after creation
- ✅ ``AuthorizedExecution._create_signed()`` is the only construction path
- ✅ Any field modification invalidates the HMAC signature
- ✅ The connector's ``CapabilityVerifier`` rejects a tampered capability
- ✅ ``DataFenceBoundary`` direct construction is blocked (must use ``.create()``)
- ✅ **Boundary-level decision validation** (new in hardening pass): before signing
  any capability, the boundary independently validates the ``PolicyDecision``
  against the frozen registry, regardless of which ``PolicyEngine`` produced it.
  A custom engine cannot bypass these invariants:
  1. allowed_fields must all exist in registry
  2. allowed_fields must not contain RESTRICTED fields
  3. enforced_filter fields must exist in registry
  4. enforced_filter must not reference RESTRICTED fields
  5. tenant-scoped resources must have a tenant predicate: EQ == principal.tenant_id
  6. tenant predicate operator must be EQ (not NEQ, GT, IN, etc.)
  7. decision row_limit must be positive
  8. request operation must be supported by the registry

**Residual risk**: Code with access to the signing key could construct a
valid capability. Key management is the application's responsibility.

---

## Threat Model B2 — Replay Attacks and Nonce Semantics

**Nonce design** (v0.1):

Each ``AuthorizedExecution`` carries a cryptographically random ``nonce``
(UUID hex) that is unique per issuance and included in the HMAC.

v0.1 capabilities are **bearer capabilities**: they are valid for any holder
until ``expires_at`` (default 5 minutes).  The nonce does **not** prevent
replay within the TTL window.

**What nonce provides**:
- Uniqueness: two authorizations for identical inputs produce different tokens
- Replay detection enablement: connectors can record consumed nonces to detect
  within-TTL replays
- Audit correlation: each capability event is uniquely identifiable

**What nonce does NOT provide** by itself:
- Single-use enforcement: DataFence core is stateless; it does not maintain a
  nonce store
- Cross-connector replay prevention: a token valid for ``audience="svc-a"``
  cannot be used against a connector expecting ``audience="svc-b"``, but
  within the same audience, any holder can replay it within the TTL

**Connector-side replay protection** (optional, connector responsibility):

```python
# Pseudocode — implement in your connector
class MyConnector:
    def __init__(self, ...):
        self._used_nonces: set[str] = set()   # or a Redis/DB set

    def execute(self, capability: AuthorizedExecution) -> ConnectorResult:
        self._verifier.verify(capability)      # raises on tamper/expiry/audience
        if capability.nonce in self._used_nonces:
            raise ReplayError(f\"Nonce {capability.nonce!r} already consumed\")
        self._used_nonces.add(capability.nonce)
        # ... execute ...
```

The nonce store must be scoped to the audience and purged after capability expiry
to prevent unbounded growth.

**Residual risk**: Within the TTL window (default 5 min), a captured capability
can be replayed unless the connector implements nonce tracking.

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
- ✅ Nonce provides uniqueness per issuance (unique random UUID per capability)

**Nonce semantics**: v0.1 capabilities are **bearer capabilities** — stateless and
valid until expiry.  The nonce enables audit correlation and connector-side replay
detection, but DataFence core does not maintain a nonce store.  See Threat Model B2
for the documented replay-protection interface.

**Residual risk**: Within the TTL window, a captured capability can be
replayed unless the connector implements nonce tracking.  The nonce store
is a connector responsibility — see Threat Model B2 for guidance.

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
| LLM uses unauthorized filter field | filterable_fields check at policy eval | None |
| LLM probes RESTRICTED field via filter | Registry + policy deny | None |
| Tampered capability | HMAC verification (all fields incl. roles) | Signing key compromise |
| Forged capability | HMAC verification | Signing key compromise |
| Tampered CapabilityToken | HMAC embedded in token | Signing key compromise |
| Role injection via tampered token | roles are HMAC-signed | None |
| Obligations stripped from token | obligations are HMAC-signed | None |
| Malicious custom PolicyEngine (RESTRICTED field) | Boundary-level decision validation | None |
| Malicious custom PolicyEngine (cross-tenant filter) | Boundary-level decision validation | None |
| Malicious custom PolicyEngine (missing tenant predicate) | Boundary-level decision validation | None |
| Malicious custom PolicyEngine (unknown field) | Boundary-level decision validation | None |
| Malicious custom PolicyEngine (non-EQ tenant operator) | Boundary-level decision validation | None |
| Expired capability replayed | Expiry check | Within TTL window |
| Cross-service capability use | Audience binding | None |
| Within-TTL replay | Nonce (connector must implement nonce store) | TTL window without connector nonce store |
| Schema drift | — | Registry must be kept in sync |
| Runtime process compromise | — | Out of scope |
| Policy misconfiguration | Compile-time validation; DataClassification auto-deny; tenant row rule required | Operator error |
| Missing tenant row rule | Rejected at DataFenceBoundary.create() | None |
| RESTRICTED field in output | Auto-denied regardless of policy allow_fields | None |
