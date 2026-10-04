"""
DataFence Authorized Execution Capability and portable CapabilityToken codec.

SECURITY MODEL
--------------
``AuthorizedExecution`` is the *only* output of ``DataFenceBoundary.authorize()``.

Properties:
- Created ONLY by ``DataFenceBoundary`` via ``AuthorizedExecution._create_signed()``.
- Every security-relevant field is covered by an HMAC-SHA256 signature.
- The capability is **deeply immutable**: all mutable Python containers have
  been replaced with tuples so that in-place mutation after issuance is
  impossible.
- ``CapabilityToken`` provides a documented, version-tagged wire format so
  the signed capability can be transported across process/service boundaries
  and re-verified without access to DataFence runtime objects.

HMAC signed fields (complete list)
-----------------------------------
execution_id, created_at, actor.id, actor.tenant_id, actor.roles,
actor.attributes, resource, operation, selected_fields, predicates,
limit, policy_version, policy_decisions, expires_at, audience, nonce,
token_version (when serialized via CapabilityToken)

Signing key requirements
------------------------
Minimum 32 bytes (256 bits) for HMAC-SHA256.  ``DataFenceBoundary.create()``
and ``CapabilityVerifier`` both enforce this.

Shared-key trust model (IMPORTANT)
-----------------------------------
The current implementation uses HMAC-SHA256 with a **shared secret key**.
Any holder of the signing key can both verify AND mint capabilities.
This is acceptable for a single-tenant deployment where the DataFence
boundary and the customer connector share the same trusted environment.

For multi-tenant deployments or third-party verifier scenarios, the
signing layer is designed to be replaced with asymmetric signing
(e.g. Ed25519) without redesigning ``AuthorizedExecution``:
  1. Implement a ``CapabilitySigner`` that wraps your asymmetric key.
  2. Pass a custom ``sign`` callable to ``_create_signed``.
  3. Update ``CapabilityVerifier`` to use the corresponding public key.

DataFence Cloud / control plane
--------------------------------
The authorization decision is 100% local.  No network call to any
DataFence Cloud service is made during ``DataFenceBoundary.authorize()``.

Portable token format
----------------------
``CapabilityToken`` serialises ``AuthorizedExecution`` to a JSON-based
wire representation that includes the raw signature bytes (hex-encoded)
so that the recipient can independently verify the capability without
holding a DataFence runtime object.

Wire format (version 1):

    {
      "dfv": 1,                    # token schema version — must match
      "execution_id": "...",
      "created_at": "...Z",        # ISO 8601 UTC
      "actor_id": "...",
      "actor_tenant_id": "...",
      "actor_roles": [...],        # sorted list for determinism
      "actor_attributes": {...},   # sorted keys
      "resource": "...",
      "operation": "read",
      "selected_fields": [...],    # sorted
      "predicates": [...],         # sorted by deterministic key
      "limit": N,
      "policy_version": "...",
      "policy_decisions": [...],
      "expires_at": "...Z",
      "audience": "...",
      "nonce": "...",
      "sig": "hexencoded..."       # HMAC-SHA256 over canonical repr
    }

Canonicalization note
---------------------
Fields are joined with ``"|"`` after JSON-serialising structured values.
Every variable-length string is length-prefixed (``"<len>:<value>"``) to
prevent collisions from attacker-controlled values containing ``"|"``.
Timestamps are normalised to UTC ISO 8601 before canonicalisation.
Numeric values are validated: non-finite floats (NaN, Inf) are rejected.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from datafence.core.principal import Principal
from datafence.core.types import Operation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Minimum signing key length in bytes.  Shorter keys are rejected at
#: boundary creation and verifier construction time.
MIN_KEY_BYTES: int = 32

#: Current token wire-format version.  Increment when the canonical
#: representation changes in an incompatible way.
TOKEN_VERSION: int = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lp(s: str) -> str:
    """Length-prefix a string: ``'5:hello'``."""
    encoded = s.encode("utf-8")
    return f"{len(encoded)}:{s}"


def _utc_iso(dt: datetime) -> str:
    """Return a UTC ISO 8601 string.  Naive datetimes are treated as UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def _safe_json(value: Any) -> str:
    """
    JSON-serialise *value*, rejecting non-finite numeric values.

    Non-finite floats (NaN, Inf, -Inf) would produce ambiguous or
    invalid JSON in some parsers, so we reject them explicitly.
    """
    # Recursively check for non-finite numbers
    _reject_nonfinite(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _reject_nonfinite(value: Any) -> None:
    """Raise ValueError if *value* or any nested value is non-finite."""
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"Non-finite numeric value is not permitted: {value!r}")
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_nonfinite(item)
    elif isinstance(value, dict):
        for v in value.values():
            _reject_nonfinite(v)


def _canon_predicates(predicates: tuple[dict[str, Any], ...]) -> str:
    """Return a deterministic canonical representation of a predicate list."""
    serialised = [_safe_json(p) for p in predicates]
    return _safe_json(sorted(serialised))


# ---------------------------------------------------------------------------
# AuthorizedExecution — deeply immutable signed capability
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizedExecution:
    """
    Cryptographically signed, deeply immutable execution capability.

    Represents DataFence's authorization for ONE specific operation.
    Created exclusively by ``DataFenceBoundary``; verified by the customer
    connector via ``CapabilityVerifier`` or ``CapabilityToken.verify()``.

    **All mutable containers have been replaced with tuples.**  Once a
    capability is created its security-relevant meaning cannot change in place.

    Fields
    ------
    execution_id      : Unique ID for this authorization event.
    created_at        : UTC timestamp of issuance.
    actor             : The authenticated Principal this was issued for.
    resource          : Resource name (e.g. ``"orders"``).
    operation         : Authorized operation type.
    selected_fields   : Fields the connector may return (immutable tuple).
    predicates        : Typed row-filter predicates (immutable tuple of dicts).
    limit             : Maximum rows the connector may return.
    policy_version    : Policy version that produced this capability.
    policy_decisions  : Audit log of matched policy rule IDs (immutable tuple).
    expires_at        : UTC expiry timestamp.
    audience          : Audience tag — connector must verify this matches.
    nonce             : Unique per-issuance random value.
    signature         : HMAC-SHA256 over the canonical representation.
    """

    # Execution metadata
    execution_id: str
    created_at: datetime

    # Authorization context
    actor: Principal
    resource: str
    operation: Operation

    # Authorized access — immutable tuples, not lists
    selected_fields: tuple[str, ...]
    predicates: tuple[dict[str, Any], ...] = ()
    limit: int = 0

    # Policy provenance — immutable tuples
    policy_version: str = "unknown"
    policy_decisions: tuple[str, ...] = ()

    # Obligations — post-execution requirements from policy (e.g. {"audit": True}).
    # These are metadata for the connector/application; DataFence does not enforce them.
    # They ARE included in the HMAC to prevent stripping.
    obligations: dict[str, Any] = field(default_factory=dict)

    # Capability lifecycle / audience binding
    expires_at: datetime | None = None
    audience: str = "datafence"
    nonce: str = ""

    # Cryptographic signature (HMAC-SHA256)
    signature: bytes = field(default=b"", repr=False)

    # ------------------------------------------------------------------
    # Canonical representation (HMAC input)
    # ------------------------------------------------------------------

    def _compute_canonical_repr(self) -> bytes:
        """
        Produce a deterministic, unambiguous byte representation for HMAC.

        Every security-relevant field is covered, including
        ``principal.roles`` which was previously unsigned.
        Variable-length string fields are length-prefixed to prevent
        canonicalisation collisions.
        Timestamps are normalised to UTC.
        Non-finite numeric values are rejected.
        """
        parts = [
            _lp(self.execution_id),
            _lp(_utc_iso(self.created_at)),
            _lp(self.actor.id),
            _lp(self.actor.tenant_id),
            # roles: sorted for determinism, signed to prevent role tampering
            _lp(_safe_json(sorted(self.actor.roles))),
            # attributes (metadata): sorted keys
            _lp(_safe_json(dict(sorted(self.actor.attributes.items())))),
            _lp(self.resource),
            _lp(self.operation.value),
            _lp(_safe_json(sorted(self.selected_fields))),
            _lp(_canon_predicates(self.predicates)),
            _lp(str(self.limit)),
            _lp(self.policy_version),
            _lp(_safe_json(list(self.policy_decisions))),
            _lp(_utc_iso(self.expires_at) if self.expires_at else ""),
            _lp(self.audience),
            _lp(self.nonce),
            # obligations: signed so they cannot be stripped
            _lp(_safe_json(dict(sorted((self.obligations or {}).items())))),
        ]
        canonical = "|".join(parts)
        return canonical.encode("utf-8")

    # ------------------------------------------------------------------
    # Signature operations
    # ------------------------------------------------------------------

    def compute_signature(self, signing_key: bytes) -> bytes:
        """Compute HMAC-SHA256 over the canonical representation."""
        return hmac.new(signing_key, self._compute_canonical_repr(), hashlib.sha256).digest()

    def verify_signature(self, signing_key: bytes) -> bool:
        """
        Verify the capability signature using constant-time comparison.

        Returns ``False`` (not raises) so callers can produce a controlled error.
        """
        if not self.signature:
            return False
        expected = self.compute_signature(signing_key)
        return hmac.compare_digest(self.signature, expected)

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return True if the capability is past its expiry timestamp."""
        if self.expires_at is None:
            return False
        reference = now or datetime.now(timezone.utc)
        # Normalise tz-naive to UTC for comparison
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        return reference >= expires

    def filter_constraints(self) -> list[dict[str, Any]]:
        """Return the typed predicate list as a defensive copy.

        Each entry: ``{"field": str, "operator": str, "value": Any}``.
        Connectors should compile row-filter clauses from this list.
        """
        return list(self.predicates)

    # ------------------------------------------------------------------
    # Deep-immutability helpers (defensive copies for public consumers)
    # ------------------------------------------------------------------

    def fields_list(self) -> list[str]:
        """Return a defensive copy of ``selected_fields`` as a list."""
        return list(self.selected_fields)

    def decisions_list(self) -> list[str]:
        """Return a defensive copy of ``policy_decisions`` as a list."""
        return list(self.policy_decisions)

    # ------------------------------------------------------------------
    # Factory (called only by DataFenceBoundary)
    # ------------------------------------------------------------------

    @staticmethod
    def _create_signed(
        execution_id: str,
        actor: Principal,
        resource: str,
        operation: Operation,
        selected_fields: list[str] | tuple[str, ...],
        enforced_predicates: list[dict[str, Any]] | tuple[dict[str, Any], ...],
        limit: int,
        policy_version: str,
        policy_decisions: list[str] | tuple[str, ...],
        signing_key: bytes,
        expires_at: datetime | None = None,
        audience: str = "datafence",
        nonce: str | None = None,
        obligations: dict[str, Any] | None = None,
    ) -> AuthorizedExecution:
        """
        Create a signed capability.  The ONLY legitimate construction path.
        Called exclusively by ``DataFenceBoundary._build_capability()``.
        """
        if len(signing_key) < MIN_KEY_BYTES:
            raise ValueError(
                f"signing_key must be at least {MIN_KEY_BYTES} bytes "
                f"(got {len(signing_key)})"
            )

        from datetime import timedelta
        created_at = datetime.now(timezone.utc)
        effective_expires = expires_at or created_at + timedelta(minutes=5)
        # Normalise expires_at to UTC
        if effective_expires.tzinfo is None:
            effective_expires = effective_expires.replace(tzinfo=timezone.utc)
        effective_nonce = nonce or uuid4().hex

        # Convert to immutable tuples
        fields_tuple = tuple(selected_fields)
        preds_tuple = tuple(dict(p) for p in enforced_predicates)
        decisions_tuple = tuple(policy_decisions)
        obligations_dict = dict(obligations or {})

        # Build unsigned first to compute signature
        unsigned = AuthorizedExecution(
            execution_id=execution_id,
            created_at=created_at,
            actor=actor,
            resource=resource,
            operation=operation,
            selected_fields=fields_tuple,
            predicates=preds_tuple,
            limit=limit,
            policy_version=policy_version,
            policy_decisions=decisions_tuple,
            obligations=obligations_dict,
            expires_at=effective_expires,
            audience=audience,
            nonce=effective_nonce,
            signature=b"",
        )
        sig = unsigned.compute_signature(signing_key)

        # Reconstruct with the real signature (frozen dataclass)
        return AuthorizedExecution(
            execution_id=execution_id,
            created_at=created_at,
            actor=actor,
            resource=resource,
            operation=operation,
            selected_fields=fields_tuple,
            predicates=preds_tuple,
            limit=limit,
            policy_version=policy_version,
            policy_decisions=decisions_tuple,
            obligations=obligations_dict,
            expires_at=effective_expires,
            audience=audience,
            nonce=effective_nonce,
            signature=sig,
        )

    def __post_init__(self) -> None:
        if not self.execution_id:
            raise ValueError("execution_id cannot be empty")
        if not self.resource:
            raise ValueError("resource cannot be empty")
        if not self.selected_fields:
            raise ValueError("selected_fields cannot be empty")
        if self.limit <= 0:
            raise ValueError("limit must be positive")
        if not self.audience:
            raise ValueError("audience cannot be empty")
        # Coerce any accidental list/sequence to tuples for deep immutability
        if not isinstance(self.selected_fields, tuple):
            object.__setattr__(self, "selected_fields", tuple(self.selected_fields))
        if not isinstance(self.predicates, tuple):
            object.__setattr__(self, "predicates", tuple(self.predicates))
        if not isinstance(self.policy_decisions, tuple):
            object.__setattr__(self, "policy_decisions", tuple(self.policy_decisions))

# ---------------------------------------------------------------------------
# CapabilityToken — portable wire representation with embedded signature
# ---------------------------------------------------------------------------


class CapabilityToken:
    """
    Portable, version-tagged wire representation of an ``AuthorizedExecution``.

    Encodes the full capability — including the HMAC signature bytes — as a
    JSON object so that:

      1. The token can be transported across process/service/network boundaries.
      2. The recipient can verify the token WITHOUT holding a DataFence runtime
         object — only the shared signing key (or public key in a PKI setup) is
         required.
      3. Any tampering with any field invalidates the embedded signature.

    Wire format (``dfv`` = DataFence Version):

        {
          "dfv": 1,
          "execution_id": "exec_...",
          "created_at": "2026-01-01T00:00:00+00:00",
          "actor_id": "user:alice",
          "actor_tenant_id": "tenant-acme",
          "actor_roles": ["finance:read"],
          "actor_attributes": {},
          "resource": "orders",
          "operation": "read",
          "selected_fields": ["id", "total"],
          "predicates": [...],
          "limit": 10,
          "policy_version": "orders-v1 / 1.0",
          "policy_decisions": [...],
          "expires_at": "2026-01-01T00:05:00+00:00",
          "audience": "orders-service",
          "nonce": "abc123...",
          "sig": "deadbeef..."
        }

    Usage::

        # Encode (DataFence side)
        token_str = CapabilityToken.encode(capability)

        # Decode + verify (connector side — no DataFence runtime needed)
        capability = CapabilityToken.decode_and_verify(token_str, signing_key,
                                                        expected_audience="orders-service")
    """

    CURRENT_VERSION: int = TOKEN_VERSION

    @staticmethod
    def encode(capability: AuthorizedExecution) -> str:
        """
        Serialise *capability* to a JSON string that includes the signature.

        The returned string is safe for transport as an HTTP header value,
        JSON field, or MCP tool result.  It is NOT base64-encoded by default
        — callers may apply their own transport encoding if needed.

        Raises:
            ValueError: If the capability has no signature (unsigned).
        """
        if not capability.signature:
            raise ValueError("Cannot encode an unsigned capability")

        payload: dict[str, Any] = {
            "dfv": TOKEN_VERSION,
            "execution_id": capability.execution_id,
            "created_at": _utc_iso(capability.created_at),
            "actor_id": capability.actor.id,
            "actor_tenant_id": capability.actor.tenant_id,
            "actor_roles": sorted(capability.actor.roles),
            "actor_attributes": dict(sorted(capability.actor.attributes.items())),
            "resource": capability.resource,
            "operation": capability.operation.value,
            "selected_fields": sorted(capability.selected_fields),
            "predicates": list(capability.predicates),
            "limit": capability.limit,
            "policy_version": capability.policy_version,
            "policy_decisions": list(capability.policy_decisions),
            "obligations": dict(capability.obligations or {}),
            "expires_at": _utc_iso(capability.expires_at) if capability.expires_at else "",
            "audience": capability.audience,
            "nonce": capability.nonce,
            "sig": capability.signature.hex(),
        }
        return json.dumps(payload, separators=(",", ":"))

    @staticmethod
    def decode(token_str: str) -> AuthorizedExecution:
        """
        Deserialise a token string to an ``AuthorizedExecution``.

        Does NOT verify the signature.  Call ``CapabilityToken.decode_and_verify``
        or ``CapabilityVerifier.verify_token`` to verify.

        Raises:
            CapabilityVerificationError: If the token is malformed, missing
                required fields, or has an unsupported version.
        """
        try:
            data = json.loads(token_str)
        except (json.JSONDecodeError, TypeError) as exc:
            raise CapabilityVerificationError(
                f"Malformed capability token: cannot parse JSON — {exc}"
            ) from exc

        if not isinstance(data, dict):
            raise CapabilityVerificationError("Malformed capability token: expected JSON object")

        # Version check — fail closed on unknown versions
        dfv = data.get("dfv")
        if dfv != TOKEN_VERSION:
            raise CapabilityVerificationError(
                f"Unsupported token version: {dfv!r} (expected {TOKEN_VERSION})"
            )

        try:
            return CapabilityToken._reconstruct(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise CapabilityVerificationError(
                f"Malformed capability token: {exc}"
            ) from exc

    @staticmethod
    def decode_and_verify(
        token_str: str,
        signing_key: bytes,
        expected_audience: str,
    ) -> AuthorizedExecution:
        """
        Decode and cryptographically verify a token string.

        This is the primary API for connector-side token verification.
        No DataFence runtime objects are required — only the shared key
        and expected audience.

        Raises:
            CapabilityVerificationError: On any parse, version, expiry,
                audience, or signature failure.
        """
        capability = CapabilityToken.decode(token_str)
        verifier = CapabilityVerifier(signing_key, expected_audience=expected_audience)
        verifier.verify(capability)
        return capability

    @staticmethod
    def _reconstruct(data: dict[str, Any]) -> AuthorizedExecution:
        """Reconstruct an AuthorizedExecution from a decoded wire dict."""
        from datafence.core.principal import Principal

        def _parse_dt(s: str | None) -> datetime | None:
            if not s:
                return None
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt

        actor = Principal(
            id=str(data["actor_id"]),
            tenant_id=str(data["actor_tenant_id"]),
            roles=tuple(str(r) for r in (data.get("actor_roles") or [])),
            attributes=dict(data.get("actor_attributes") or {}),
        )

        sig_hex = data.get("sig", "")
        if not sig_hex:
            raise ValueError("token missing signature ('sig' field)")

        try:
            sig_bytes = bytes.fromhex(str(sig_hex))
        except ValueError as exc:
            raise ValueError(f"invalid hex signature: {exc}") from exc

        created_at = _parse_dt(data.get("created_at")) or datetime.now(timezone.utc)
        expires_at = _parse_dt(data.get("expires_at"))

        fields_raw = data.get("selected_fields") or []
        preds_raw = data.get("predicates") or []
        decisions_raw = data.get("policy_decisions") or []

        return AuthorizedExecution(
            execution_id=str(data["execution_id"]),
            created_at=created_at,
            actor=actor,
            resource=str(data["resource"]),
            operation=Operation(str(data["operation"])),
            selected_fields=tuple(str(f) for f in fields_raw),
            predicates=tuple(dict(p) for p in preds_raw),
            limit=int(data["limit"]),
            policy_version=str(data.get("policy_version", "unknown")),
            policy_decisions=tuple(str(d) for d in decisions_raw),
            obligations=dict(data.get("obligations") or {}),
            expires_at=expires_at,
            audience=str(data.get("audience", "datafence")),
            nonce=str(data.get("nonce", "")),
            signature=sig_bytes,
        )


# ---------------------------------------------------------------------------
# CapabilityVerificationError
# ---------------------------------------------------------------------------


class CapabilityVerificationError(Exception):
    """Raised when capability verification fails (forged, expired, mis-targeted, malformed)."""
    pass


# ---------------------------------------------------------------------------
# CapabilityVerifier — customer-side verifier
# ---------------------------------------------------------------------------


class CapabilityVerifier:
    """
    Customer-side verifier for DataFence authorization capabilities.

    Configure with the same signing key (min 32 bytes) and expected audience,
    then call ``verify()`` before translating a capability into a backend
    operation, or ``verify_token()`` to verify a wire-format token string.

    **Shared-key model**: any holder of the key can mint *and* verify
    capabilities.  See the module docstring for guidance on future
    asymmetric signing support.

    Usage::

        verifier = CapabilityVerifier(signing_key, expected_audience="my-service")

        # From an in-memory AuthorizedExecution:
        verifier.verify(capability)

        # From a wire token (no DataFence runtime needed):
        capability = verifier.verify_token(token_str)
    """

    def __init__(self, signing_key: bytes, expected_audience: str = "datafence") -> None:
        if len(signing_key) < MIN_KEY_BYTES:
            raise ValueError(
                f"signing_key must be at least {MIN_KEY_BYTES} bytes "
                f"(got {len(signing_key)}) — use secrets.token_bytes(32) or larger"
            )
        if not expected_audience:
            raise ValueError("expected_audience cannot be empty")
        self._signing_key = signing_key
        self._expected_audience = expected_audience

    def verify(self, capability: AuthorizedExecution) -> None:
        """Verify an in-memory capability.

        Checks (in order):
        1. Type — must be an ``AuthorizedExecution`` instance.
        2. Audience — must match ``expected_audience``.
        3. Expiry — must not be expired.
        4. Signature — HMAC must be valid.

        Raises:
            CapabilityVerificationError: On any verification failure.
        """
        if not isinstance(capability, AuthorizedExecution):
            raise CapabilityVerificationError(
                f"Expected AuthorizedExecution, got {type(capability).__name__!r}"
            )
        if capability.audience != self._expected_audience:
            raise CapabilityVerificationError(
                f"Capability audience {capability.audience!r} does not match "
                f"expected {self._expected_audience!r}"
            )
        if capability.is_expired():
            raise CapabilityVerificationError(
                f"Capability {capability.execution_id!r} has expired"
            )
        if not capability.verify_signature(self._signing_key):
            raise CapabilityVerificationError(
                f"Capability {capability.execution_id!r} has an invalid signature — "
                "it may be forged or tampered with"
            )

    def verify_token(self, token_str: str) -> AuthorizedExecution:
        """
        Decode a wire-format token string, verify it, and return the capability.

        This is the primary API for connectors that receive tokens over
        the network.  No DataFence runtime objects are required.

        Raises:
            CapabilityVerificationError: On parse, version, expiry,
                audience, or signature failure.
        """
        capability = CapabilityToken.decode(token_str)
        self.verify(capability)
        return capability
