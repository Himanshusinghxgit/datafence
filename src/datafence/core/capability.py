"""
DataFence Authorized Execution Capability.

SECURITY MODEL
--------------
AuthorizedExecution is the *only* output of DataFenceBoundary.authorize().

Properties:
- Created ONLY by DataFenceBoundary via AuthorizedExecution._create_signed().
- Each capability carries an HMAC-SHA256 signature covering ALL fields.
- Connector verifies signature before translating the capability to a DB call.
- Capability is immutable (frozen dataclass) — cannot be altered after issuance.

What this prevents:
- Capability forgery (attacker cannot create a valid HMAC without the key).
- Capability tampering (any field change invalidates the signature).
- Bypass attacks (connector must call verify() before execution).
- Audience confusion (capability is bound to a specific audience tag).
- Replay within the TTL window (nonce provides uniqueness per issuance).

What this does NOT prevent:
- Full Python runtime compromise (Threat Model C) — the signing key can be
  extracted via Python introspection. This is explicitly out of scope.
- Replay attacks after the TTL window if the connector does not store nonces.
  Replay protection requires the connector to record consumed nonces.
  This is documented as a limitation; nonces provide uniqueness, not replay
  prevention on their own.

Canonicalization note
---------------------
Fields are joined with "|" after JSON-serializing structured values.
Actor-controlled strings (actor.id, tenant_id, resource) could in principle
contain "|" characters, creating ambiguity.  To prevent this, every
variable-length field is length-prefixed: "<len>:<value>" before joining.
This ensures the canonical representation is unambiguous regardless of
field content.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from datafence.core.types import Actor, Operation


def _lp(s: str) -> str:
    """Length-prefix a string: '5:hello'."""
    encoded = s.encode("utf-8")
    return f"{len(encoded)}:{s}"


@dataclass(frozen=True)
class AuthorizedExecution:
    """
    Cryptographically signed execution capability.

    Represents DataFence's authorization for ONE specific operation.
    Created exclusively by DataFenceBoundary; verified by the customer connector.

    The customer connector MUST call CapabilityVerifier.verify() before
    translating this capability into any backend operation.
    """

    # Execution metadata
    execution_id: str
    created_at: datetime

    # Authorization context
    actor: Actor
    resource: str
    operation: Operation

    # Authorized access (what the connector may execute)
    selected_fields: list[str]
    enforced_filters: dict[str, Any]   # legacy EQ-only view; use enforced_predicates
    limit: int

    # Typed, lossless predicate list (full operator + value preserved)
    enforced_predicates: list[dict[str, Any]] = field(default_factory=list)

    # Policy provenance
    policy_version: str = "unknown"
    policy_decisions: list[str] = field(default_factory=list)

    # Capability lifecycle / audience binding
    expires_at: datetime | None = None
    audience: str = "datafence"
    nonce: str = ""

    # Cryptographic signature (HMAC-SHA256)
    signature: bytes = field(default=b"", repr=False)

    # ------------------------------------------------------------------
    # Canonical representation
    # ------------------------------------------------------------------

    def _compute_canonical_repr(self) -> bytes:
        """
        Produce a deterministic, unambiguous byte representation for HMAC.

        Every security-relevant field is covered.
        Variable-length string fields are length-prefixed to prevent
        canonicalization collisions caused by attacker-controlled values
        that happen to contain the separator character.
        """
        parts = [
            _lp(self.execution_id),
            _lp(self.created_at.isoformat()),
            _lp(self.actor.id),
            _lp(self.actor.tenant_id),
            _lp(json.dumps(self.actor.metadata, sort_keys=True, separators=(",", ":"))),
            _lp(self.resource),
            _lp(self.operation.value),
            _lp(json.dumps(sorted(self.selected_fields), separators=(",", ":"))),
            _lp(json.dumps(self.enforced_filters, sort_keys=True, separators=(",", ":"))),
            _lp(
                json.dumps(
                    sorted(self.enforced_predicates, key=lambda p: json.dumps(p, sort_keys=True)),
                    separators=(",", ":"),
                )
            ),
            _lp(str(self.limit)),
            _lp(self.policy_version),
            _lp(json.dumps(self.policy_decisions, separators=(",", ":"))),
            _lp(self.expires_at.isoformat() if self.expires_at else ""),
            _lp(self.audience),
            _lp(self.nonce),
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

        Returns False (not raises) so callers can produce a controlled error.
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
        # Handle both tz-aware and tz-naive expires_at (legacy data)
        if self.expires_at.tzinfo is None:
            # Treat naive as UTC for comparison
            reference = reference.replace(tzinfo=None) if reference.tzinfo else reference
        return reference >= self.expires_at

    def filter_constraints(self) -> list[dict[str, Any]]:
        """Return the lossless predicate list.

        Includes full operator semantics — not just equality.
        Connectors should compile from this, not from enforced_filters.
        """
        if self.enforced_predicates:
            return list(self.enforced_predicates)
        # Fallback: synthesize EQ predicates from the legacy dict view.
        return [
            {"field": f, "operator": "=", "value": v}
            for f, v in self.enforced_filters.items()
        ]

    # ------------------------------------------------------------------
    # Factory (called only by DataFenceBoundary)
    # ------------------------------------------------------------------

    @staticmethod
    def _create_signed(
        execution_id: str,
        actor: Actor,
        resource: str,
        operation: Operation,
        selected_fields: list[str],
        enforced_filters: dict[str, Any],
        limit: int,
        policy_version: str,
        policy_decisions: list[str],
        signing_key: bytes,
        expires_at: datetime | None = None,
        audience: str = "datafence",
        nonce: str | None = None,
        enforced_predicates: list[dict[str, Any]] | None = None,
    ) -> "AuthorizedExecution":
        """
        Create a signed capability.

        This is the ONLY legitimate construction path.
        Called exclusively by DataFenceBoundary._build_capability().
        """
        created_at = datetime.now(timezone.utc)
        effective_expires = expires_at or created_at + timedelta(minutes=5)
        effective_nonce = nonce or uuid4().hex

        # Build unsigned first to compute the canonical representation.
        unsigned = AuthorizedExecution(
            execution_id=execution_id,
            created_at=created_at,
            actor=actor,
            resource=resource,
            operation=operation,
            selected_fields=selected_fields,
            enforced_filters=enforced_filters,
            limit=limit,
            policy_version=policy_version,
            policy_decisions=policy_decisions,
            enforced_predicates=list(enforced_predicates or []),
            expires_at=effective_expires,
            audience=audience,
            nonce=effective_nonce,
            signature=b"",
        )
        sig = unsigned.compute_signature(signing_key)

        # Reconstruct with the real signature (frozen dataclass).
        return AuthorizedExecution(
            execution_id=execution_id,
            created_at=created_at,
            actor=actor,
            resource=resource,
            operation=operation,
            selected_fields=selected_fields,
            enforced_filters=enforced_filters,
            limit=limit,
            policy_version=policy_version,
            policy_decisions=policy_decisions,
            enforced_predicates=list(enforced_predicates or []),
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


# ---------------------------------------------------------------------------
# Customer-side verifier
# ---------------------------------------------------------------------------


class CapabilityVerificationError(Exception):
    """Raised when capability verification fails (forged, expired, or mis-targeted)."""

    pass


class CapabilityVerifier:
    """Customer-side verifier for DataFence authorization capabilities.

    The customer backend configures this verifier with the same signing key
    (or an asymmetric verification key in a PKI deployment) and calls
    :meth:`verify` before translating a capability into a backend operation.

    Usage::

        verifier = CapabilityVerifier(signing_key, expected_audience="my-service")
        verifier.verify(capability)        # raises on failure
        result = my_connector.execute(capability)
    """

    def __init__(self, signing_key: bytes, expected_audience: str = "datafence") -> None:
        if not signing_key:
            raise ValueError("signing_key cannot be empty")
        if not expected_audience:
            raise ValueError("expected_audience cannot be empty")
        self._signing_key = signing_key
        self._expected_audience = expected_audience

    def verify(self, capability: AuthorizedExecution) -> None:
        """Verify a capability and raise CapabilityVerificationError on any failure.

        Checks (in order):
        1. Type — must be an AuthorizedExecution instance.
        2. Audience — must match the configured expected_audience.
        3. Expiry — must not be expired.
        4. Signature — HMAC must be valid.

        Args:
            capability: The AuthorizedExecution returned by boundary.authorize().

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
