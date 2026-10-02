"""
DataFence Authorized Execution Capability.

This module implements the cryptographic capability model for v0.4.

SECURITY MODEL:
- AuthorizedExecution is created ONLY by DataFenceBoundary
- Each capability has an HMAC signature over its contents
- Connector verifies signature before execution
- Signature uses secret key shared between boundary and connector

This prevents:
- Capability forgery (attacker cannot create valid HMAC)
- Capability tampering (signature covers all fields)
- Bypass attacks (connector requires valid signature)

THREAT MODEL:
- ✅ Protects against Threat Model A (untrusted LLM/agent)
- ✅ Protects against Threat Model B (compromised application code)
- ❌ Does NOT protect against Threat Model C (full Python runtime compromise)

The secret key can be extracted via Python introspection (Threat Model C),
but this is explicitly out of scope.
"""

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from datafence.core.types import Actor, Operation


@dataclass(frozen=True)
class AuthorizedExecution:
    """
    Cryptographically signed execution capability.

    This represents DataFence's authorization for ONE specific operation.

    The capability:
    - Is created ONLY by DataFenceBoundary
    - Contains an HMAC signature over all fields
    - Cannot be forged without the secret signing key
    - Cannot be tampered with (signature verification fails)

    INTERNAL USE ONLY - Not exported in public API.
    """

    # Execution metadata
    execution_id: str
    created_at: datetime

    # Authorization context
    actor: Actor
    resource: str
    operation: Operation

    # Authorized access
    selected_fields: list[str]
    enforced_filters: dict[str, Any]
    limit: int

    # Policy provenance
    policy_version: str
    policy_decisions: list[str] = field(default_factory=list)

    # Capability lifecycle / audience binding
    expires_at: datetime | None = None
    audience: str = "datafence"
    nonce: str = ""

    # Cryptographic signature (HMAC-SHA256)
    signature: bytes = field(default=b"", repr=False)

    def _compute_canonical_repr(self) -> bytes:
        """
        Compute canonical byte representation for HMAC.

        This must be deterministic and cover ALL security-relevant fields.
        Any tampering will change the signature.
        """
        # Build canonical representation
        parts = [
            self.execution_id,
            self.created_at.isoformat(),
            self.actor.id,
            self.actor.tenant_id,
            json.dumps(self.actor.metadata, sort_keys=True),
            self.resource,
            self.operation.value,
            json.dumps(self.selected_fields, separators=(",", ":")),
            json.dumps(self.enforced_filters, sort_keys=True),
            str(self.limit),
            self.policy_version,
            json.dumps(self.policy_decisions, separators=(",", ":")),
            self.expires_at.isoformat() if self.expires_at else "",
            self.audience,
            self.nonce,
        ]

        canonical = "|".join(parts)
        return canonical.encode("utf-8")

    def compute_signature(self, signing_key: bytes) -> bytes:
        """
        Compute HMAC-SHA256 signature over capability contents.

        Args:
            signing_key: Secret key (32 bytes recommended)

        Returns:
            HMAC signature (32 bytes)
        """
        canonical = self._compute_canonical_repr()
        return hmac.new(signing_key, canonical, hashlib.sha256).digest()

    def verify_signature(self, signing_key: bytes) -> bool:
        """
        Verify capability signature.

        Args:
            signing_key: Secret key used to sign

        Returns:
            True if signature is valid, False otherwise

        Security:
            Uses constant-time comparison to prevent timing attacks
        """
        if not self.signature:
            return False

        expected_signature = self.compute_signature(signing_key)
        return hmac.compare_digest(self.signature, expected_signature)

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return whether this capability is outside its validity window."""
        return self.expires_at is not None and (now or datetime.utcnow()) >= self.expires_at

    @staticmethod
    def create_signed(
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
    ) -> "AuthorizedExecution":
        """
        Create a signed capability.

        This is the ONLY way to create a valid capability.
        Called by DataFenceBoundary.

        Args:
            execution_id: Unique execution identifier
            actor: Authorized actor
            resource: Resource to access
            operation: Operation to perform
            selected_fields: Fields authorized for access
            enforced_filters: Filters that must be applied
            limit: Maximum rows
            policy_version: Policy version used
            policy_decisions: Policy decisions made
            signing_key: Secret signing key

        Returns:
            Signed AuthorizedExecution capability
        """
        # Create unsigned capability
        created_at = datetime.utcnow()
        capability = AuthorizedExecution(
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
            expires_at=expires_at or created_at + timedelta(minutes=5),
            audience=audience,
            nonce=nonce or uuid4().hex,
            signature=b"",  # Temporary
        )

        # Compute signature
        signature = capability.compute_signature(signing_key)

        # Create signed capability
        # Note: We need to bypass frozen=True here
        signed_capability = AuthorizedExecution(
            execution_id=execution_id,
            created_at=capability.created_at,
            actor=actor,
            resource=resource,
            operation=operation,
            selected_fields=selected_fields,
            enforced_filters=enforced_filters,
            limit=limit,
            policy_version=policy_version,
            policy_decisions=policy_decisions,
            expires_at=capability.expires_at,
            audience=capability.audience,
            nonce=capability.nonce,
            signature=signature,
        )

        return signed_capability

    def __post_init__(self) -> None:
        """Validate capability fields."""
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


class CapabilityVerificationError(Exception):
    """Raised when capability signature verification fails."""

    pass
