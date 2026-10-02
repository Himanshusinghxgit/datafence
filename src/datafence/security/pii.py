"""
PII (Personally Identifiable Information) detection and redaction.

Detects and optionally redacts sensitive data patterns.
"""

import re
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any


class PIIType(str, Enum):
    """Types of PII."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    PASSWORD = "password"
    SECRET = "secret"


class RedactionStrategy(str, Enum):
    """PII redaction strategies."""

    REMOVE = "remove"  # Remove entirely
    MASK = "mask"  # Mask with asterisks (e.g., ****5678)
    HASH = "hash"  # Replace with hash
    PARTIAL = "partial"  # Show partial (e.g., +1***456)
    TOKEN = "token"  # Replace with token like [EMAIL]


class PIIDetector(ABC):
    """Abstract PII detector."""

    @abstractmethod
    def detect(self, value: str) -> bool:
        """
        Check if value contains PII.

        Args:
            value: String to check

        Returns:
            True if PII detected
        """
        pass

    @abstractmethod
    def redact(self, value: str, strategy: RedactionStrategy) -> str:
        """
        Redact PII from value.

        Args:
            value: String to redact
            strategy: Redaction strategy

        Returns:
            Redacted string
        """
        pass

    @property
    @abstractmethod
    def pii_type(self) -> PIIType:
        """Get PII type this detector handles."""
        pass


class EmailDetector(PIIDetector):
    """Email address detector."""

    PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", re.IGNORECASE)

    @property
    def pii_type(self) -> PIIType:
        return PIIType.EMAIL

    def detect(self, value: str) -> bool:
        return bool(self.PATTERN.search(str(value)))

    def redact(self, value: str, strategy: RedactionStrategy) -> str:
        if strategy == RedactionStrategy.TOKEN:
            return self.PATTERN.sub("[EMAIL]", str(value))
        elif strategy == RedactionStrategy.MASK:
            return self.PATTERN.sub("***@***.***", str(value))
        elif strategy == RedactionStrategy.REMOVE:
            return self.PATTERN.sub("", str(value))
        elif strategy == RedactionStrategy.PARTIAL:
            # Show first char + domain
            def partial_mask(match: re.Match[str]) -> str:
                email = match.group(0)
                parts = email.split("@")
                if len(parts) == 2:
                    return f"{parts[0][0]}***@{parts[1]}"
                return "***@***.***"

            return self.PATTERN.sub(partial_mask, str(value))
        else:
            return "[EMAIL_REDACTED]"


class PhoneDetector(PIIDetector):
    """Phone number detector."""

    # US phone patterns
    PATTERNS = [
        re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"),  # 123-456-7890
        re.compile(r"\(\d{3}\)\s*\d{3}[-.]?\d{4}"),  # (123) 456-7890
        re.compile(r"\+1\s*\d{3}[-.]?\d{3}[-.]?\d{4}"),  # +1 123-456-7890
    ]

    @property
    def pii_type(self) -> PIIType:
        return PIIType.PHONE

    def detect(self, value: str) -> bool:
        return any(pattern.search(str(value)) for pattern in self.PATTERNS)

    def redact(self, value: str, strategy: RedactionStrategy) -> str:
        value_str = str(value)

        if strategy == RedactionStrategy.TOKEN:
            for pattern in self.PATTERNS:
                value_str = pattern.sub("[PHONE]", value_str)
        elif strategy == RedactionStrategy.MASK:
            for pattern in self.PATTERNS:
                value_str = pattern.sub("***-***-****", value_str)
        elif strategy == RedactionStrategy.PARTIAL:
            # Show last 4 digits
            def partial_mask(match: re.Match[str]) -> str:
                phone = match.group(0)
                digits = re.findall(r"\d", phone)
                if len(digits) >= 4:
                    return "***-***-" + "".join(digits[-4:])
                return "***-***-****"

            for pattern in self.PATTERNS:
                value_str = pattern.sub(partial_mask, value_str)
        elif strategy == RedactionStrategy.REMOVE:
            for pattern in self.PATTERNS:
                value_str = pattern.sub("", value_str)
        else:
            for pattern in self.PATTERNS:
                value_str = pattern.sub("[PHONE_REDACTED]", value_str)

        return value_str


class SSNDetector(PIIDetector):
    """Social Security Number detector."""

    PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    @property
    def pii_type(self) -> PIIType:
        return PIIType.SSN

    def detect(self, value: str) -> bool:
        return bool(self.PATTERN.search(str(value)))

    def redact(self, value: str, strategy: RedactionStrategy) -> str:
        if strategy == RedactionStrategy.TOKEN:
            return self.PATTERN.sub("[SSN]", str(value))
        elif strategy == RedactionStrategy.MASK:
            return self.PATTERN.sub("***-**-****", str(value))
        elif strategy == RedactionStrategy.PARTIAL:
            # Show last 4
            return self.PATTERN.sub(lambda m: "***-**-" + m.group(0)[-4:], str(value))
        elif strategy == RedactionStrategy.REMOVE:
            return self.PATTERN.sub("", str(value))
        else:
            return "[SSN_REDACTED]"


class CreditCardDetector(PIIDetector):
    """Credit card number detector."""

    # Basic credit card pattern (13-19 digits)
    PATTERN = re.compile(r"\b\d{13,19}\b")

    @property
    def pii_type(self) -> PIIType:
        return PIIType.CREDIT_CARD

    def detect(self, value: str) -> bool:
        match = self.PATTERN.search(str(value))
        if not match:
            return False

        # Verify with Luhn algorithm
        digits = match.group(0)
        return self._luhn_check(digits)

    def _luhn_check(self, card_number: str) -> bool:
        """Validate card number with Luhn algorithm."""
        try:
            digits = [int(d) for d in card_number]
            checksum = 0

            # Double every second digit from right
            for i in range(len(digits) - 2, -1, -2):
                doubled = digits[i] * 2
                checksum += doubled if doubled < 10 else doubled - 9

            # Add remaining digits
            for i in range(len(digits) - 1, -1, -2):
                checksum += digits[i]

            return checksum % 10 == 0
        except (ValueError, IndexError):
            return False

    def redact(self, value: str, strategy: RedactionStrategy) -> str:
        def redact_card(match: re.Match[str]) -> str:
            card = match.group(0)
            if not self._luhn_check(card):
                return card  # Not a valid card, don't redact

            if strategy == RedactionStrategy.TOKEN:
                return "[CARD]"
            elif strategy == RedactionStrategy.MASK:
                return "*" * (len(card) - 4) + card[-4:]
            elif strategy == RedactionStrategy.PARTIAL:
                return card[:4] + "*" * (len(card) - 8) + card[-4:]
            elif strategy == RedactionStrategy.REMOVE:
                return ""
            else:
                return "[CARD_REDACTED]"

        return self.PATTERN.sub(redact_card, str(value))


class APIKeyDetector(PIIDetector):
    """API key and secret detector."""

    PATTERNS = [
        re.compile(r"sk_live_[A-Za-z0-9_]{24,}"),  # Stripe live
        re.compile(r"sk_test_[A-Za-z0-9_]{20,}"),  # Stripe test (reduced from 24)
        re.compile(r"AIza[A-Za-z0-9_-]{35}"),  # Google
    ]

    @property
    def pii_type(self) -> PIIType:
        return PIIType.API_KEY

    def detect(self, value: str) -> bool:
        # Detect known patterns
        value_str = str(value)
        for pattern in self.PATTERNS:
            if pattern.search(value_str):
                return True
        return False

    def redact(self, value: str, strategy: RedactionStrategy) -> str:
        value_str = str(value)

        for pattern in self.PATTERNS:
            if strategy == RedactionStrategy.TOKEN:
                value_str = pattern.sub("[API_KEY]", value_str)
            elif strategy == RedactionStrategy.PARTIAL:
                value_str = pattern.sub(lambda m: m.group(0)[:8] + "***", value_str)
            else:
                value_str = pattern.sub("[API_KEY_REDACTED]", value_str)

        return value_str


class PIIScanner:
    """
    Scanner for detecting and redacting PII.

    Combines multiple detectors.
    """

    def __init__(
        self,
        detectors: list[PIIDetector] | None = None,
        default_strategy: RedactionStrategy = RedactionStrategy.MASK,
    ):
        """
        Initialize PII scanner.

        Args:
            detectors: List of PII detectors (uses default set if None)
            default_strategy: Default redaction strategy
        """
        self.detectors = detectors or self._default_detectors()
        self.default_strategy = default_strategy

    def _default_detectors(self) -> list[PIIDetector]:
        """Get default set of detectors."""
        return [
            EmailDetector(),
            PhoneDetector(),
            SSNDetector(),
            CreditCardDetector(),
            APIKeyDetector(),
        ]

    def scan_value(self, value: Any) -> dict[PIIType, bool]:
        """
        Scan a single value for PII.

        Args:
            value: Value to scan

        Returns:
            Dictionary mapping PII types to detection results
        """
        if not isinstance(value, str):
            value = str(value)

        results = {}
        for detector in self.detectors:
            results[detector.pii_type] = detector.detect(value)

        return results

    def has_pii(self, value: Any) -> bool:
        """
        Check if value contains any PII.

        Args:
            value: Value to check

        Returns:
            True if PII detected
        """
        results = self.scan_value(value)
        return any(results.values())

    def redact_value(self, value: Any, strategy: RedactionStrategy | None = None) -> Any:
        """
        Redact PII from a value.

        Args:
            value: Value to redact
            strategy: Redaction strategy (uses default if None)

        Returns:
            Redacted value
        """
        if not isinstance(value, str):
            # For non-strings, convert to string, redact, return as-is
            # In production, you might want different handling
            return value

        strategy = strategy or self.default_strategy

        redacted = value
        for detector in self.detectors:
            if detector.detect(redacted):
                redacted = detector.redact(redacted, strategy)

        return redacted

    def redact_dict(
        self, data: dict[str, Any], strategy: RedactionStrategy | None = None
    ) -> dict[str, Any]:
        """
        Redact PII from a dictionary.

        Args:
            data: Dictionary to redact
            strategy: Redaction strategy

        Returns:
            Dictionary with PII redacted
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, dict):
                result[key] = self.redact_dict(value, strategy)
            elif isinstance(value, list):
                result[key] = [
                    self.redact_dict(item, strategy)
                    if isinstance(item, dict)
                    else self.redact_value(item, strategy)
                    for item in value
                ]
            else:
                result[key] = self.redact_value(value, strategy)

        return result
