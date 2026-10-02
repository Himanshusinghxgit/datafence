"""
Tests for PII detection and redaction.
"""

from datafence.security.pii import (
    APIKeyDetector,
    CreditCardDetector,
    EmailDetector,
    PhoneDetector,
    PIIScanner,
    RedactionStrategy,
    SSNDetector,
)


def test_email_detection():
    """Test email address detection."""
    detector = EmailDetector()

    assert detector.detect("contact@example.com")
    assert detector.detect("My email is user@test.org")
    assert not detector.detect("not an email")
    assert not detector.detect("12345")


def test_email_redaction_token():
    """Test email redaction with token strategy."""
    detector = EmailDetector()

    text = "Contact me at john@example.com"
    redacted = detector.redact(text, RedactionStrategy.TOKEN)

    assert "[EMAIL]" in redacted
    assert "john@example.com" not in redacted


def test_email_redaction_mask():
    """Test email redaction with mask strategy."""
    detector = EmailDetector()

    text = "Email: alice@company.com"
    redacted = detector.redact(text, RedactionStrategy.MASK)

    assert "***@***.***" in redacted
    assert "alice@company.com" not in redacted


def test_phone_detection():
    """Test phone number detection."""
    detector = PhoneDetector()

    assert detector.detect("123-456-7890")
    assert detector.detect("(123) 456-7890")
    assert detector.detect("+1 123-456-7890")
    assert detector.detect("Call me at 555.123.4567")
    assert not detector.detect("not a phone")


def test_phone_redaction_partial():
    """Test phone redaction showing last 4 digits."""
    detector = PhoneDetector()

    text = "Call 123-456-7890"
    redacted = detector.redact(text, RedactionStrategy.PARTIAL)

    assert "7890" in redacted  # Last 4 digits visible
    assert "123-456" not in redacted


def test_ssn_detection():
    """Test SSN detection."""
    detector = SSNDetector()

    assert detector.detect("123-45-6789")
    assert detector.detect("SSN: 987-65-4321")
    assert not detector.detect("123456789")  # No dashes
    assert not detector.detect("not an ssn")


def test_ssn_redaction_partial():
    """Test SSN redaction showing last 4."""
    detector = SSNDetector()

    text = "SSN: 123-45-6789"
    redacted = detector.redact(text, RedactionStrategy.PARTIAL)

    assert "6789" in redacted
    assert "123-45" not in redacted


def test_credit_card_detection():
    """Test credit card detection with Luhn validation."""
    detector = CreditCardDetector()

    # Valid test card numbers (pass Luhn check)
    assert detector.detect("4532015112830366")  # Visa test card
    assert detector.detect("Card: 5425233430109903")  # Mastercard test

    # Invalid (fail Luhn)
    assert not detector.detect("1234567890123456")
    assert not detector.detect("not a card")


def test_credit_card_redaction_mask():
    """Test credit card redaction with masking."""
    detector = CreditCardDetector()

    text = "Card: 4532015112830366"
    redacted = detector.redact(text, RedactionStrategy.MASK)

    assert "0366" in redacted  # Last 4 visible
    assert "4532015112" not in redacted  # Rest masked


def test_credit_card_redaction_partial():
    """Test credit card redaction showing first 4 and last 4."""
    detector = CreditCardDetector()

    text = "4532015112830366"
    redacted = detector.redact(text, RedactionStrategy.PARTIAL)

    assert "4532" in redacted  # First 4
    assert "0366" in redacted  # Last 4
    assert "01511283" not in redacted  # Middle masked


def test_api_key_detection():
    """Test API key detection."""
    detector = APIKeyDetector()

    assert detector.detect("sk_live_FAKE_KEY_FOR_TESTING_ONLY_00000000")
    assert detector.detect("sk_test_FAKE_KEY_FOR_TESTING_ONLY_11111111")
    assert not detector.detect("short_string")


def test_api_key_redaction():
    """Test API key redaction."""
    detector = APIKeyDetector()

    text = "API key: sk_live_FAKE_KEY_FOR_TESTING_ONLY_00000000"
    redacted = detector.redact(text, RedactionStrategy.TOKEN)

    assert "[API_KEY]" in redacted
    assert "sk_live" not in redacted


def test_pii_scanner_detects_multiple_types():
    """Test that scanner detects multiple PII types."""
    scanner = PIIScanner()

    text = "Contact john@example.com or call 123-456-7890"
    results = scanner.scan_value(text)

    assert results["email"] is True
    assert results["phone"] is True


def test_pii_scanner_has_pii():
    """Test has_pii method."""
    scanner = PIIScanner()

    assert scanner.has_pii("Email: test@example.com")
    assert scanner.has_pii("SSN: 123-45-6789")
    assert not scanner.has_pii("No PII here")


def test_pii_scanner_redact_value():
    """Test value redaction."""
    scanner = PIIScanner(default_strategy=RedactionStrategy.TOKEN)

    text = "Contact alice@example.com"
    redacted = scanner.redact_value(text)

    assert "[EMAIL]" in redacted
    assert "alice@example.com" not in redacted


def test_pii_scanner_redact_dict():
    """Test dictionary redaction."""
    scanner = PIIScanner(default_strategy=RedactionStrategy.MASK)

    data = {
        "name": "John Doe",
        "email": "john@example.com",
        "phone": "123-456-7890",
        "notes": "No PII here",
    }

    redacted = scanner.redact_dict(data)

    assert "john@example.com" not in str(redacted)
    assert "123-456-7890" not in str(redacted)
    assert redacted["name"] == "John Doe"  # No PII in name
    assert redacted["notes"] == "No PII here"


def test_pii_scanner_redact_nested_dict():
    """Test nested dictionary redaction."""
    scanner = PIIScanner(default_strategy=RedactionStrategy.TOKEN)

    data = {
        "user": {
            "email": "test@example.com",
            "profile": {"phone": "123-456-7890"},
        }
    }

    redacted = scanner.redact_dict(data)

    assert "[EMAIL]" in str(redacted)
    assert "[PHONE]" in str(redacted)
    assert "test@example.com" not in str(redacted)


def test_pii_scanner_redact_list_in_dict():
    """Test redacting lists in dictionaries."""
    scanner = PIIScanner(default_strategy=RedactionStrategy.TOKEN)

    data = {"emails": ["alice@example.com", "bob@example.com"]}

    redacted = scanner.redact_dict(data)

    for email in redacted["emails"]:
        assert "[EMAIL]" in email
