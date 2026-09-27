"""
PII Protection Example

Demonstrates how DataFence automatically detects and redacts PII:
- Email addresses
- Phone numbers
- Credit card numbers
- SSNs
- API keys
"""

from pathlib import Path

from datafence import DataFence
from datafence.connectors.memory import MemoryConnector
from datafence.policy.models import (
    FieldPolicy,
    OperationPolicy,
    Policy,
    ResourcePolicy,
)
from datafence.security.pii import PIIScanner, RedactionStrategy

print("=" * 70)
print("DataFence PII Protection Demo")
print("=" * 70)

# Sample data with PII
customer_data = [
    {
        "customer_id": 1,
        "name": "Alice Johnson",
        "email": "alice.johnson@email.com",
        "phone": "555-123-4567",
        "ssn": "123-45-6789",
        "card_number": "4532015112830366",  # Valid test card
        "notes": "Preferred contact: alice.johnson@email.com or 555-123-4567",
    },
    {
        "customer_id": 2,
        "name": "Bob Smith",
        "email": "bob.smith@company.org",
        "phone": "(555) 987-6543",
        "ssn": "987-65-4321",
        "card_number": "5425233430109903",  # Valid test card
        "notes": "Call 555-987-6543 for updates",
    },
]

# Create policy allowing all fields (to demonstrate PII protection)
policy = Policy(
    version="1",
    name="customer-policy",
    resources={
        "customers": ResourcePolicy(
            operations=OperationPolicy(allow=["read"]),
            fields=FieldPolicy(
                allow=["customer_id", "name", "email", "phone", "ssn", "card_number", "notes"]
            ),
        )
    },
)

connector = MemoryConnector({"customers": customer_data})

# Demo 1: No PII Protection
print("\n1. WITHOUT PII PROTECTION (Unsafe)")
print("-" * 70)

fence_unsafe = DataFence(
    policy,
    connector,
    enable_pii_detection=False,
)

result = fence_unsafe.execute(
    {
        "actor": {"id": "agent", "type": "agent"},
        "operation": "read",
        "resource": "customers",
        "fields": ["customer_id", "name", "email", "phone"],
    }
)

print("Raw data returned (UNSAFE):")
for record in result.data[:1]:  # Show first record
    for key, value in record.items():
        print(f"  {key}: {value}")

# Demo 2: PII Protection with MASK strategy
print("\n2. WITH PII PROTECTION - MASK Strategy")
print("-" * 70)

fence_mask = DataFence(
    policy,
    connector,
    enable_pii_detection=True,
    pii_redaction_strategy=RedactionStrategy.MASK,
)

result = fence_mask.execute(
    {
        "actor": {"id": "agent", "type": "agent"},
        "operation": "read",
        "resource": "customers",
        "fields": ["customer_id", "name", "email", "phone"],
    }
)

print("Masked data (SAFE):")
for record in result.data[:1]:
    for key, value in record.items():
        print(f"  {key}: {value}")

# Demo 3: PII Protection with TOKEN strategy
print("\n3. WITH PII PROTECTION - TOKEN Strategy")
print("-" * 70)

fence_token = DataFence(
    policy,
    connector,
    enable_pii_detection=True,
    pii_redaction_strategy=RedactionStrategy.TOKEN,
)

result = fence_token.execute(
    {
        "actor": {"id": "agent", "type": "agent"},
        "operation": "read",
        "resource": "customers",
        "fields": ["customer_id", "name", "email", "notes"],
    }
)

print("Tokenized data (SAFE):")
for record in result.data[:1]:
    for key, value in record.items():
        print(f"  {key}: {value}")

# Demo 4: Credit Card Protection
print("\n4. CREDIT CARD PROTECTION")
print("-" * 70)

result = fence_mask.execute(
    {
        "actor": {"id": "agent", "type": "agent"},
        "operation": "read",
        "resource": "customers",
        "fields": ["customer_id", "name", "card_number"],
    }
)

print("Credit card data (with Luhn validation):")
for record in result.data:
    print(f"  Customer {record['customer_id']}: {record['card_number']}")

# Demo 5: SSN Protection with PARTIAL
print("\n5. SSN PROTECTION - PARTIAL (Last 4)")
print("-" * 70)

fence_partial = DataFence(
    policy,
    connector,
    enable_pii_detection=True,
    pii_redaction_strategy=RedactionStrategy.PARTIAL,
)

result = fence_partial.execute(
    {
        "actor": {"id": "agent", "type": "agent"},
        "operation": "read",
        "resource": "customers",
        "fields": ["customer_id", "name", "ssn"],
    }
)

print("SSN data (showing last 4 only):")
for record in result.data:
    print(f"  {record['name']}: {record['ssn']}")

# Demo 6: PII Scanner Standalone
print("\n6. PII SCANNER - Standalone Usage")
print("-" * 70)

scanner = PIIScanner(default_strategy=RedactionStrategy.MASK)

test_text = """
Contact Information:
Email: support@company.com
Phone: 1-800-555-0199
Card: 4532015112830366
SSN: 123-45-6789
"""

print("Original text:")
print(test_text)

# Detect PII
results = scanner.scan_value(test_text)
print("\nPII Detected:")
for pii_type, detected in results.items():
    if detected:
        print(f"  ✓ {pii_type}")

# Redact
redacted = scanner.redact_value(test_text)
print("\nRedacted text:")
print(redacted)

# Summary
print("\n" + "=" * 70)
print("SUMMARY: PII Protection")
print("=" * 70)
print("✓ Email addresses:    DETECTED & REDACTED")
print("✓ Phone numbers:      DETECTED & REDACTED")
print("✓ Credit cards:       DETECTED & REDACTED (with Luhn validation)")
print("✓ SSNs:               DETECTED & REDACTED")
print("✓ API keys:           DETECTED & REDACTED")
print()
print("PII detection works on:")
print("  • Individual fields")
print("  • Text fields with embedded PII")
print("  • Nested dictionaries")
print("  • Lists of records")
print()
print("Redaction strategies:")
print("  • MASK: ****5678 (show last 4)")
print("  • TOKEN: [EMAIL], [PHONE], [CARD]")
print("  • PARTIAL: 4532****0366 (first+last)")
print("  • REMOVE: Delete entirely")
print("=" * 70)
