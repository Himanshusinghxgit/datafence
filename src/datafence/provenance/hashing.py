"""
Hashing utilities for provenance and evidence.

Uses SHA-256 for deterministic, cryptographic hashes.
"""

import hashlib
import json
from typing import Any


def normalize_dict(data: dict[str, Any]) -> str:
    """
    Normalize a dictionary to a canonical JSON string.

    Args:
        data: Dictionary to normalize

    Returns:
        Canonical JSON string (sorted keys, no whitespace)
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def hash_dict(data: dict[str, Any]) -> str:
    """
    Generate SHA-256 hash of a dictionary.

    Args:
        data: Dictionary to hash

    Returns:
        Hexadecimal SHA-256 hash with 'sha256:' prefix
    """
    normalized = normalize_dict(data)
    hash_obj = hashlib.sha256(normalized.encode("utf-8"))
    return f"sha256:{hash_obj.hexdigest()}"


def hash_string(text: str) -> str:
    """
    Generate SHA-256 hash of a string.

    Args:
        text: String to hash

    Returns:
        Hexadecimal SHA-256 hash with 'sha256:' prefix
    """
    hash_obj = hashlib.sha256(text.encode("utf-8"))
    return f"sha256:{hash_obj.hexdigest()}"


def hash_query(query: str) -> str:
    """
    Generate SHA-256 hash of a normalized SQL query.

    Args:
        query: SQL query to hash

    Returns:
        Hexadecimal SHA-256 hash with 'sha256:' prefix
    """
    # Normalize whitespace
    normalized = " ".join(query.split())
    return hash_string(normalized.lower())
