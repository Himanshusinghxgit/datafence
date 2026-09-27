"""
Policy loading from YAML files.
"""

from pathlib import Path
from typing import Any

import yaml

from datafence.errors import PolicyError
from datafence.policy.models import Policy


def load_policy_yaml(path: str | Path) -> dict[str, Any]:
    """
    Load policy from YAML file.

    Args:
        path: Path to YAML file

    Returns:
        Policy dictionary

    Raises:
        PolicyError: If file cannot be loaded or parsed
    """
    path = Path(path)

    if not path.exists():
        raise PolicyError(f"Policy file not found: {path}")

    try:
        with open(path) as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise PolicyError(f"Policy file must contain a dictionary: {path}")

        return data

    except yaml.YAMLError as e:
        raise PolicyError(f"Failed to parse policy YAML: {e}") from e
    except Exception as e:
        raise PolicyError(f"Failed to load policy file: {e}") from e


def load_policy(path: str | Path) -> Policy:
    """
    Load and validate policy from YAML file.

    Args:
        path: Path to policy YAML file

    Returns:
        Validated Policy object

    Raises:
        PolicyError: If policy is invalid
    """
    data = load_policy_yaml(path)

    # Ensure required structure
    if "policy" not in data:
        raise PolicyError("Policy file must contain 'policy' key")

    policy_data = data["policy"]

    # Add version if not present
    if "version" not in policy_data:
        policy_data["version"] = data.get("version", "1")

    try:
        return Policy(**policy_data)
    except Exception as e:
        raise PolicyError(f"Invalid policy structure: {e}") from e


def load_policy_dict(data: dict[str, Any]) -> Policy:
    """
    Load policy from dictionary.

    Args:
        data: Policy dictionary

    Returns:
        Validated Policy object

    Raises:
        PolicyError: If policy is invalid
    """
    if "policy" in data:
        policy_data = data["policy"]
        if "version" not in policy_data:
            policy_data["version"] = data.get("version", "1")
    else:
        policy_data = data
        if "version" not in policy_data:
            policy_data["version"] = "1"

    try:
        return Policy(**policy_data)
    except Exception as e:
        raise PolicyError(f"Invalid policy structure: {e}") from e
