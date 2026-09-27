"""
Tests for CLI tool.
"""

import json
import pytest
from pathlib import Path
from click.testing import CliRunner

try:
    from datafence.cli import cli, validate, describe, test, export, init

    CLI_AVAILABLE = True
except ImportError:
    CLI_AVAILABLE = False


@pytest.fixture
def runner():
    """Create CLI test runner."""
    return CliRunner()


@pytest.fixture
def sample_policy(tmp_path):
    """Create sample policy file."""
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text("""
version: "1"
policy:
  name: test-policy
  resources:
    transactions:
      operations:
        allow: [read]
      fields:
        allow: [id, amount, merchant]
      limits:
        max_rows: 100
""")
    return policy_file


@pytest.fixture
def sample_request(tmp_path):
    """Create sample request file."""
    request_file = tmp_path / "request.json"
    request_dict = {
        "actor": {"id": "test", "tenant_id": "acme", "type": "agent"},
        "operation": "read",
        "resource": "transactions",
        "fields": ["id", "amount"],
        "limit": 10,
    }
    request_file.write_text(json.dumps(request_dict))
    return request_file


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_cli_help(runner):
    """Test CLI help."""
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "DataFence" in result.output


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_validate_valid_policy(runner, sample_policy):
    """Test validating a valid policy."""
    result = runner.invoke(validate, [str(sample_policy)])
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_validate_verbose(runner, sample_policy):
    """Test validation with verbose output."""
    result = runner.invoke(validate, [str(sample_policy), "--verbose"])
    assert result.exit_code == 0
    assert "test-policy" in result.output
    assert "Resources" in result.output


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_validate_missing_file(runner, tmp_path):
    """Test validating non-existent file."""
    result = runner.invoke(validate, [str(tmp_path / "missing.yaml")])
    assert result.exit_code != 0


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_validate_invalid_yaml(runner, tmp_path):
    """Test validating invalid YAML."""
    invalid_file = tmp_path / "invalid.yaml"
    invalid_file.write_text("invalid: yaml: content:\n  - [")

    result = runner.invoke(validate, [str(invalid_file)])
    assert result.exit_code != 0
    assert "error" in result.output.lower()


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_describe_resource(runner, sample_policy):
    """Test describing a resource."""
    result = runner.invoke(describe, [str(sample_policy), "--resource", "transactions"])
    assert result.exit_code == 0
    assert "transactions" in result.output
    assert "Operations" in result.output
    assert "Fields" in result.output


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_describe_resource_json(runner, sample_policy):
    """Test describing resource with JSON output."""
    result = runner.invoke(
        describe, [str(sample_policy), "-r", "transactions", "--format", "json"]
    )
    assert result.exit_code == 0

    output = json.loads(result.output)
    assert output["resource"] == "transactions"
    assert "operations" in output
    assert "fields" in output


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_describe_missing_resource(runner, sample_policy):
    """Test describing non-existent resource."""
    result = runner.invoke(describe, [str(sample_policy), "--resource", "nonexistent"])
    assert result.exit_code != 0
    assert "not found" in result.output.lower()


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_test_dry_run(runner, sample_policy, sample_request):
    """Test request with dry-run."""
    result = runner.invoke(
        test, [str(sample_policy), str(sample_request), "--dry-run"]
    )
    assert result.exit_code == 0
    assert "Dry-run" in result.output or "dry" in result.output.lower()


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_test_dry_run_verbose(runner, sample_policy, sample_request):
    """Test request with dry-run and verbose."""
    result = runner.invoke(
        test, [str(sample_policy), str(sample_request), "--dry-run", "--verbose"]
    )
    assert result.exit_code == 0


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_test_memory_connector(runner, sample_policy, sample_request):
    """Test request with memory connector."""
    result = runner.invoke(
        test, [str(sample_policy), str(sample_request), "--connector", "memory"]
    )
    # May fail because no data in memory connector, but should not crash
    assert "error" in result.output.lower() or "denied" in result.output.lower()


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_export_openai(runner, sample_policy, tmp_path):
    """Test exporting to OpenAI format."""
    output_file = tmp_path / "functions.json"

    result = runner.invoke(
        export,
        [str(sample_policy), "--framework", "openai", "--output", str(output_file)],
    )
    assert result.exit_code == 0
    assert output_file.exists()

    # Check output
    functions = json.loads(output_file.read_text())
    assert isinstance(functions, list)
    assert len(functions) > 0
    assert functions[0]["name"] == "read_transactions"


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_export_claude(runner, sample_policy):
    """Test exporting to Claude format."""
    result = runner.invoke(export, [str(sample_policy), "--framework", "claude"])
    assert result.exit_code == 0

    # Check output is valid JSON
    tools = json.loads(result.output)
    assert isinstance(tools, list)
    assert len(tools) > 0


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_init_command(runner, tmp_path):
    """Test init command."""
    output_file = tmp_path / "new-policy.yaml"

    result = runner.invoke(init, ["--output", str(output_file)], input="y\n")
    assert result.exit_code == 0
    assert output_file.exists()

    # Check created policy is valid
    content = output_file.read_text()
    assert "version:" in content
    assert "policy:" in content


@pytest.mark.skipif(not CLI_AVAILABLE, reason="CLI dependencies not installed")
def test_init_existing_file(runner, sample_policy):
    """Test init with existing file."""
    result = runner.invoke(init, ["--output", str(sample_policy)], input="n\n")
    assert result.exit_code != 0
    assert "Aborted" in result.output or "exists" in result.output


def test_cli_missing_dependencies():
    """Test error when CLI dependencies not installed."""
    if CLI_AVAILABLE:
        pytest.skip("CLI is available")

    with pytest.raises(ImportError):
        from datafence.cli import cli
