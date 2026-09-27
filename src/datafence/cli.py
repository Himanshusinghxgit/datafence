"""
DataFence CLI tool.

Command-line interface for policy validation, testing, and management.
"""

import json
import sys
from pathlib import Path
from typing import Any

try:
    import click
    import yaml
except ImportError:
    click = None
    yaml = None

from datafence import DataFence
from datafence.connectors import MemoryConnector, SQLiteConnector
from datafence.core.request import ExecutionRequest
from datafence.errors import DataFenceError


def _ensure_dependencies():
    """Ensure CLI dependencies are installed."""
    if click is None:
        print("Error: click package required for CLI")
        print("Install with: pip install 'datafence[cli]'")
        sys.exit(1)


@click.group()
@click.version_option()
def cli():
    """DataFence - Security boundary for AI agents and enterprise data."""
    _ensure_dependencies()


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--verbose", "-v", is_flag=True, help="Show detailed validation info")
def validate(policy_file: str, verbose: bool):
    """
    Validate a policy file.

    Checks YAML syntax, schema compliance, and logical consistency.

    Example:
        datafence validate policy.yaml
        datafence validate policy.yaml --verbose
    """
    try:
        click.echo(f"Validating policy: {policy_file}")

        # Load and validate policy
        with open(policy_file, "r") as f:
            policy_dict = yaml.safe_load(f)

        # Try to parse with DataFence
        from datafence.policy.models import Policy

        policy = Policy.model_validate(policy_dict["policy"])

        click.secho("✓ Policy is valid", fg="green")

        if verbose:
            click.echo("\nPolicy Summary:")
            click.echo(f"  Name: {policy.name}")
            click.echo(f"  Version: {policy_dict.get('version', '1')}")
            click.echo(f"  Resources: {len(policy.resources)}")

            for resource_name, resource_config in policy.resources.items():
                click.echo(f"\n  Resource: {resource_name}")
                click.echo(f"    Operations: {resource_config.operations}")
                click.echo(
                    f"    Fields: {len(resource_config.fields.get('allow', []))} allowed"
                )

                if hasattr(resource_config, "limits") and resource_config.limits:
                    click.echo(f"    Limits: {resource_config.limits}")

    except yaml.YAMLError as e:
        click.secho(f"✗ YAML error: {e}", fg="red")
        sys.exit(1)
    except Exception as e:
        click.secho(f"✗ Validation failed: {e}", fg="red")
        sys.exit(1)


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--resource", "-r", required=True, help="Resource name")
@click.option("--format", "-f", type=click.Choice(["table", "json"]), default="table")
def describe(policy_file: str, resource: str, format: str):
    """
    Describe a resource from the policy.

    Shows allowed operations, fields, and constraints.

    Example:
        datafence describe policy.yaml --resource transactions
        datafence describe policy.yaml -r users --format json
    """
    try:
        # Load policy
        with open(policy_file, "r") as f:
            policy_dict = yaml.safe_load(f)

        from datafence.policy.models import Policy

        policy = Policy.model_validate(policy_dict["policy"])

        if resource not in policy.resources:
            click.secho(f"✗ Resource '{resource}' not found in policy", fg="red")
            sys.exit(1)

        resource_config = policy.resources[resource]

        if format == "json":
            # JSON output
            output = {
                "resource": resource,
                "operations": resource_config.operations,
                "fields": resource_config.fields,
            }

            if hasattr(resource_config, "limits") and resource_config.limits:
                output["limits"] = resource_config.limits

            if hasattr(resource_config, "row_filters") and resource_config.row_filters:
                output["row_filters"] = resource_config.row_filters

            click.echo(json.dumps(output, indent=2))

        else:
            # Table output
            click.echo(f"\nResource: {resource}")
            click.echo("=" * 50)

            click.echo("\nOperations:")
            click.echo(f"  Allowed: {', '.join(resource_config.operations.get('allow', []))}")
            if resource_config.operations.get("deny"):
                click.echo(f"  Denied: {', '.join(resource_config.operations['deny'])}")

            click.echo("\nFields:")
            allowed_fields = resource_config.fields.get("allow", [])
            click.echo(f"  Allowed ({len(allowed_fields)}): {', '.join(allowed_fields)}")

            denied_fields = resource_config.fields.get("deny", [])
            if denied_fields:
                click.echo(f"  Denied ({len(denied_fields)}): {', '.join(denied_fields)}")

            if hasattr(resource_config, "limits") and resource_config.limits:
                click.echo("\nLimits:")
                for key, value in resource_config.limits.items():
                    click.echo(f"  {key}: {value}")

            if hasattr(resource_config, "row_filters") and resource_config.row_filters:
                click.echo("\nRow Filters:")
                for key, value in resource_config.row_filters.items():
                    click.echo(f"  {key}: {value}")

    except Exception as e:
        click.secho(f"✗ Error: {e}", fg="red")
        sys.exit(1)


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.argument("request_file", type=click.Path(exists=True))
@click.option("--connector", "-c", type=click.Choice(["memory", "sqlite"]), default="memory")
@click.option("--database", "-d", help="Database file (for sqlite connector)")
@click.option("--dry-run", is_flag=True, help="Show decision without executing")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
def test(
    policy_file: str,
    request_file: str,
    connector: str,
    database: str | None,
    dry_run: bool,
    verbose: bool,
):
    """
    Test a request against a policy.

    Request file should be JSON with actor, operation, resource, etc.

    Example:
        datafence test policy.yaml request.json
        datafence test policy.yaml request.json --dry-run
        datafence test policy.yaml request.json -c sqlite -d data.db
    """
    try:
        # Load request
        with open(request_file, "r") as f:
            request_dict = json.load(f)

        # Create connector
        if connector == "memory":
            conn = MemoryConnector(data={})
        elif connector == "sqlite":
            if not database:
                click.secho("✗ --database required for sqlite connector", fg="red")
                sys.exit(1)
            conn = SQLiteConnector(database)
        else:
            click.secho(f"✗ Unknown connector: {connector}", fg="red")
            sys.exit(1)

        # Load DataFence
        fence = DataFence.from_yaml(policy_file, conn)

        if dry_run:
            # Just validate and show decision (don't execute)
            click.echo("Dry-run mode: Checking policy compliance...\n")

            # Manually evaluate policy
            from datafence.core.context import ExecutionContext
            from datafence.policy.evaluator import PolicyEvaluator

            req = ExecutionRequest.model_validate(request_dict)
            ctx = ExecutionContext(
                request=req,
                policy=fence.policy,
                connector=conn,
                sql_firewall=None,
                pii_scanner=None,
            )

            evaluator = PolicyEvaluator(fence.policy)
            decision = evaluator.evaluate(ctx)

            click.echo(f"Decision: {decision.decision.value}")

            if decision.decision.value == "allow":
                click.secho("✓ Request would be ALLOWED", fg="green")
            else:
                click.secho("✗ Request would be DENIED", fg="red")

            if decision.reasons:
                click.echo("\nReasons:")
                for reason in decision.reasons:
                    click.echo(f"  - {reason}")

            if verbose:
                click.echo("\nApplied Policies:")
                for policy in decision.applied_policies:
                    click.echo(f"  - {policy}")

        else:
            # Full execution
            result = fence.execute(request_dict)

            if result.verified:
                click.secho("✓ Request ALLOWED", fg="green")
                click.echo(f"\nRows returned: {len(result.data)}")

                if verbose and result.data:
                    click.echo("\nSample data (first 3 rows):")
                    for i, row in enumerate(result.data[:3], 1):
                        click.echo(f"  Row {i}: {row}")

                if verbose:
                    click.echo("\nEvidence:")
                    click.echo(f"  Hash: {result.evidence.evidence_hash}")
                    click.echo(f"  Timestamp: {result.evidence.timestamp}")

            else:
                click.secho("✗ Request DENIED", fg="red")
                click.echo("\nReasons:")
                for reason in result.decision.reasons:
                    click.echo(f"  - {reason}")

    except DataFenceError as e:
        click.secho(f"✗ DataFence error: {e}", fg="red")
        sys.exit(1)
    except Exception as e:
        click.secho(f"✗ Error: {e}", fg="red")
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--framework", "-f", type=click.Choice(["openai", "claude"]), required=True)
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
def export(policy_file: str, framework: str, output: str | None):
    """
    Export policy as framework-specific schemas.

    Generates OpenAI function schemas or Claude tool schemas from policy.

    Example:
        datafence export policy.yaml --framework openai
        datafence export policy.yaml -f claude -o tools.json
    """
    try:
        # Create temporary connector
        conn = MemoryConnector(data={})
        fence = DataFence.from_yaml(policy_file, conn)

        if framework == "openai":
            from datafence.integrations.openai_adapter import OpenAIAdapter

            adapter = OpenAIAdapter(fence)
            schemas = adapter.get_functions()

        elif framework == "claude":
            from datafence.integrations.anthropic_adapter import ClaudeAdapter

            adapter = ClaudeAdapter(fence)
            schemas = adapter.get_tools()

        else:
            click.secho(f"✗ Unknown framework: {framework}", fg="red")
            sys.exit(1)

        output_json = json.dumps(schemas, indent=2)

        if output:
            with open(output, "w") as f:
                f.write(output_json)
            click.secho(f"✓ Exported to {output}", fg="green")
        else:
            click.echo(output_json)

    except ImportError as e:
        click.secho(f"✗ Missing dependency: {e}", fg="red")
        click.echo("Install with: pip install 'datafence[integrations]'")
        sys.exit(1)
    except Exception as e:
        click.secho(f"✗ Error: {e}", fg="red")
        sys.exit(1)


@cli.command()
@click.option("--output", "-o", type=click.Path(), default="policy.yaml")
def init(output: str):
    """
    Create a sample policy file.

    Example:
        datafence init
        datafence init --output my-policy.yaml
    """
    sample_policy = """version: "1"

policy:
  name: sample-policy
  description: Sample DataFence policy

  resources:
    users:
      operations:
        allow: [read]
        deny: [insert, update, delete]
      
      fields:
        allow:
          - id
          - email
          - name
          - created_at
        deny:
          - password_hash
          - ssn
      
      row_filters:
        tenant_id: "{{ actor.tenant_id }}"
      
      limits:
        max_rows: 100
        max_date_range_days: 30

  actors:
    agent:
      type: agent
      description: AI agent with read-only access
"""

    try:
        if Path(output).exists():
            if not click.confirm(f"File {output} exists. Overwrite?"):
                click.echo("Aborted.")
                sys.exit(0)

        with open(output, "w") as f:
            f.write(sample_policy)

        click.secho(f"✓ Created sample policy: {output}", fg="green")
        click.echo("\nNext steps:")
        click.echo(f"  1. Edit {output} to match your needs")
        click.echo(f"  2. Validate: datafence validate {output}")
        click.echo(f"  3. Test: datafence test {output} request.json")

    except Exception as e:
        click.secho(f"✗ Error: {e}", fg="red")
        sys.exit(1)


def main():
    """Entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()
