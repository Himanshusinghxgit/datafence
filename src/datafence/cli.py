"""
DataFence CLI tool.

Command-line interface for policy validation, testing, and management.
"""

import json
import sys
from pathlib import Path

try:
    import click
    import yaml
except ImportError:
    click = None
    yaml = None

from datafence.core.policy import YAMLPolicyLoader


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
        with open(policy_file) as f:
            policy_dict = yaml.safe_load(f)

        # Parse with the canonical v1 policy loader.  Policy files are
        # intentionally validated without constructing a boundary; boundary
        # construction is where a concrete ResourceRegistry is required.
        policy = YAMLPolicyLoader.from_dict(policy_dict)

        click.secho("✓ Policy is valid", fg="green")

        if verbose:
            click.echo("\nPolicy Summary:")
            click.echo(f"  Name: {policy.name}")
            click.echo(f"  Version: {policy.version}")
            click.echo(f"  Resources: {len(policy.resources)}")

            for resource_name, resource_config in policy.resources.items():
                click.echo(f"\n  Resource: {resource_name}")
                click.echo(f"    Operations: {resource_config.actions}")
                click.echo(f"    Fields: {len(resource_config.allowed_fields)} allowed")
                click.echo(f"    Max rows: {resource_config.max_rows}")

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
        with open(policy_file) as f:
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
    """Report that the pre-v1 request runner is no longer supported."""
    raise click.ClickException(
        "The legacy request runner was removed in v1.0; use the typed boundary API."
    )


@cli.command()
@click.argument("policy_file", type=click.Path(exists=True))
@click.option("--framework", "-f", type=click.Choice(["openai", "claude"]), required=True)
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
def export(policy_file: str, framework: str, output: str | None):
    """Report that the pre-v1 schema exporter is no longer supported."""
    raise click.ClickException(
        "The legacy schema exporter was removed in v1.0; use an integration adapter."
    )


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
