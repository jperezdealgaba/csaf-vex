"""CLI entrypoint for csaf-vex."""

import json
from pathlib import Path

import click

from csaf_vex.models import CSAFVEXDocument


@click.group()
def main():
    """CSAF VEX file manipulation tool."""
    pass


@main.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--verify/--no-verify", default=True, help="Enable/disable verification")
def read(file: Path, verify: bool):
    """Read and parse a CSAF VEX JSON file."""
    try:
        with file.open() as f:
            data = json.load(f)

        csaf_vex = CSAFVEXDocument.from_dict(data, verify=verify)

        click.echo(f"Successfully read CSAF VEX file: {file}")
        click.echo(f"Document: {csaf_vex.document}")
        click.echo(f"Product tree entries: {len(csaf_vex.product_tree)}")
        click.echo(f"Vulnerabilities: {len(csaf_vex.vulnerabilities)}")

    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {file}: {e}") from None
    except Exception as e:
        raise click.ClickException(f"Error reading file {file}: {e}") from None


if __name__ == "__main__":
    main()
