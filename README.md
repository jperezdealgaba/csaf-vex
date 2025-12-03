# csaf-vex

A Python library for generating, parsing, and validating CSAF VEX files.

## Installation

```bash
pip install csaf-vex
```

For development:

```bash
git clone https://github.com/RedHatProductSecurity/csaf-vex.git
cd csaf-vex
uv sync --dev
```

## Usage

### CLI

Read and parse a CSAF VEX file:

```bash
csaf-vex read tests/test_files/sample-vex.json
```

Disable verification:

```bash
csaf-vex read --no-verify tests/test_files/minimal-vex.json
```

### Python API

```python
from csaf_vex.models import CSAFVEXDocument

# Load from dictionary
with open("vex-file.json") as f:
    data = json.load(f)

csaf_vex = CSAFVEXDocument.from_dict(data)

# Access document metadata
print(csaf_vex.document.title)
print(csaf_vex.document.tracking_id)

# Access vulnerabilities and product tree
print(f"Vulnerabilities: {len(csaf_vex.vulnerabilities)}")
print(f"Products: {len(csaf_vex.product_tree)}")

# Disable verification
csaf_vex = CSAFVEXDocument.from_dict(data, verify=False)
```

## Development

### Running linter and formatter

```bash
# Check linting issues
uv run ruff check .

# Auto-fix linting issues
uv run ruff check --fix .

# Format code
uv run ruff format .
```

### Project Structure

- `src/csaf_vex/cli.py` - CLI entrypoint
- `src/csaf_vex/models/csafvex.py` - CSAFVEXDocument and Document classes
- `src/csaf_vex/validation/` - Validation logic (future)
- `src/csaf_vex/verification/` - Verification logic (future)
- `tests/test_files/` - Test CSAF VEX files
- `tests/` - Tests (future)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Authors

- Jakub Frejlach (jfrejlac@redhat.com)
- Juan Perez de Algaba (jperezde@redhat.com)
- George Vauter (gvauter@redhat.com)

Developed by Red Hat Product Security.
