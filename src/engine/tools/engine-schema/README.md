# Engine Schema Tool

Standalone tool for generating engine schema and associated configuration files from Wazuh Common Schema (WCS).

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Using a single YAML file
engine-schema generate --wcs-path /path/to/wcs_flat.yml --output-dir ./output --allowed-fields-path /path/to/allowed_fields.json

# Using a directory with multiple YAML files (they will be merged)
engine-schema generate --wcs-path /path/to/wcs_directory/ --output-dir ./output --allowed-fields-path /path/to/allowed_fields.json
```

## Arguments

- `--wcs-path`: Path to the Wazuh Common Schema YAML file or directory containing YAML files. If a directory is provided, all .yml and .yaml files will be merged into a single schema without duplicated keys
- `--output-dir`: Root directory to store generated files (default: current directory)
- `--allowed-fields-path`: Path to the allowed fields JSON file used to filter the generated schema
- `--types-output`: Optional path to write the list of ECS field types

## Generated Files

The tool generates the following files:
- `fields_decoder.json`: Schema for decoder fields
- `fields_rule.json`: Schema for rule fields
- `wazuh-logpar-overrides.json`: Logpar configuration overrides
- `engine-schema.json`: Engine schema definition