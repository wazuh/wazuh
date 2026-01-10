# Engine Schema Tool

Standalone tool for generating engine schema and associated configuration files from Wazuh Common Schema (WCS).

## Installation

```bash
pip install -e .
```

It can also be used directly without the installation:

```bash
python3 engine_schema.py generate --output-dir /engine_schema_test --wcs-path "ecs_flat_1.yaml , ecs_flat_2.yaml" --decoder-template /path/to/wazuh-decoders.template.json
```

## Usage

```bash
# Using a single YAML file
engine-schema generate --wcs-path /path/to/wcs_flat.yml --output-dir ./output --decoder-template /path/to/wazuh-decoders.template.json

# Using a directory with multiple YAML files (they will be merged)
engine-schema generate --wcs-path /path/to/wcs_directory/ --output-dir ./output --decoder-template /path/to/wazuh-decoders.template.json

# Using a list of YAML files (they will be merged)
engine-schema generate --wcs-path "/path/to/wcs_directory/file_1.yaml , /path/to/wcs_directory/file_2.yaml" --output-dir ./output --decoder-template /path/to/wazuh-decoders.template.json
```

## Arguments

- `--wcs-path`: Path to the Wazuh Common Schema YAML file, directory containing YAML files or list of files separated by comma.
If a directory is provided, all .yml and .yaml files will be merged into a single schema without duplicated keys
- `--output-dir`: Root directory to store generated files (default: current directory)
- `--decoder-template`: Path to wazuh-decoders.json template file for fields injection
- `--types-output`: Optional path to write the list of ECS field types

## Generated Files

The tool generates the following files:
- `wazuh-decoders.json`: Unified decoder schema with all fields injected into the template
- `wazuh-logpar-overrides.json`: Logpar configuration overrides
- `engine-schema.json`: Engine schema definition
