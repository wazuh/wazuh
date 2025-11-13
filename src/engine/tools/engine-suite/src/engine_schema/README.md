# Engine schema tool
The engine uses a schema to define and standardize the structure of the data it processes, ensuring consistency and accuracy in event categorization and normalization. The `engine-schema` tool facilitates the update of the schema version, allowing seamless integration of new data formats and changes.

1. [Directory structure](#directory-structure)
2. [Install](#install)
3. [Usage](#usage)

## Install
The script is packaged along the engine-suite python packaged, to install simply run:
```bash
pip install wazuh/src/engine/tools/engine-suite
```
To verify it's working:
```bash
engine-schema --version
```

## Usage
```bash
╰─# engine-schema --help
usage: engine-schema [-h] [--version] {generate} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

subcommands:
  {generate}
    generate            Generate the schema and associated configuration
```

```bash
$ engine-schema generate --help
usage: engine-schema generate [-h] --wcs-path WCS_FILE_PATH [--output-dir OUTPUT_DIR] --allowed-fields-path ALLOWED_FIELDS_PATH
                              [--types-output TYPES_OUTPUT]

options:
  -h, --help                   show this help message and exit
  --wcs-path WCS_FILE_PATH     Path to the WCS flat schema YAML file
  --output-dir OUTPUT_DIR      [default="./"] Root directory to store generated files
  --allowed-fields-path ALLOWED_FIELDS_PATH
                               Path to the allowed fields JSON file used to filter the generated schema
  --types-output TYPES_OUTPUT  Optional path to write the list of ECS field types
```

```bash
$ engine-schema generate --wcs-path ./wcs_flat.yml --allowed-fields-path ./allowed-fields.json --output-dir /tmp/schema_update \
    --types-output src/engine/ruleset/schemas/ecs_types.json
Loading resources...
Loading WCS file from ./wcs_flat.yml...
Loading schema template...
Loading mappings template...
Loading logpar overrides template...
Building field tree from WCS definition...
Success.
Generating engine schema...
Generating fields schema properties...
Success.
Generating indexer mappings...
Success.
Generating logpar configuration...
Success.
Saving files to "/tmp/schema_update"...
Updated "src/engine/ruleset/schemas/ecs_types.json" with 11 field types.
Success.
```
It will output the following files under the specified directory (working directory by default):
- `engine-schema.json`: Schema configuration for the engine module.
- `fields_decoder.json`: Contains the Visual Code schema for the decoders.
- `fields_rule.json`: Contains the Visual Code schema for the rules.
- `wazuh-logpar-types.json`: Configuration for the engine parser module.
- `wazuh-template.json`: Configuration for the Wazuh indexer.
- `ecs_types.json`: Ordered list of field types present in the generated schema (only produced when `--types-output` is supplied).

We must format the documents and replace them in their respective folders:
- engine-schema.json -> wazuh/src/engine/ruleset/schemas/engine-schema.json
- fields_decoder.json -> wazuh/src/engine/ruleset/schemas/fields_decoder.json
- fields_rule.json -> wazuh/src/engine/ruleset/schemas/fields_rule.json
- wazuh-logpar-types.json -> wazuh/src/engine/ruleset/schemas/wazuh-logpar-types.json
- wazuh-template.json -> wazuh/src/engine/extension/elasticsearch/7.x/wazuh-template.json
