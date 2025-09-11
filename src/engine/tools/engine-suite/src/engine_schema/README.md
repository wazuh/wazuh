# Engine schema tool
The engine uses a schema to define and standardize the structure of the data it processes, ensuring consistency and accuracy in event categorization and normalization. The `engine-schema` tool facilitates the update of the schema version, allowing seamless integration of new data formats and changes.

1. [Directory structure](#directory-structure)
2. [Install](#install)
3. [Usage](#usage)
    1. [Generate](#generate)
    2. [Integrate](#integrate)

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
$ engine-schema --help
usage: engine-schema [-h] [--version] {generate,integrate} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

subcommands:
  {generate,integrate}
    generate            Generate the schema and associated configuration
    integrate           Generate the schema and associated configuration and apply them to an Engine
                        instance
```

The tool has two subcommands:
- generate: Generates the associated files to be updated manually (intended for contributing).
- integrate: Automatically replaces the schema configuration files on the current Wazuh manager installation.

### Generate

```bash
╰─# engine-schema generate --help
usage: engine-schema generate [-h] [--ecs-version ECS_VERSION] [--output-dir OUTPUT_DIR] --allowed-fields-path ALLOWED_FIELDS_PATH
                              {integration} ...

options:
  -h, --help            show this help message and exit
  --ecs-version ECS_VERSION
                        [default="v8.17.0"] ECS version to use for the schema generation
  --output-dir OUTPUT_DIR
                        [default="./"] Root directory to store generated files
  --allowed-fields-path ALLOWED_FIELDS_PATH
                        Path to the allowed fields JSON file. It will be used to filter the generated schema.

subcommands:
  {integration}
    integration         Add schema integration fields
```

When updating the schema, specify the integration subcommand with the path to the Wazuh core integration so that Wazuh-specific fields are generated.

```bash
$ engine-schema generate --output-dir /tmp/schema_update integration engine/ruleset/wazuh-core/
Using target ECS version: v8.17.0
Loading resources...
Downloading https://raw.githubusercontent.com/elastic/ecs/v8.17.0/generated/ecs/ecs_flat.yml...
Loading schema template...
Loading mappings template...
Loading logpar overrides template...
Building field tree from ecs definition...
Success.
Generating engine schema...
Adding module engine/ruleset/wazuh-core/...
Loading resources...
Generating field tree...
Adding logpar overrides...
Merging module...
Adding to engine schema...
Success.
Generating fields schema properties...
Success.
Generating indexer mappings...
Success.
Generating logpar configuration...
Success.
Saving files to "/tmp/schema_update"...
Success.
```
It will output the following files under the specified directory (working directory by default):
- `engine-schema.json`: Schema configuration for the engine module.
- `fields.json`: Contains the Visual Code schema for the assets.
- `fields_decoder.json`: Contains the Visual Code schema for the decoders.
- `fields_rule.json`: Contains the Visual Code schema for the rules.
- `wazuh-logpar-types.json`: Configuration for the engine parser module.
- `wazuh-template.json`: Configuration for the Wazuh indexer.

We must format the documents and replace them in their respective folders:
- engine-schema.json -> wazuh/src/engine/ruleset/schemas/engine-schema.json
- fields_decoder.json -> wazuh/src/engine/ruleset/schemas/fields_decoder.json
- fields_rule.json -> wazuh/src/engine/ruleset/schemas/fields_rule.json
- wazuh-logpar-types.json -> wazuh/src/engine/ruleset/schemas/wazuh-logpar-types.json
- wazuh-template.json -> wazuh/src/engine/extension/elasticsearch/7.x/wazuh-template.json
