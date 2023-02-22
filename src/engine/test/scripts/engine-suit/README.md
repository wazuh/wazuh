# Engine python suit tools

The `engine-suit` python package contains various scripts to help developing content for the Engine.

## Installation
Requires `python 3.8`, to install navigate where the Wazuh repository folder is located and run:
```
pip install wazuh/src/engine/test/scripts/engine-suit
```
If we want to install for developing and modifying the scripts, install in editable mode and the additional dev packages:
```
pip install -e wazuh/src/engine/test/scripts/engine-suit[dev]
```
**For developing we recommend to install it under a virtual environment.**

Once installed the scripts are available in the path:
```
engine-decoder  engine-schema  
```
## engine-schema
This script handles schema generation.

### Usage
```
$ engine-schema -h
usage: engine-schema [-h] [--version] {generate,integrate} ...

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

subcommands:
  {generate,integrate}
    generate            Generate the schema and associated configuration
    integrate           Generate the schema and associated configuration and apply them to an Engine
                        instance

```

For detailed help on each subcommand run 
```
engine-schema <subcommand> -h'
```

## engine-decoder
This script performs various tasks with the decoders Yaml files:
- list extracted fields

### Usage
```
$ engine-decoder -h
usage: engine-decoder [-h] [--version] {list-extracted} ...

optional arguments:
  -h, --help        show this help message and exit
  --version         show program's version number and exit

subcommands:
  {list-extracted}
    list-extracted  List all extracted fields from a decoder

```

For detailed help on each subcommand run 
```
engine-decoder <subcommand> -h'
```
