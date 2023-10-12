# Engine python suite tools

The `engine-suite` python package contains various scripts to help developing content for the Engine.

## Installation
Requires `python 3.8`, to install navigate where the Wazuh repository folder is located and run:
```
pip install wazuh/src/engine/tools/engine-suite
```
If we want to install for developing and modifying the scripts, install in editable mode and the additional dev packages:
```
pip install -e wazuh/src/engine/tools/engine-suite[dev]
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

## engine-test
This script allows you to send an event to the TEST command of the Engine API. The sending of events can be done interactively, through the CLI, or through an input file and have an output file as destination.

### Usage
```
$ engine-test -h
usage: engine-test [-h] [-c CONFIG_FILE] [-v] {run,add,get,list,delete,format} ...

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config CONFIG_FILE
                        Configuration file. Default: /var/ossec/etc/engine-test.conf
  -v, --version         show program's version number and exit

subcommands:
  {run,add,get,list,delete,format}
    run                 Run integration
    add                 Add integration
    get                 Get integration
    list                List of integrations
    delete              Delete integration
    format              Format integration
```

For detailed help on each subcommand run
```
engine-test <subcommand> -h'
```

## engine-clear
This script allows you to remove different resources from the engine.

### Usage
```
$ engine-clear -h
usage: engine-clear [-h] [--version] [--api-sock API_SOCK] [-f, --force] [-n, --namespaces [NAMESPACES [NAMESPACES ...]]] [resources [resources ...]]

positional arguments:
  resources             Resources to clear. Default:['kvdbs', 'decoder', 'rule', 'output', 'filter', 'integration', 'policy']

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-sock API_SOCK   Path to the engine-api socket
  -f, --force           Force the execution of the command
  -n, --namespaces [NAMESPACES [NAMESPACES ...]]
                        Namespace to delete the resources from. Default:['user', 'wazuh', 'system']
```

## engine-integration
This script allows you to manage the different integrations of the engine

### Usage
```
$ engine-integration -h
usage: engine-integration [-h] [--version] [-v] {create,generate-doc,generate-graph,generate-manifest,add,delete,update} ...

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Print traceback on error messages

subcommands:
  {create,generate-doc,generate-graph,generate-manifest,add,delete,update}
    create              Create a new integration project scaffold on the current directory
    generate-doc        Generate documentation for the integration, must be run from the integration directory
    generate-graph      Generate dot graph for the integration, must be run from the integration directory
    generate-manifest   Generate the manifest file of all assets of the currentintegration. Name of the integration is taken from the name of
                        thedirectory used
    add                 Add integration components to the Engine Catalog. If a step fails it will undo the previous ones
    delete              Delete integration assets from the Engine Catalog. If a step fails it continue with the next
    update              Updates all available intgration components, deletes if no longer present, adds when new.
```

For detailed help on each subcommand run
```
engine-integration <subcommand> -h'
```