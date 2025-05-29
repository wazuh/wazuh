# Engine integration tool
This tool facilitates working with integrations in the Engine. Helps in the creation, documentation, and in managing the integration assets in the catalog.

## Installation
The script is packaged along the engine-suite python packaged, to install simply run:
```bash
pip install wazuh/src/engine/tools/engine-suite
```
To verify it's working:
```bash
engine-integration --version
```

## Usage
```console
$ engine-integration -h
usage: engine-integration [-h] [--version] [-v]
                          {create,generate-doc,generate-graph,generate-manifest,add,delete,update}
                          ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -v, --verbose         Print traceback on error messages

subcommands:
  {create,generate-doc,generate-graph,generate-manifest,add,delete,update}
    create              Create a new integration project scaffold on the current
                        directory
    generate-doc        Generate documentation for the integration, must be run
                        from the integration directory
    generate-graph      Generate dot graph for the integration, must be run from
                        the integration directory
    generate-manifest   Generate the manifest file of all assets of the
                        currentintegration. Name of the integration is taken
                        from the name of thedirectory used
    add                 Add integration components to the Engine Catalog. If a
                        step fails it will undo the previous ones
    delete              Delete integration assets from the Engine Catalog. If a
                        step fails it continue with the next
    update              Updates all available intgration components, deletes if
                        no longer present, adds when new.
```

### Create scaffolding
The create subcommand will set up the directory for the integration on the current folder.
```
$ engine-integration create -h
usage: engine-integration create [-h] name

positional arguments:
  name        Name of the integration

options:
  -h, --help  show this help message and exit
```

### Generate documentation
Generates the README.md for the integration based on the assets listed in the manifest and the documentation.yml file.
```
$ engine-integration generate-doc -h
usage: engine-integration generate-doc [-h]

options:
  -h, --help  show this help message and exit
```

### Generate graph (dot format)
Generates the graphs for the different assets.
```
$ engine-integration generate-graph -h
usage: engine-integration generate-graph [-h] {decoders,rules,outputs}

positional arguments:
  {decoders,rules,outputs}
                        Component type to generate the graph

options:
  -h, --help            show this help message and exit
```

### Add the integration to the Engine
Adds the integration assets and mappings to the Engine's catalog.
```
$ engine-integration add -h
usage: engine-integration add [-h] [-a API_SOCK] [--dry-run] [-n NAMESPACE]
                              integration-path

positional arguments:
  integration-path      [default=current directory] Integration directory path

options:
  -h, --help            show this help message and exit
  -a API_SOCK, --api-sock API_SOCK
                        [default="/run/wazuh-server/engine-api.socket"] Engine
                        instance API socket path
  --dry-run             When set it will print all the steps to apply but wont
                        affect the store
  -n NAMESPACE, --namespace NAMESPACE
                        [default=user] Namespace to add the integration to
```

### Delete the integration from the Engine
Deletes assets listed in the integration and the integration from the Engine's catalog.
```
$ engine-integration delete -h
usage: engine-integration delete [-h] [-a API_SOCK] [--dry-run] [-n NAMESPACE]
                                 integration-path

positional arguments:
  integration-path      Integration path to be deleted

options:
  -h, --help            show this help message and exit
  -a API_SOCK, --api-sock API_SOCK
                        [default="/run/wazuh-server/engine-api.socket"] Engine
                        instance API socket path
  --dry-run             default False, When True will print all the steps to
                        apply without affecting the store
  -n NAMESPACE, --namespace NAMESPACE
                        [default="user"] Namespace of the integration
```

### Update the integration in the Engine
Updates changes in assets on the Engine's catalog.
```
$ engine-integration update -h
usage: engine-integration update [-h] [-a API_SOCK] [-p INTEGRATION-PATH]
                                 [--dry-run] [-n NAMESPACE]

options:
  -h, --help            show this help message and exit
  -a API_SOCK, --api-sock API_SOCK
                        [default="/run/wazuh-server/engine-api.socket"] Engine
                        instance API socket path
  -p INTEGRATION-PATH, --integration-path INTEGRATION-PATH
                        [default=current directory] Integration directory path
  --dry-run             When set it will print all the steps to apply but wont
                        affect the store
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace to add the integration to
```
