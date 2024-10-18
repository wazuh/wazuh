## engine-catalog

The `engine-catalog` script is part of the `engine-suite` package. It is a tool that allows you to manage the catalog of decoders, rules, and integrations. It provides the ability to list, add, update, and delete catalog items.

## Directory structure

```bash
├── engine_catalog/
|   └── cmds
|       └── __init__.py
|       └── add.py
|       └── delete.py
|       └── list.py
|       └── update.py
|   └── __init__.py
|   └── __main__.py
```

## Install

The script is packaged along the `engine-suite` python package. To install, simply run:

```bash
pip install tools/engine-suite
```

To verify it's working:

```bash
engine-catalog --version
```

## Usage

```console
engine-catalog [-h] [--version] [--api-socket API_SOCKET] [-n NAMESPACE] [--format {json,yml,yaml}] {delete,get,update,create,validate,load} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket
  -n NAMESPACE, --namespace NAMESPACE
                        Namespace to use for the catalog
  --format {json,yml,yaml}
                        Input/Output format

subcommands:
  {delete,get,update,create,validate,load}
    delete              delete asset-type[/asset-name[/version]]: Delete an asset or a collection.
    get                 Get asset-type[/asset-id[/item-version]]: Get an asset or list a collection.
    update              Update an asset.
    create              Create an asset.
    validate            validate an asset.
    load                Load item-type path: Tries to create and add all the items found in the path to the collection.
```
