## engine-policy

The `engine-policy` tool is a command-line interface that allows you to manage policies in the Wazuh engine. It provides the ability to list, create, update, and delete policies. The tool is part of the `engine-suite` package.

## Directory structure

The `engine-policy` tool is located in the `engine_policy` directory of the `engine-suite` package. The directory structure is as follows:

```
engine_policy/
├── README.md
├── cmds # Command modules
│   ├── __init__.py
│   ├── ...
|   └── ...
├── __main__.py # Main script
```


## Installation


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
usage: engine-policy [-h] [--version] [--api-socket API_SOCKET] {create,delete,get,list,asset-add,asset-remove,asset-list,asset-clean-deleted,parent-set,parent-remove,namespace-list} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket

subcommands:
  {create,delete,get,list,asset-add,asset-remove,asset-list,asset-clean-deleted,parent-set,parent-remove,namespace-list}
    create              Create a new, empty policy
    delete              Remove a policy
    get                 Get a policy
    list                List all policies
    asset-add           Add an asset to a policy
    asset-remove        Remove an asset to a policy
    asset-list          List all assets in a policy
    asset-clean-deleted
                        Remove all deleted assets from a policy
    parent-set          Set the default parent for assets under a specific namespace
    parent-remove       Remove the default parent for assets under a specific namespace
    namespace-list      List all namespaces included in a policy
```
