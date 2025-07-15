# Engine clear tool
Is a command line tool for managing and clearing resources in an engine management system.

1. [Directory structure](#directory-structure)
1. [Install](#install)
1. [Usage](#usage)

# Directory structure

```bash
├── engine_clear/
|   └── __init__.py
|   └── __main__.py
```

## Install
The script is packaged along the engine-suite python packaged, to install simply run:
```bash
￼pip install tools/engine-suite
```
￼To verify it's working:
```bash
￼engine-clear --version
```

## Usage
```bash
usage: engine-clear [-h] [--version] [--api-sock API_SOCK] [-f, --force] [-n, --namespaces [NAMESPACES ...]] [resources ...]

positional arguments:
  resources             Resources to clear. Default:['kvdbs', 'decoder', 'rule', 'output', 'filter', 'integration', 'policy']

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-sock API_SOCK   Path to the engine-api socket
  -f, --force           Force the execution of the command
  -n, --namespaces [NAMESPACES ...]
                        Namespace to delete the resources from. Default:['user', 'wazuh', 'system']
```
