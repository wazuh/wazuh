## engine-kvdb

The `engine-kvdb` tool is a command-line interface that allows you to manage key-value databases in the Wazuh engine. It provides the ability to list, create, update, and delete key-value databases. The tool is part of the `engine-suite` package.

## Directory structure

The `engine-kvdb` tool is located in the `engine_kvdb` directory of the `engine-suite` package. The directory structure is as follows:

```
engine_kvdb/
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
engine-kvdb --version
```

## Usage

```console
usage: engine-kvdb [-h] [--version] [--api-socket API_SOCKET] {list,create,delete,dump,get,search,remove,upsert} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket

subcommands:
  {list,create,delete,dump,get,search,remove,upsert}
    list                List all key-value databases
    create              Create a new key-value database
    delete              Remove a key-value database
    dump                Dump all key-value databases
    get                 Get a key-value pair from the database
    search              Get filtered key-value pairs from the database
    remove              Remove a pair key-value in the database
    upsert              Insert or update a key-value in the database
```
