## engine-router

The `engine-router` tool is a command-line interface that allows you to manage routes in the Wazuh engine. It provides the ability to list, create, update, and delete routes. The tool is part of the `engine-suite` package.

## Directory structure

The `engine-router` tool is located in the `engine_router` directory of the `engine-suite` package. The directory structure is as follows:

```
engine_router/
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
engine-router --version
```

## Usage

```console

usage: engine-router [-h] [--version] [--api-socket API_SOCKET] {get,delete,add,reload,update,list,ingest,eps-get,eps-enable,eps-disable,eps-update} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket

subcommands:
  {get,delete,add,reload,update,list,ingest,eps-get,eps-enable,eps-disable,eps-update}
    get                 Get a route details
    delete              Delete a route
    add                 Add a route
    reload              Reload/rebuild a route
    update              Update a route. it only supports the update of the priority
    list                Get routes table
    ingest              Ingest an event
    eps-get             Get EPS status on the engine
    eps-enable          Enable EPS on the engine
    eps-disable         Disable EPS on the engine
    eps-update          Change EPS settings.
```
