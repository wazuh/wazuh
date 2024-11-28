## engine-geo

The `engine-geo` script is part of the `engine-suite` package. It is a tool that allows you to manage the GeoIP database. It provides the ability to download, update, and delete the GeoIP database.

## Directory structure

```bash
├── engine_geo/
|   └── cmds
|       └── __init__.py
|       └── ...
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
engine-geo --version
```

## Usage

```bash
usage: engine-geo [-h] [--version] [--api-socket API_SOCKET] {add,delete,list,remote-upsert} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket

subcommands:
  {add,delete,list,remote-upsert}
    add                 Add a GeoIP database
    delete              Remove a GeoIP database
    list                List all GeoIP databases in use by the manager
    remote-upsert       Download and update a GeoIP database from a remote URL
```

