## engine-event-dumper

The `engine-event-dumper` script is part of the `engine-suite` package. It is a tool that allows you to manage the event dumper in the Engine.

## Directory structure

```bash
├── engine_event_dumper/
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
engine-event-dumper --version
```

## Usage

```bash
usage: engine-event-dumper [-h] [--version] [--api-socket API_SOCKET] {activate,deactivate,status} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket

subcommands:
  {activate,deactivate,status}
    activate            Activate the event-dumper
    deactivate          Deactivate the event-dumper
    status              Get the event-dumper status
```
