## engine-event-dumper

The `engine-event-dumper` script is part of the `engine-suite` package. It turns on and off, at runtime, the
engine's event dumper, which writes the raw body of every batch received on `POST /events/enriched` to rotating
files (see the [dumper module README](../../../../source/dumper/README.md) for where they go).

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

(from `src/engine/`, after installing `tools/api-communication`; see the
[engine-suite installation](../../README.md#installation)).

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

`--api-socket` defaults to `/var/wazuh-manager/queue/sockets/engine-api-http.sock`. The commands call the
engine's `_internal/event-dumper/activate`, `_internal/event-dumper/deactivate` and
`_internal/event-dumper/status` endpoints. `status` prints `active` or `inactive`; `activate` and `deactivate`
print nothing on success. On an error every command prints it and exits 1.
