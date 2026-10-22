# Engine python suite tools

1. [Summary](#summary)
2. [Directory structure](#directory-structure)
    1. [Engine router](#engine-router)
    1. [Engine test](#engine-test)
    1. [Engine event dumper](#engine-event-dumper)
    1. [Engine public](#engine-public)
    1. [Engine private](#engine-private)
3. [Installation](#installation)

## Summary

The `engine-suite` python package contains command-line tools that talk to the engine
(`wazuh-manager-analysisd`) over its HTTP API socket, through the [api-communication](../api-communication/README.md)
library. Every tool takes `--api-socket` (`engine-test` takes it on its `run`, `run-raw` and `session`
subcommands), defaulting to `/var/wazuh-manager/queue/sockets/engine-api-http.sock`
(`src/shared/default_settings.py`). They are development and testing tools: none is installed with the
manager.

# Directory structure

```plaintext
engine-suite/
├── setup.cfg               # Package metadata and console_scripts entry points
└── src/
    ├── engine_event_dumper/
    ├── engine_private/
    ├── engine_public/
    ├── engine_router/
    ├── engine_test/
    └── shared/             # Default settings, payload loaders and output dumpers
```

## Engine router

Route management on the engine's router (`_internal/router/*` endpoints):

- `list`: Get the routes table.
- `get <route>`: Get a route's details.
- `add <route> <priority> <policy> [-d DESCRIPTION]`: Create a route.
- `update <route> --priority PRIORITY`: Change a route's priority (the only field it can update).
- `reload <route>`: Rebuild a route.
- `delete <route>`: Delete a route.
- `ingest <event>`: Present in the parser, but `api-communication` maps no endpoint to its request
  (`QueuePost_Request`), so it always fails.

For more details, refer to [src/engine_router/README.md](src/engine_router/README.md).

## Engine test

- **Integration configurations**: `add`, `get`, `list` and `delete` manage the local configuration file of
  integrations under test (each integration names a collector type: `single-line`, `multi-line`,
  `dynamic-multi-line` or `windows-eventchannel`); `create-config` writes a default configuration file.
- **Test execution**: `run` and `run-raw` send events read from standard input to a testing session (or a
  namespace) and print the output, optionally with the trace through the assets of the policy.
- **Testing sessions**: `session list|get|add|delete|reload|delete-all` manage the engine's tester sessions.

For more details, refer to [src/engine_test/README.md](src/engine_test/README.md).

## Engine event dumper

- **Event Dumper Management**: Activates, deactivates, and reports the status of the engine's internal event
  dumper (`activate`, `deactivate`, `status`).

For more details, refer to [src/engine_event_dumper/README.md](src/engine_event_dumper/README.md).

## Engine public

- **Content Validation**: Validates a full policy (`cm policy-validate`) or a single resource (`cm validate`)
  against the engine, optionally loading a validated policy into a testing session.
- **Logtest Cleanup**: Removes the logtest testing session and its temporary namespace (`logtest cleanup`).
- **IOC**: Reports the IOC databases' state (`ioc state`) and schedules an IOC synchronization from an ndjson
  file (`ioc update`).
- **Engine Status**: Reports whether the engine has all required resources available to process events
  (`status get`).

For more details, refer to [src/engine_public/README.md](src/engine_public/README.md).

## Engine private

- **Namespace Management** (`ns`): `list`, `create`, `delete` and `import` namespaces.
- **Content Manager CRUD** (`cm -n SPACE`): `list`, `get`, `upsert` and `delete` resources, and
  `policy-upsert`/`policy-delete` the policy, within a namespace.
- **Geo** (`geo`): `get` the GeoIP/ASN data of an IP, and `list` the loaded databases.
- **Raw Event Indexer** (`rawevt`): `status` of the raw event indexer.

These are internal-only operations (`_internal/*` endpoints), not intended for use outside development and
testing.

# Installation

Requires Python 3.8 or newer and `pip3`. The package depends on `api-communication`, which is not
published: install it first. From `src/engine/`:

```bash
pip3 install tools/api-communication
pip3 install tools/engine-suite
```

To install for developing and modifying the scripts, install in editable mode with the additional dev packages:

```bash
pip3 install -e tools/engine-suite[dev]
```

**For developing we recommend to install it under a virtual environment.**

Once installed the following scripts are available in the path (`[options.entry_points]` in `setup.cfg`):
- [engine-router](src/engine_router/README.md)
- [engine-test](src/engine_test/README.md)
- [engine-event-dumper](src/engine_event_dumper/README.md)
- [engine-public](src/engine_public/README.md)
- `engine-private` (no README; see `src/engine_private/__main__.py` and `src/engine_private/cmds/`)
