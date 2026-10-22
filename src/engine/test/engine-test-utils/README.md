# Engine test utils

A Python library with utilities for the engine test tools (`engine-it`, `engine-helper-test`) and
`engine-bench`. Its main module, `engine_handler`, starts and stops an engine process configured from a
`.env` file.

## Installation

From `src/engine/`, after `tools/api-communication` (a dependency that is not published):

```bash
pip install tools/api-communication
pip install test/engine-test-utils
```

## Engine handler

### Usage

Create an `EngineHandler` with the path of the engine binary and of the configuration file, start the
engine, use it through its API client, and stop it.

```py
from engine_handler.handler import EngineHandler
from api_communication.proto import router_pb2 as api_router

engine_handler = EngineHandler("path/to/wazuh-engine", "path/to/config.env")

# Start the Engine (foreground, with the configuration exported as environment variables)
engine_handler.start()

# Do something with the Engine: the API client is available through the handler
error, response = engine_handler.api_client.send_recv(api_router.TableGet_Request())

# Stop the Engine
engine_handler.stop()
```

- The constructor takes an optional third argument, a dictionary of variables that override the file's.
  It raises `KeyError` when the configuration has no `WAZUH_SERVER_API_SOCKET`, which the API client uses.
- `start(log_file_path="")` exports every variable, runs `<binary> -f` with the binary's directory as the
  working directory (the home in standalone mode), and waits until the API answers a router table request
  (10 attempts, 2 seconds apart; on exhaustion it stops the engine and raises). With `log_file_path`, the
  engine's stdout and stderr go to that file.
- `stop()` terminates the process, waits for it, and removes the exported variables.
- `get_pid()` returns the engine's process id.

The configuration file is a `.env` file with one `NAME=value` per line; empty lines and lines starting with
`#` are ignored:

```env
WAZUH_ENGINE_STANDALONE=true
WAZUH_SERVER_API_SOCKET=/tmp/engine/queue/sockets/engine-api-http.sock
```

The variables the engine reads are registered in `Conf::Conf` in `src/engine/source/conf/src/conf.cpp`. The
test suites ship their own (`test/integration_tests/configuration_files/config.env`,
`test/helper_tests/configuration_files/config.env`), which their `init` subcommands copy into the test
environment.

## API utils

The `api_utils` module (`src/api_utils/commands.py`) imports protobuf modules that `api-communication` no
longer ships (`policy_pb2`, `catalog_pb2`), so importing it fails. No tool uses it.
