# Engine Test

1. [Summary](#summary)
2. [Directory Structure](#directory-structure)
3. [Installation](#installation)
4. [Usage](#usage)
    1. [engine-test add](#engine-test-add)
    2. [engine-test get](#engine-test-get)
    3. [engine-test list](#engine-test-list)
    4. [engine-test delete](#engine-test-delete)
    5. [engine-test create-config](#engine-test-create-config)
    6. [engine-test run and run-raw](#engine-test-run-and-run-raw)
    7. [engine-test session](#engine-test-session)

## Summary

The `engine-test` tool is used to test integrations: it sends events to a testing session of the engine
(`/_internal/tester/*` endpoints) and prints how the policy processed them, optionally with the trace of
every asset.

Events are described by an *integration configuration*, stored in a local JSON configuration file
(`-c/--config`, default `/etc/wazuh-manager/engine-test.conf`). Each integration names a **collect mode**,
which decides how the input is split into events, and optionally the queue byte and location that fill the
event header (the *template*). Events are read from standard input: interactively from a terminal, or the
whole input when it is piped.

# Directory structure

```plaintext
engine_test/
├── __main__.py                  # Argument parser and entry point
├── cmds/                        # One module per subcommand (add, get, list, delete, create, run, run_raw, session_*)
├── conf/                        # Configuration file store, integration configuration and event template
├── event_splitters/             # Input splitters per collect mode (single-line, multi-line, dynamic, eventchannel)
├── api_connector.py             # Tester API calls (session create/delete, run)
├── base_tester_integration.py   # Common runner logic
├── tester_integration.py        # `run`
├── raw_tester_integration.py    # `run-raw`
└── input_collector.py           # Reads events from the terminal or a pipe
```

# Installation

The script is packaged along the engine-suite python package (see the
[engine-suite installation](../../README.md#installation)). From `src/engine/`:
```bash
pip install tools/engine-suite
```
To verify it's working:
```bash
engine-test --version
```

# Usage

```bash
usage: engine-test [-h] [-c CONFIG_FILE] [-v] {run,run-raw,add,get,list,delete,create-config,session} ...

options:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config CONFIG_FILE
                        Configuration file. Default: /etc/wazuh-manager/engine-test.conf
  -v, --version         show program's version number and exit

subcommands:
  {run,run-raw,add,get,list,delete,create-config,session}
    run                 Run test on an integration. It can only work if the integration has a template.
    run-raw             Allows testing raw events. It can work with or without a template in the
                        integration.
    add                 Add integration
    get                 Get integration configuration
    list                List integration configurations
    delete              Delete integration configuration
    create-config       Creates a new empty configuration file, if not exists
    session             Session manager
```

The default configuration file lives in `/etc/wazuh-manager` (root:wazuh-manager 0770), so writing it needs
root or the `wazuh-manager` group; pass `-c` to use a file elsewhere.

## engine-test add

```bash
usage: engine-test add [-h] -i INTEGRATION_NAME -c
                       {single-line,multi-line,dynamic-multi-line,windows-eventchannel} [-q QUEUE]
                       [-o LOCATION] [-l LINES]

options:
  -h, --help            show this help message and exit
  -i INTEGRATION_NAME, --integration-name INTEGRATION_NAME
                        Integration to test name
  -c {single-line,multi-line,dynamic-multi-line,windows-eventchannel}, --collect-mode {single-line,multi-line,dynamic-multi-line,windows-eventchannel}
                        Collect mode in which events should be handled by engine-test.
  -q QUEUE, --queue QUEUE
                        Queue number representing the queue byte in the protocol
  -o LOCATION, --location LOCATION
                        Name of the collector, source of data (i.g. file, windows-eventlog, journald, macos-
                        uls)
  -l LINES, --lines LINES
                        Fixed number of lines for each event. Only for multi-line collect mode.
```

`-l` is required with `multi-line`. `-q` and `-o` must be given together; when both are omitted they default
per collect mode (`conf/integration.py`): queue `1` and location `file`, or queue `f` and location
`windows-eventlog` for `windows-eventchannel`. The configuration file is created if it does not exist.

```bash
engine-test add -i apache-access -c single-line
```

## engine-test get

```bash
usage: engine-test get [-h] [-j] integration-name
```

Prints an integration configuration, as YAML or, with `-j`, JSON.

## engine-test list

```bash
usage: engine-test list [-h] [-d] [-j]
```

Lists the integration configurations; `-d` prints every field, `-j` prints JSON.

## engine-test delete

```bash
usage: engine-test delete [-h] integration-name
```

## engine-test create-config

```bash
usage: engine-test create-config [-h]
```

Creates an empty configuration file (`{}`, mode 0640) if it does not exist.

## engine-test run and run-raw

```bash
usage: engine-test run [-h] [--api-socket API-SOCKET] [--output OUTPUT_FILE]
                       [-n NAMESPACEID | -s SESSION_NAME] [-d | -dd] [-t ASSETS [ASSETS ...]] [-j]
                       integration-name

positional arguments:
  integration-name      Integration name

options:
  -h, --help            show this help message and exit
  --api-socket API-SOCKET
                        Socket to connect to the API
  --output OUTPUT_FILE  Output file where the events will be stored, if empty events wont be saved
  -n NAMESPACEID, --namespace NAMESPACEID
                        Namespace where to run the test. A temporary test session will be created and
                        deleted when the command is completed.
  -s SESSION_NAME, --session-name SESSION_NAME
                        Session where to run the test
  -d, --debug           Log asset history
  -dd, --full-debug     Log asset history and full tracing
  -t ASSETS [ASSETS ...], --trace ASSETS [ASSETS ...]
                        List of assets to filter trace
  -j, --json            Allows the output and trace generated by an event to be printed in Json format.
```

`run-raw` takes the same options. `run` needs an integration with a template (queue and location);
`run-raw` sends the raw events with or without one. `--api-socket` defaults to
`/var/wazuh-manager/queue/sockets/engine-api-http.sock` and `-n` to the `testing` namespace.

```bash
echo '127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET / HTTP/1.1" 200 2326' | engine-test run apache-access -n standard -d
```

## engine-test session

```bash
usage: engine-test session [-h] [--api-socket API_SOCKET] {list,get,add,delete,reload,delete-all} ...

session commands:
  {list,get,add,delete,reload,delete-all}
    list                List all sessions
    get                 Get information about a session
    add                 Add a new session for testing
    delete              Delete a session for testing
    reload              Reload a session for testing (rebuild the policy)
    delete-all          Delete all sessions
```

- `session list [-j]` and `session get [-j] name` print YAML or, with `-j`, JSON.
- `session add name namespaceId [description]` creates a session on a namespace.
- `session delete name`, `session reload name`.
- `session delete-all [-o]`: with `-o/--only-engine-tests`, only the sessions whose name starts with
  `engine_test_`.
