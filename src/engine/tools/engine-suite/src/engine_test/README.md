# Engine Test

1. [Summary](#summary)
2. [Directory Structure](#directory-structure)
    1. [CMD](#cmd)
    2. [Formats](#formats)
3. [Installation](#installation)
4. [Usage](#usage)
    1. [engine-test add](#engine-test-add)
    2. [engine-test delete](#engine-test-delete)
    3. [engine-test get](#engine-test-get)
    4. [engine-test run](#engine-test-run)

## Summary
The `engine-test` tool, is used to test integrations, it allows test a policy,
simulate an agent and send events to the engine. The tool allows to simulate the
data sent by an agent, for this it makes use of a specific configuration to fill
in the agent's metadata. This configuration is called integration configuration,
and it contains information about how the log was collected (metadata). Then the
use of the interactive console to send logs along with that metadata, simulating
the agent's log sending.

# Directory structure

```plaintext
├── engine-suite/
│   └── cmd/
│   └── formats/
│   └── __init__.py
│   └── __main__.py
│   └── api_connector.py
│   └── command.py
│   └── config.py
│   └── crud_integration.py
│   └── event_format.py
│   └── events_collector.py
│   └── integration.py
│   └── parse.py
```

## CMD
Contains the commands to add, remove and get integrations. It also adds the command to use one of the integrations along with a session to insert events and test decoders and rules

## Formats
Contains the different formats of handled events, such as syslog, json, macos, eventchannel, multiline etc.

# Install
The script is packaged along the engine-suite python packaged, to install simply run:
```bash
pip install wazuh/src/engine/tools/engine-suite
```
To verify it's working:
```bash
engine-test --version
```

# Usage

```bash
usage: engine-test [-h] [-c CONFIG_FILE] [-v] {run,add,get,list,delete} ...

options:
  -h, --help            show this help message and exit
  -c CONFIG_FILE, --config CONFIG_FILE
                        Configuration file. Default: /var/ossec/etc/engine-test.conf
  -v, --version         show program's version number and exit

subcommands:
  {run,add,get,list,delete}
    run                 Run integration
    add                 Add integration
    get                 Get integration
    list                List of integrations
    delete              Delete integration
```

## engine-test add
```bash
usage: engine-test add [-h] [-i INTEGRATION_NAME | --from-file FROM_FILE]
                       [-f {audit,command,eventchannel,full-command,json,macos,multi-line,syslog,remote-syslog}] [-o ORIGIN] [-l LINES]

options:
  -h, --help            show this help message and exit
  -i INTEGRATION_NAME, --integration-name INTEGRATION_NAME
                        Integration to test name
  --from-file FROM_FILE
                        Add all integrations from the file to current configuration
  -f {audit,command,eventchannel,full-command,json,macos,multi-line,syslog,remote-syslog}, --format {audit,command,eventchannel,full-command,json,macos,multi-line,syslog,remote-syslog}
                        Format of integration.
  -o ORIGIN, --origin ORIGIN
                        Origin of integration.
  -l LINES, --lines LINES
                        Number of lines. Only for multi-line format.

```

## engine-test delete
```bash
usage: engine-test delete [-h] integration-name

positional arguments:
  integration-name  Integration name

options:
  -h, --help        show this help message and exit
```

## engine-test get
```bash
usage: engine-test get [-h] integration-name

positional arguments:
  integration-name  Integration name

options:
  -h, --help        show this help message and exit
```

## engine-test run
```bash
usage: engine-test run [-h] [--agent-id AGENT_ID] [--api-socket API-SOCKET] [--agent-name AGENT_NAME] [--agent-ip AGENT_IP] [-o ORIGIN] [--output OUTPUT_FILE]
                       [-n NAMESPACES [NAMESPACES ...]] [-p POLICY | -s SESSION_NAME] [-d | -dd] [-t ASSETS [ASSETS ...]] [-j]
                       integration-name

positional arguments:
  integration-name      Integration name

options:
  -h, --help            show this help message and exit
  --agent-id AGENT_ID   Agent ID for event filling
  --api-socket API-SOCKET
                        Socket to connect to the API
  --agent-name AGENT_NAME
                        Agent name for events filling
  --agent-ip AGENT_IP   Register agent ip for events filling
  -o ORIGIN, --origin ORIGIN
                        Origin of the integration
  --output OUTPUT_FILE  Output file where the events will be stored, if empty events wont be saved
  -n NAMESPACES [NAMESPACES ...], --namespaces NAMESPACES [NAMESPACES ...]
                        List of namespaces to include
  -p POLICY, --policy POLICY
                        Policy where to run the test. A temporary test session will be created and deleted when the command is completed.
  -s SESSION_NAME, --session-name SESSION_NAME
                        Session where to run the test
  -d, --debug           Log asset history
  -dd, --full-debug     Log asset history and full tracing
  -t ASSETS [ASSETS ...], --trace ASSETS [ASSETS ...]
                        List of assets to filter trace
  -j, --json            Allows the output and trace generated by an event to be printed in Json format.
```
