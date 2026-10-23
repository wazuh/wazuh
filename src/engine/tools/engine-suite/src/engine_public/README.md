# Engine Public

1. [Summary](#summary)
2. [Installation](#installation)
3. [Usage](#usage)
    1. [engine-public cm policy-validate](#engine-public-cm-policy-validate)
    2. [engine-public cm validate](#engine-public-cm-validate)
    3. [engine-public logtest cleanup](#engine-public-logtest-cleanup)
    4. [engine-public ioc state](#engine-public-ioc-state)
    5. [engine-public ioc update](#engine-public-ioc-update)
    6. [engine-public status get](#engine-public-status-get)

## Summary

The `engine-public` tool calls the engine's public API endpoints: validating policies and resources,
cleaning up logtest sessions, managing the IOC databases and reporting the engine's readiness. The
endpoints are documented in the
[public API reference](../../../../../../docs/ref/modules/engine/public-api-reference.md).

## Installation

The script is packaged along the engine-suite python package (see [Installation](../../README.md#installation)).
From `src/engine/`:
```bash
pip install tools/engine-suite
```
To verify it's working:
```bash
engine-public --version
```

## Usage

```bash
usage: engine-public [-h] [--version] [--api-socket API_SOCKET] {cm,logtest,ioc,status} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket

subcommands:
  {cm,logtest,ioc,status}
    cm                  Content Manager operations
    logtest             Logtest operations
    ioc                 IOC (Indicator of Compromise) operations
    status              Engine readiness/status operations
```

`--api-socket` defaults to `/var/wazuh-manager/queue/sockets/engine-api-http.sock`. Every command exits
with a non-zero status and an error message when the request fails.

### engine-public cm policy-validate

```bash
usage: engine-public cm policy-validate [-h] [-c FULL_POLICY] -n SPACE [--load-in-tester]
```

Validates a full policy payload (policy + resources) against the engine, in the space given with
`-n/--space`. The payload is read from `-c/--full-policy` or, when omitted, from standard input, and must be
a JSON object. With `--load-in-tester`, the validated policy is loaded into a testing session so you can run
events against it with `POST /logtest`. Calls `POST /content/validate/policy`.

```bash
engine-public cm policy-validate -n standard --load-in-tester < policy.json
```

### engine-public cm validate

```bash
usage: engine-public cm validate [-h] [-c RESOURCE] type
```

Validates a single resource of the given `type` against the engine. The resource is read from
`-c/--resource` or, when omitted, from standard input, and must be a JSON object. Calls
`POST /content/validate/resource`.

```bash
engine-public cm validate decoder < resource.json
```

### engine-public logtest cleanup

```bash
usage: engine-public logtest cleanup [-h] -n SPACE
```

Removes the logtest testing session and its temporary namespace from storage. This is used to clean up after
a `policy-validate --load-in-tester` call. Calls `DELETE /logtest`.

```bash
engine-public logtest cleanup -n standard
```

### engine-public ioc state

```bash
usage: engine-public ioc state [-h] [-f {text,json}]
```

Prints the state of the IOC databases, as YAML (`text`, the default) or JSON. Calls
`GET /content/ioc/state`.

### engine-public ioc update

```bash
usage: engine-public ioc update [-h] [--hash HASH] path
```

Schedules an IOC synchronization from an ndjson file. The engine accepts only a regular file inside its IOC
input directory (`WAZUH_KVDB_IOC_INPUT_PATH`). Without `--hash` the tool computes the file's MD5 and sends it;
when it matches the stored hash the engine skips the synchronization and the tool prints the engine's message.
Calls `POST /content/ioc/update`.

### engine-public status get

```bash
usage: engine-public status get [-h] [-f {text,json}]
```

Reports whether the engine has all required resources available to process events: the global `ready` flag
plus the per-resource state of content-manager spaces, IOC databases and geo databases.

```bash
engine-public status get             # YAML output (default)
engine-public status get -f json     # JSON output
```

Calls `GET /status`.
