# Engine Public

1. [Summary](#summary)
2. [Installation](#installation)
3. [Usage](#usage)
    1. [engine-public cm policy-validate](#engine-public-cm-policy-validate)
    2. [engine-public cm validate](#engine-public-cm-validate)
    3. [engine-public cm logtest-cleanup](#engine-public-cm-logtest-cleanup)

## Summary

The `engine-public` tool provides public-facing commands for validating policies and resources against the engine, and for cleaning up logtest sessions.

## Installation

The script is packaged along the engine-suite python package, to install simply run:
```bash
pip install wazuh/src/engine/tools/engine-suite
```
To verify it's working:
```bash
engine-public --version
```

## Usage

```bash
usage: engine-public [-h] [--version] [--api-socket API_SOCKET] {cm} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --api-socket API_SOCKET
                        Path to the Wazuh API socket

subcommands:
  {cm}
    cm                  Content Manager operations
```

### engine-public cm policy-validate

Validates a full policy payload (policy + resources) against the engine. When `--load-in-tester` is used, the validated policy is loaded into a testing session so you can run events against it with `POST /logtest`.

```bash
engine-public cm policy-validate --load-in-tester < policy.json
```

### engine-public cm validate

Validates a single resource payload against the engine.

```bash
engine-public cm validate < resource.json
```

### engine-public cm logtest-cleanup

Removes the active logtest testing session and its temporary namespace from storage. This is used to clean up after a `policy-validate --load-in-tester` call.

Safe to call when there is nothing to clean up (returns success).

```bash
engine-public cm logtest-cleanup
```

Calls `DELETE /logtest` on the engine API.
