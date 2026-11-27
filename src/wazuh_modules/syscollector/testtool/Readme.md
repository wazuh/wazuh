# Syscollector Testing Tool
## Index
1. [Purpose](#purpose)
2. [Compile Wazuh](#compile-wazuh)
3. [How to use the tool](#how-to-use-the-tool)

## Purpose
The Syscollector Testing Tool was created to test and validate the data obtained by the module's execution. This tool works as a black box where an user will be able execute it and analyze the output data as desired.

## Compile Wazuh
Syscollector is an agent module, so the tool is built only with an agent target, in release or debug mode:
```
make TARGET=agent|winagent <DEBUG=1>
```

## How to use the tool
The `syscollector_test_tool` binary is written to the `src/build/bin` folder. It runs Syscollector with every inventory category enabled and prints each stateless event (`diff output payload:`), each stateful document (`persist output payload (version: N):`) and the module's log lines to standard output.

```
./syscollector_test_tool [seconds]
```

- Without arguments, it runs until `q` followed by Enter is read from standard input.
- With one argument, it stops after that many seconds (60 if the argument is not a number).
- With more than one argument, it exits without running (`main()` returns `-1`).

It opens its database at `queue/syscollector/db/local.db` and its normalization file at `queue/syscollector/norm_config.json`, both relative to the current directory, so run it from a scratch directory that has a `queue/syscollector/db/` folder rather than from an agent installation.

The information output will vary based on the Operating System the tool is being executed.
