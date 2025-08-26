# Syscollector Testing Tool
## Index
1. [Purpose](#purpose)
2. [Compile Wazuh](#compile-wazuh)
3. [How to use the tool](#how-to-use-the-tool)

## Purpose
The Syscollector Testing Tool was created to test and validate the data obtained by the module's execution. This tool works as a black box where an user will be able execute it and analyze the output data as desired.

## Compile Wazuh
In order compile the solution on a specific wazuh target, the project needs to be built either in release or debug mode.
```
make TARGET=server|agent <DEBUG=1>
```

## How to use the tool
In order to run the `syscollector_test_tool` (located in `src/wazuh_modules/syscollector/build/bin` folder) utility the only step to be followed is just to execute the tool (without parameters):
```
./syscollector_test_tool
```

The information output will vary based on the Operating System the tool is being executed.
