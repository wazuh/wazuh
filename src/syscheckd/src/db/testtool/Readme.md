# FIMDB Testing Tool
## Index
1. [Purpose](#purpose)
2. [Architecture Diagram](#architecture-diagram)
3. [Compile Wazuh](#compile-wazuh)
4. [How to use the tool](#how-to-use-the-tool)

## Purpose
The FIMDB Testing Tool was created to test and validate the fimdb module. This tool works as a black box where an user will be able execute it with different arguments and analyze the output data as desired.

## Architecture Diagram

![alt text](../../../../../architecture/FIM/db/001-class-testtool.puml)
![alt text](../../../../../architecture/FIM/db/002-sequence-testtool.puml)

## Compile Wazuh
In order to run tests on a specific wazuh target, the project needs to be built either in release or debug mode.
```
make TARGET=server|agent|winagent <DEBUG=1>
```

## How to use the tool
In order to run the `fimdb_test_tool` utility the following steps need to be accomplished:
1) Create a config json file with the following structure:
```
{
    "storage_type": <0|1>,
    "sync_interval": 60,
    "file_limit": 20,
    "value_limit": 1,
    "is_windows": false
}
```
Where:
  - storage_type: Defines the storage type 0 = DISK, 1 = MEMORY.
  - sync_interval: Integrity check interval.
  - file_limit: File table row limit.
  - value_limit: Registry tables row limit.
  - is_windows: Flag to enable windows/registry tables.

2) Create the needed amount of json files representing the different actions information.
3) Define an output folder where all resulting data will be located.
4) Once all the above steps are accomplished the tool will be used like this:
```
./fimdb_test_tool -c config.json -a input1.json,input2.json,input3.json -o ./output
```
5) Considering the example above all actions outpus will be located in ./output folder in the following format: action_1.json, action_2.json ... action_n.json where 'n' will be the number of json files passed as part of the argument "-a".

