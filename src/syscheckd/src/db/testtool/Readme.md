# FIMDB Testing Tool
## Index
1. [Purpose](#purpose)
2. [Compile Wazuh](#compile-wazuh)
3. [How to use the tool](#how-to-use-the-tool)

## Purpose
The FIMDB Testing Tool was created to test and validate the fimdb module. This tool works as a black box where a user can execute it with different arguments and analyze the output data as desired.

## Compile Wazuh
The tool is built with the agent, in release or debug mode:
```
make TARGET=agent|winagent [DEBUG=yes]
```
The binary is `src/build/bin/fimdb_test_tool`. The registry tables exist only in the Windows build.

## How to use the tool
In order to run the `fimdb_test_tool` utility the following steps need to be accomplished:
1) Create a config json file with the following structure:
```
{
    "storage_type": <0|1>,
    "file_limit": 20,
    "registry_limit": 1
}
```
Where:
  - storage_type: Defines the storage type 0 = DISK (`queue/fim/db/fim.db`, relative to the working directory), 1 = MEMORY.
  - file_limit: File table row limit (`0` = no limit).
  - registry_limit: Row limit of each registry table (`0` = no limit; used only by the Windows build).

2) Create one json file per action, with the structure `{"action": "<name>", "body": {...}}`. The actions are `UpdateFile`, `RemoveFile`, `GetFile`, `SearchFile`, `CountEntries`, `StartTransaction`, `SyncTxnRows` and `GetDeletedRows`; the keys each one reads from `body` are in `action.h`.
3) Define an output folder where all resulting data will be located. It must exist.
4) Once all the above steps are accomplished the tool will be used like this:
```
./fimdb_test_tool -c config.json -a input1.json,input2.json,input3.json -o ./output
```
All three switches are required: a missing one prints `Switch value: <switch> not found.` followed by the usage.

5) Considering the example above, the output of each action is written to the ./output folder as action_0.json, action_1.json ... action_n.json, numbered from 0 in the order of the files passed to "-a". The transaction actions also append the rows their callbacks receive to ./output/txn_ops.json.
