# DBSync Testing Tool
## Index
1. [Purpose](#purpose)
2. [Architecture Diagram](#architecture-diagram)
3. [Compile Wazuh](#compile-wazuh)
4. [How to use the tool](#how-to-use-the-tool)

## Purpose
The DBSync Testing Tool was created to test and validate the dbsync module. This tool works as a black box where an user will be able execute it with different arguments and analyze the output data as desired.

## Architecture Diagram

![alt text](../images/dbsyncTestToolArchDiagram.png)

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built either in release or debug mode.
```
make TARGET=server|agent <DEBUG=1>
```

## How to use the tool
In order to run the `dbsync_test_tool` utility the following steps need to be accomplished:
1) Create a config json file with the following structure:
```
{
    "db_name": "db_name",
    "db_type": "1",
    "host_type": "<0|1>",
    "persistance": "",
    "sql_statement":"sql"
}
```
Where:
  - db_name: Database name to be used.
  - db_type: Database type to be used. Only SQLITE3 is currently supported.
  - host_type: Agent or Manager.
  - persistance: Database type of persistance being used.
  - sql_statement: Database sql structure to be created. This structure will be associated with the other files needed to use the tool.

2) Create the needed amount of json files representing the different actions information. These ones need to follow the sql_statement structure created in the step 1.
3) Define an output folder where all resulting data will be located.
4) Once all the above steps are accomplished the tool will be used like this:
```
./dbsync_test_tool -c config.json -a input1.json,input2.json,input3.json -o ./output
```
5) Considering the example above all diff snapshots will be located in ./output folder in the following format: action_1.json, action_2.json ... action_n.json where 'n' will be the number of json files passed as part of the argument "-a".
