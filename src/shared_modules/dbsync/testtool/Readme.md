# DBSync Testing Tool
## Index
1. [Purpose](#purpose)
2. [Build the tool](#build-the-tool)
3. [How to use the tool](#how-to-use-the-tool)
4. [Actions](#actions)

## Purpose
The DBSync Testing Tool exercises the dbsync library as a black box: it creates a database from a
configuration file, applies a list of action files to it in order, and writes what each action
returned to an output folder. The [smoke tests](../smokeTests/Readme.md) are built on it.

## Build the tool
dbsync and this tool are built only for agent targets (`src/CMakeLists.txt` adds dbsync under
`IS_AGENT`), in release or debug mode:
```
make -C src deps TARGET=agent
make -C src TARGET=agent [DEBUG=yes]
```
The binary is `src/build/bin/dbsync_test_tool`.

## How to use the tool
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
Where (all values are strings):
  - db_name: Path of the database file to create.
  - db_type: `"1"` selects SQLite3, the only engine supported; any other value is `UNDEFINED`.
  - host_type: `"0"` creates the instance as `MANAGER`; any other value as `AGENT`.
  - persistance: `"1"` creates it with `dbsync_create_persistent()` (persistent database management);
    any other value, the empty string included, with `dbsync_create()` (volatile).
  - sql_statement: SQL that creates the tables. The action files refer to these tables.

2) Create one json file per action (see [Actions](#actions)).
3) Choose an output folder; it must exist.
4) Run the tool:
```
./dbsync_test_tool -c config.json -a input1.json,input2.json,input3.json -o ./output
```
All three switches are required: a missing one prints `Switch value: <switch> not found.` followed by the usage. The usage lists `-h`, but the tool does not parse it.

5) Each action writes its result to the output folder as `action_<n>.json`, where `<n>` is the
action's 0-based position in the `-a` list (`action_0.json` for the first file). Actions that report
through a callback also write `callback.action_<n>.json`, and the rows a transaction reports go to
`txn_<id>.json`. The tool exits with `0` even when an action fails: check its console output.

## Actions
An action file is a json object with an `action` name and a `body` holding its arguments, for example
`{"action": "dbsync_create_txn", "body": {"tables": ["processes"]}}`. The [smoke tests](../smokeTests/Readme.md)
hold an example of every C action except `dbsync_set_table_max_rows`, which is in `input/input6.json`. `factoryAction.h` maps each name to its implementation:

| C interface | C++ interface |
|---|---|
| `dbsync_insert_data` | `insertData` |
| `dbsync_update_with_snapshot` | `updateWithSnapshot` |
| `dbsync_create_txn` | `createTxn` |
| `dbsync_close_txn` | |
| `dbsync_set_table_max_rows` | `setTableMaxRows` |
| `dbsync_get_deleted_rows` | `getDeletedRows` |
| `dbsync_sync_row` | `syncRow` |
| `dbsync_sync_txn_row` | `syncTxnRow` |
| `dbsync_delete_rows` | `deleteRows` |
| `dbsync_select_rows` | `selectRows` |
| `dbsync_add_table_relationship` | `addTableRelationship` |

Any other name stops the tool with `Invalid action: <name>`.
