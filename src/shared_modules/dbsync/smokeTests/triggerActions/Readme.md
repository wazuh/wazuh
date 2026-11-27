# Trigger actions
This test represents a trigger action use case where the following steps will be followed:
1) Create the database based on the `sql_statement` option of the shared `../config.json` file.
2) Insert the `insertDataProcesses.json` file's data into the `processes` table (`dbsync_insert_data`).
3) Insert the `insertDataSocket.json` file's data into the `processes_sockets` table (`dbsync_insert_data`).
4) Relate `processes_sockets` to `processes` by `pid`, as `addTableRelationship.json` says (`dbsync_add_table_relationship`).
5) Delete data in the `processes` table based on `deleteRows.json` (`dbsync_delete_rows`), which should implicitly delete the related rows of `processes_sockets`.

# Execution
Run it from the `smokeTests` folder (see [../Readme.md](../Readme.md#running-them)):
```
$> ../../../build/bin/dbsync_test_tool -c config.json -a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json -o ./output
```
