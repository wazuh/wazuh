# Insertion Update Delete and Select
This test represents a common use case where the following steps will be followed:
1) Create the database based on the `sql_statement` option of the shared `../config.json` file.
2) Insert the `inputSyncRowInsert.json` file's data into the DB (`dbsync_sync_row`).
3) Update the DB with the `inputSyncRowModified.json` file's data (`dbsync_sync_row`).
4) Delete some DB data based on the `deleteRows.json` file's data (`dbsync_delete_rows`).
5) Select rows based on `inputSelectRows.json` file's data (`dbsync_select_rows`).

# Execution
Run it from the `smokeTests` folder (see [../Readme.md](../Readme.md#running-them)):
```
$> ../../../build/bin/dbsync_test_tool -c config.json -a InsertionUpdateDeleteSelect/inputSyncRowInsert.json,InsertionUpdateDeleteSelect/inputSyncRowModified.json,InsertionUpdateDeleteSelect/deleteRows.json,InsertionUpdateDeleteSelect/inputSelectRows.json -o ./output
```
