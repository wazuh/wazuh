# Snapshots Update
This test represents a case where the following steps will be followed:
1) Create the database based on the `sql_statement` option of the shared `../config.json` file.
2) Insert the `insertData.json` file's data into the DB (`dbsync_insert_data`).
3) Update the DB with the `updateWithSnapshot.json` file's data (`dbsync_update_with_snapshot`).

# Execution
Run it from the `smokeTests` folder (see [../Readme.md](../Readme.md#running-them)):
```
$> ../../../build/bin/dbsync_test_tool -c config.json -a snapshotsUpdate/insertData.json,snapshotsUpdate/updateWithSnapshot.json -o ./output
```
