# Insertion Update Delete and Select
This test represents a common use case where the following steps will be followed:
1) Create the database based on the `sql_statement` option under the `config.json` file.
2) Insert the `inputSyncRowInsert.json` file's data into the DB.
3) Update the DB with the `inputSyncRowModified.json` file's data.
4) Delete some DB data based on the `deleteRows.json` file's data.
5) Select rows based on `inputSelectRows.json` file's data.

# Execution
In order to execute this test it would be needed the `dbsync_test_tool` binary and the command line will look like the following one:
```
$> ./dbsync_test_tool -c config.json -a inputSyncRowInsert.json,inputSyncRowModified.json,deleteRows.json,inputSelectRows.json -o ./output
```

