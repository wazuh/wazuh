# Txn Operation
This test represents a case where the following steps will be followed:
1) Create the database based on the `sql_statement` option under the `config.json` file.
2) Insert the `insertData.json` file's data into the DB.
3) Update the DB with the `updateWithSnapshot.json` file's data.
4) Close the transaction.

# Execution
In order to execute this test it would be needed the `dbsync_test_tool` binary and the command line will look like the following one:
```
$> ./dbsync_test_tool -c config.json -a insertData.json,updateWithSnapshot.json -o ./output
```

