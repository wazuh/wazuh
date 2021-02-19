# Trigger actions
This test represents a trigger action use case where the following steps will be followed:
1) Create the database based on the `sql_statement` option under the `config.json` file.
2) Insert the `insertDataProcesses.json` file's data into the DB.
3) Insert the `insertDataSocket.json` file's data into the DB.
4) Add relationship in tables based on `addTableRelationship.json` file's data.
5) Delete data in table processes based on `deleteRows.json`, which should implicitly delete the data in the socket table. 

# Execution
In order to execute this test it would be needed the `dbsync_test_tool` binary and the command line will look like the following one:
```
$> ./dbsync_test_tool -c config.json -a insertDataProcesses.json,insertDataSocket.json,addTableRelationship.json,deleteRows.json -o ./output
```

