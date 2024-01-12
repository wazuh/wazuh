# Txn Operation
This test represents a transactional use case where the following steps will be followed:
1) Create the database based on the `sql_statement` option under the `config.json` file.
2) Create a transaction.
3) Insert the `inputSyncRowInsertTxn.json` file's data into the DB.
4) Get deleted rows. `pksGetDeletedRows.json` and `fullyGetDeletedRows.json` will define the information details.
5) Update the DB with the `inputSyncRowModifiedTxn.json` file's data.
6) Close the transaction.

# Execution
In order to execute this test it would be needed the `dbsync_test_tool` binary and the command line will look like the following one:
```
$> ./dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/pksGetDeletedRows.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
```

