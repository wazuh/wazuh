# Txn Operation
This test represents a transactional use case where the following steps will be followed:
1) Create the database based on the `sql_statement` option of the shared `../config.json` file.
2) Create a transaction on the `processes` table (`createTxn.json`, `dbsync_create_txn`).
3) Insert the `inputSyncRowInsertTxn.json` file's data into the DB within the transaction (`dbsync_sync_txn_row`).
4) Get the rows of the transaction's tables that it has not synced, reported as deleted (`dbsync_get_deleted_rows`). `pksGetDeletedRows.json` and `fullyGetDeletedRows.json` hold the same action, which takes no arguments; use either.
5) Update the DB with the `inputSyncRowModifiedTxn.json` file's data (`dbsync_sync_txn_row`).
6) Close the transaction (`closeTxn.json`, `dbsync_close_txn`).

# Execution
Run it from the `smokeTests` folder (see [../Readme.md](../Readme.md#running-them)):
```
$> ../../../build/bin/dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/pksGetDeletedRows.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
```
