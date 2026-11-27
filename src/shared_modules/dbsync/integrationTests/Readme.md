# Integration Tests
## Index
1. [What is tested](#what-is-tested)
2. [Build the tests](#build-the-tests)
3. [Run the tests](#run-the-tests)

## What is tested
`fim_integration_test` (sources in `fim/`) runs the FIM database queries (`FIMDB_STMT_GET_PATH`,
`FIMDB_STMT_GET_ALL_ENTRIES`, `FIMDB_STMT_GET_PATHS_INODE` and the rest of the `DBSyncFimIntegrationTest`
cases) through the real dbsync library and SQLite engine.

## Build the tests
dbsync is built only for agent targets (`src/CMakeLists.txt` adds it under `IS_AGENT`), and this test
only when the tree is configured with `TEST`, which turns on `UNIT_TEST`:
```
make -C src deps TARGET=agent
make -C src TARGET=agent TEST=yes
```

## Run the tests
The binary lands in `src/build/bin` and is registered in CTest with the label `dbsync`, together with
the [unit tests](../tests/Readme.md):
```
cd src/build
ctest -R fim_integration_test -V
```
or run `src/build/bin/fim_integration_test` directly. The output of the test is written to the console.
