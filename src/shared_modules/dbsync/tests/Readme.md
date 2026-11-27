# Unit Tests
## Index
1. [Build the tests](#build-the-tests)
2. [Run the tests](#run-the-tests)

## Build the tests
dbsync is built only for agent targets (`src/CMakeLists.txt` adds it under `IS_AGENT`). Its unit tests
are built when the tree is configured with `TEST`, which turns on `UNIT_TEST`:
```
make -C src deps TARGET=agent
make -C src TARGET=agent TEST=yes
```

## Run the tests
The binaries land in `src/build/bin` and are registered in CTest with the label `dbsync`:

| Binary | Sources |
|---|---|
| `sqlite_unit_test` | `tests/sqlite/` |
| `dbsync_unit_test` | `tests/interface/` |
| `dbsyncPipelineFactory_unit_test` | `tests/pipelineFactory/` |
| `dbengine_unit_test` | `tests/dbengine/` |

Run them all (the label also selects `fim_integration_test`, see [../integrationTests/Readme.md](../integrationTests/Readme.md)):
```
cd src/build
ctest -L dbsync -V
```

Run one binary, optionally filtered:
```
src/build/bin/dbsync_unit_test --gtest_filter='DBSyncTest.*'
```
The output of the test is written to the console.
