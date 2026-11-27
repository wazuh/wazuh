# DBSync Smoke Tests
## Index
1. [Purpose](#purpose)
2. [Folder Structure](#folder-structure)
3. [Running them](#running-them)

## Purpose
The DBSync Smoke Tests exercise the dbsync library APIs through the DBSync Test Tool. For more
information about the tool, its config file and its actions, see the [testtool Readme file](../testtool/Readme.md).

## Folder Structure
Each folder is one use case: its action files and a Readme.md that explains the case and how to run it.
All of them share the database definition in `config.json` (tables `processes` and `processes_sockets`).

## Running them
Build the tool as the [testtool Readme file](../testtool/Readme.md#build-the-tool) says, then run every
case from this folder, so that `config.json` and the `<case>/<file>.json` paths resolve, into an
existing output folder:
```
cd src/shared_modules/dbsync/smokeTests
mkdir -p output
../../../build/bin/dbsync_test_tool -c config.json -a <case>/<file1>.json,<case>/<file2>.json -o ./output
```
`src/ci/input/test_tool_config.json` (key `shared_modules/dbsync`) lists the exact runs that
`python3 build.py --readytoreview shared_modules/dbsync` performs.
