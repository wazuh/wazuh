# General Build Script
## Index
1. [Purpose](#purpose)
2. [Dependencies](#dependencies)
3. [Compile Wazuh](#compile-wazuh)
4. [How to use the tool](#how-to-use-the-tool)

## Purpose
The `build.py` script was created to compile, test and validate the available modules and its code readiness. This tool was meant to developers to speed up the code readiness checking and development and to be able to include the usage of the tool as part of automation processes and checks.

## Dependencies
There are several modules needed in order to the tool to work correctly.
  - cppcheck
  - valgrind
  - lcov
  - gcov
  - astyle

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `DEBUG` and `TEST` options as shown below:
```
make TARGET=server|agent DEBUG=1 TEST=1
```

## How to use the tool
Once the code is compiled and built successfully the following line should be executed:

```
usage: python3 build.py [-h] [-r READYTOREVIEW] [-m MAKE] [-t TESTS] [-c COVERAGE] [-v VALGRIND] [--clean CLEAN] [--cppcheck CPPCHECK]
```

### Optional arguments:

|Argument|Description|
|---|---|
| `-h`, `--help`          | Show the help message and exit |
| `-r`, `--readytoreview` | Run all the quality checks needed to create a PR. Example: `python3 build.py -r <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `-m`, `--make`          | Compile the lib. Example: `python3 build.py -m <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `-t`, `--tests`         | Run tests (should be configured with TEST=on). Example: `python3 build.py -t <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `-c`, `--coverage`      | Collect tests coverage and generates report. Example: `python3 build.py -c <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `-v`, `--valgrind`      | Run valgrind on tests. Example: `python3 build.py -v <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `-c`, `--coverage`      | Collect tests coverage and generates report. Example: `python3 build.py -c <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `--clean`               | Clean the lib. Example: `python3 build.py --clean <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `--cppcheck`            | Run cppcheck on the code. Example: `python3 build.py --cppcheck <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `--asan`                | Run ASAN on the code. Example: `python3 build.py --asan <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `--scheck`              | Run AStyle on the code for checking purposes. Example: `python3 build.py --scheck <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |
| `--sformat`             | Run AStyle on the code formatting the needed files. Example: `python3 build.py --sformat <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>` |

Ready to review checks:
  1. Runs cppcheck on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> folder.
  2. Compiles <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>.
  3. Runs <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> UTs.
  4. Runs valgrind on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> UTs.
  5. Runs code coverage on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> tests and generates coverage reports.
If all the checks passed it returns 0 and prints a "[RTR: PASSED]", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns and error code.


Output Example executing the RTR tool with `dbsync` module:
```
#> python3 build.py -r shared_modules/dbsync
<shared_modules/dbsync>=================== Running RTR checks  ===================<shared_modules/dbsync>
<shared_modules/dbsync>=================== Running cppcheck    ===================<shared_modules/dbsync>
[Cppcheck: PASSED]
[Cleanfolder: PASSED]
<shared_modules/dbsync>=================== Running CMake Conf  ===================<shared_modules/dbsync>
[ConfigureCMake: PASSED]
<shared_modules/dbsync>=================== Compiling library   ===================<shared_modules/dbsync>
shared_modules/dbsync > [make: PASSED]
<shared_modules/dbsync>=================== Running Tests       ===================<shared_modules/dbsync>
[dbengine_unit_test: PASSED]
[sqlite_unit_test: PASSED]
[fim_integration_test: PASSED]
[dbsync_unit_test: PASSED]
[dbsyncPipelineFactory_unit_test: PASSED]
<shared_modules/dbsync>=================== Running Valgrind    ===================<shared_modules/dbsync>
[dbengine_unit_test: PASSED]
[sqlite_unit_test: PASSED]
[fim_integration_test: PASSED]
[dbsync_unit_test: PASSED]
[dbsyncPipelineFactory_unit_test: PASSED]
<shared_modules/dbsync>=================== Running Coverage    ===================<shared_modules/dbsync>
[lcov info: GENERATED]
[genhtml info: GENERATED]
Report: /home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/coverage_report/index.html
[Lines Coverage 93.4%: PASSED]
[Functions Coverage 96.7%: PASSED]
<shared_modules/dbsync>=================== Running AStyle      ===================<shared_modules/dbsync>
[Cleanfolder: PASSED]
<shared_modules/dbsync>[AStyle Check: PASSED]<shared_modules/dbsync>
<shared_modules/dbsync>=================== Running ASAN        ===================<shared_modules/dbsync>
[Cleanfolder: PASSED]
<shared_modules/dbsync>=================== Running CMake Conf  ===================<shared_modules/dbsync>
[ConfigureCMake: PASSED]
<shared_modules/dbsync>=================== Compiling library   ===================<shared_modules/dbsync>
shared_modules/dbsync > [make: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a snapshotsUpdate/insertData.json,snapshotsUpdate/updateWithSnapshot.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a InsertionUpdateDeleteSelect/inputSyncRowInsert.json,InsertionUpdateDeleteSelect/inputSyncRowModified.json,InsertionUpdateDeleteSelect/deleteRows.json,InsertionUpdateDeleteSelect/inputSelectRows.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<shared_modules/dbsync>[ASAN: PASSED]<shared_modules/dbsync>
<shared_modules/dbsync>[RTR: PASSED]<shared_modules/dbsync>

```

Address sanitizer checks:
  1. Clean previous builds <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> folder.
  2. Compiles with address sanitizers flags<data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>.
  3. Runs smoke tests <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  4. Runs valgrind on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> UTs.
If all the checks passed it returns 0 and prints a "[ASAN: PASSED]", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns and error code.

Output Example executing the ASAN tests with `dbsync` module:
```
#> python3 build.py -r shared_modules/dbsync
<shared_modules/dbsync>=================== Running ASAN        ===================<shared_modules/dbsync>
[Cleanfolder: PASSED]
<shared_modules/dbsync>=================== Running CMake Conf  ===================<shared_modules/dbsync>
[ConfigureCMake: PASSED]
<shared_modules/dbsync>=================== Compiling library   ===================<shared_modules/dbsync>
shared_modules/dbsync > [make: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a snapshotsUpdate/insertData.json,snapshotsUpdate/updateWithSnapshot.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a InsertionUpdateDeleteSelect/inputSyncRowInsert.json,InsertionUpdateDeleteSelect/inputSyncRowModified.json,InsertionUpdateDeleteSelect/deleteRows.json,InsertionUpdateDeleteSelect/inputSelectRows.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/home/dwordcito/wazuh/src/ci/../shared_modules/dbsync/build//bin/dbsync_test_tool -c config.json -a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json -o ./output
[Cleanfolder: PASSED]
[TestTool: PASSED]
<shared_modules/dbsync>[ASAN: PASSED]<shared_modules/dbsync>
```