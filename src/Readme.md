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

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `DEBUG` and `TEST` options as shown below:
```
make TARGET=server|agent DEBUG=1 TEST=1
```

## How to use the tool
Once the code is compiled and built successfully the following line should be executed:

```
usage: python3 build.py [-h] [-r READYTOREVIEW] [-m MAKE] [-t TESTS] [-c COVERAGE] [-v VALGRIND] [--clean CLEAN] [--cppcheck CPPCHECK]

optional arguments:
  -h, --help            show this help message and exit
  -r READYTOREVIEW, --readytoreview READYTOREVIEW
                        Run all the quality checks needed to create a PR. Example: python3 build.py -r <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  -m MAKE, --make MAKE  Compile the lib. Example: python3 build.py -m <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  -t TESTS, --tests TESTS
                        Run tests (should be configured with TEST=on). Example: python3 build.py -t <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  -c COVERAGE, --coverage COVERAGE
                        Collect tests coverage and generates report. Example: python3 build.py -c <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  -v VALGRIND, --valgrind VALGRIND
                        Run valgrind on tests. Example: python3 build.py -v <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  --clean CLEAN         Clean the lib. Example: python3 build.py --clean <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  --cppcheck CPPCHECK   Run cppcheck on the code. Example: python3 build.py --cppcheck <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  --asan ASAN           Run ASAN on the code. Example: python3 build.py --asan <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>


Ready to review checks:
  1. runs cppcheck on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> folder.
  2. compiles <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>.
  3. runs <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> UTs.
  4. runs valgrind on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> UTs.
  5. runs code coverage on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> tests and generates coverage reports.
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
  1. clean previous builds <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> folder.
  2. compiles with address sanitizers flags<data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>.
  3. runs smoke tests <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector>
  4. runs valgrind on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector> UTs.
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