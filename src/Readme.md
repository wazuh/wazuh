# General Build Script
## Index
- [General Build Script](#general-build-script)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Dependencies](#dependencies)
  - [Compile Wazuh](#compile-wazuh)
  - [How to use the tool](#how-to-use-the-tool)
    - [Optional arguments:](#optional-arguments)

## Purpose
The `build.py` script was created to compile, test and validate the available modules and its code readiness. This tool was meant to developers to speed up the code readiness checking and development and to be able to include the usage of the tool as part of automation processes and checks.

## Dependencies
There are several modules needed in order to the tool to work correctly.
  - cppcheck
  - valgrind
  - lcov
  - gcov
  - astyle
  - scan-build-10

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `DEBUG` and `TEST` options as shown below:
```
make TARGET=server|agent DEBUG=1 TEST=1
```

## How to use the tool
Once the code is compiled and built successfully the following line should be executed:

```
usage: python3 build.py [-h] [-r READYTOREVIEW] 
[-d DELETELOGS] [-rc READYTOREVIEWANDCLEAN] [-m MAKE] 
[-t TESTS] [-c COVERAGE] [-v VALGRIND] [--clean CLEAN] 
[--cppcheck CPPCHECK] [--asan ASAN] [--scheck SCHECK] 
[--sformat SFORMAT] [--scanbuild SCANBUILD]
```

### Optional arguments:

|Argument|Description|
|---|---|
| `-h`, `--help`          | Show the help message and exit |
| `-r`, `--readytoreview` | Run all the quality checks needed to create a PR. Example: `python3 build.py -r <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `-rc`, `--readytoreviewandclean` | Run all the quality checks needed to create a PR and clean results. Example: `python3 build.py -r <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `-m`, `--make`          | Compile the lib. Example: `python3 build.py -m <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `-t`, `--tests`         | Run tests (should be configured with TEST=on). Example: `python3 build.py -t <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `-c`, `--coverage`      | Collect tests coverage and generates report. Example: `python3 build.py -c <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `-v`, `--valgrind`      | Run valgrind on tests. Example: `python3 build.py -v <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `-c`, `--coverage`      | Collect tests coverage and generates report. Example: `python3 build.py -c <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `--clean`               | Clean the lib. Example: `python3 build.py --clean <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `--cppcheck`            | Run cppcheck on the code. Example: `python3 build.py --cppcheck <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `--asan`                | Run ASAN on the code. Example: `python3 build.py --asan <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `--scheck`              | Run AStyle on the code for checking purposes. Example: `python3 build.py --scheck <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `--sformat`             | Run AStyle on the code formatting the needed files. Example: `python3 build.py --sformat <data_provider\|shared_modules/dbsync\|shared_modules/rsync\|shared_modules/utils\|wazuh_modules/syscollector\|syscheckd>` |
| `--scanbuild`           | Run scan-build on the code. Example: `python3 build.py --scanbuild <agent\|server\|winagent>` |

Ready to review checks:
  1. Runs cppcheck on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd> folder.
  2. Compiles <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd>.
  3. Runs <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd> UTs.
  4. Runs valgrind on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd> UTs.
  5. Runs code coverage on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd> tests and generates coverage reports.
  6. Runs AStyle on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd>.
  7. Runs ASAN on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd>.
  8. Runs Test tool for Windows on <syscheckd>.
  9. Runs check output from test tool on <syscheckd>.

If all the checks passed it returns 0 and prints a "[RTR: PASSED]", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns and error code. We can use a flag like `target` to run tests on Windows this runs unit tests so this works only for syscheckd at the moment.


Output Example executing the RTR tool with `dbsync` module:
```
#> python3 build.py -r shared_modules/dbsync
<shared_modules/dbsync>=================== Running RTR checks  ===================<shared_modules/dbsync>
<shared_modules/dbsync>=================== Running cppcheck    ===================<shared_modules/dbsync>
[Cppcheck: PASSED]
[Cleanfolder : PASSED]
<shared_modules/dbsync>=================== Running CMake Conf  ===================<shared_modules/dbsync>
[ConfigureCMake: PASSED]
<shared_modules/dbsync>=================== Compiling library   ===================<shared_modules/dbsync>
shared_modules/dbsync > [make: PASSED]
<shared_modules/dbsync>=================== Running Tests       ===================<shared_modules/dbsync>
[dbsyncPipelineFactory_unit_test: PASSED]
[dbengine_unit_test: PASSED]
[dbsync_unit_test: PASSED]
[fim_integration_test: PASSED]
[sqlite_unit_test: PASSED]
<shared_modules/dbsync>=================== Running Valgrind    ===================<shared_modules/dbsync>
[dbsyncPipelineFactory_unit_test : PASSED]
[dbengine_unit_test : PASSED]
[dbsync_unit_test : PASSED]
[fim_integration_test : PASSED]
[sqlite_unit_test : PASSED]
<shared_modules/dbsync>=================== Running Coverage    ===================<shared_modules/dbsync>
[lcov info: GENERATED]
[genhtml info: GENERATED]
Report: /root/repos/wazuh/src/shared_modules/dbsync/coverage_report/index.html
[Lines Coverage 95.1%: PASSED]
[Functions Coverage 98.0%: PASSED]
<shared_modules/dbsync>=================== Running AStyle      ===================<shared_modules/dbsync>
[Cleanfolder : PASSED]
<shared_modules/dbsync>[AStyle Check: PASSED]<shared_modules/dbsync>
<shared_modules/dbsync>=================== Running ASAN        ===================<shared_modules/dbsync>
[CleanInternals: PASSED]
[MakeTarget: PASSED]
[Cleanfolder : PASSED]
<shared_modules/dbsync>=================== Running CMake Conf  ===================<shared_modules/dbsync>
[ConfigureCMake: PASSED]
<shared_modules/dbsync>=================== Compiling library   ===================<shared_modules/dbsync>
shared_modules/dbsync > [make: PASSED]
[Cleanfolder : PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a snapshotsUpdate/insertData.json,snapshotsUpdate/updateWithSnapshot.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a InsertionUpdateDeleteSelect/inputSyncRowInsert.json,InsertionUpdateDeleteSelect/inputSyncRowModified.json,InsertionUpdateDeleteSelect/deleteRows.json,InsertionUpdateDeleteSelect/inputSelectRows.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/pksGetDeletedRows.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/fullyGetDeletedRows.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json -o ./output
[TestTool: PASSED]
<shared_modules/dbsync>[ASAN: PASSED]<shared_modules/dbsync>
<shared_modules/dbsync>[RTR: PASSED]<shared_modules/dbsync>

```
Output Example executing the RTR tool with `syscheck` module and target `winagent`:
```
#> python3 build.py -r syscheckd --target winagent
 <syscheckd>=============== Running RTR checks  ===============<syscheckd>
 <syscheckd>=============== Running cppcheck    ===============<syscheckd>
 [Cppcheck: PASSED]
 <winagent>=============== Running Make Deps   ===============<winagent>
 [MakeDeps: PASSED]
 <winagent>=============== Running Make project ==============<winagent>
 [MakeTarget: PASSED]
 <syscheckd>=============== Running Tests       ===============<syscheckd>
 [fim_db_interface_test.exe: PASSED]
 [fileitem_unit_test.exe: PASSED]
 [registryvalue_unit_test.exe: PASSED]
 [fimdb_unit_test.exe: PASSED]
 [fim_registry_interface_test.exe: PASSED]
 [fim_file_interface_test.exe: PASSED]
 [registrykey_unit_test.exe: PASSED]


 <syscheckd>[All tests: PASSED]<syscheckd>
 [Cleanfolder : PASSED]
 <syscheckd>=============== Running CMake Conf  ===============<syscheckd>
 [ConfigureCMake: PASSED]
 <syscheckd>=============== Running AStyle      ===============<syscheckd>
 [Cleanfolder : PASSED]
 [AStyle Check: PASSED]
 [CleanAll: PASSED]
 [CleanExternals: PASSED]
 <agent>=============== Running Make Deps   ===============<agent>
 [MakeDeps: PASSED]
 <agent>=============== Running Make project ==============<agent>
 [MakeTarget: PASSED]
 [Cleanfolder : PASSED]
 <syscheckd>=============== Running ASAN        ===============<syscheckd>
 [CleanInternals: PASSED]
 <agent>=============== Running Make project ==============<agent>
 [MakeTarget: PASSED]
 [Cleanfolder : PASSED]
 <syscheckd>=============== Running CMake Conf  ===============<syscheckd>
 [ConfigureCMake: PASSED]
 <syscheckd>=============== Compiling library   ===============<syscheckd>
 [make: PASSED]
 [Cleanfolder : PASSED]
 <TESTTOOL>=============== Running TEST TOOL   ===============<TESTTOOL>
 /home/francorivero/Desktop/Wazuh_repositories/vagrant/wazuh/src/syscheckd/build/bin/fimdb_test_tool -c config.json -a FimDBTransaction/StartTransaction.json,FimDBTransaction/SyncTxnRows_1.json,FimDBTransaction/GetDeletedRows.json,FimDBTransaction/CountFiles.json,FimDBTransaction/StartTransaction.json,FimDBTransaction/SyncTxnRows_2.json,FimDBTransaction/GetDeletedRows.json,FimDBTransaction/CountFiles.json -o ./output/fileTransaction
 <TESTTOOL>=============== Running TEST TOOL   ===============<TESTTOOL>
 /home/francorivero/Desktop/Wazuh_repositories/vagrant/wazuh/src/syscheckd/build/bin/fimdb_test_tool -c config.json -a atomicFileOperations/SyncRow_1.json,atomicFileOperations/SyncRow_2.json,atomicFileOperations/CountFiles.json,atomicFileOperations/SyncRow_3.json,atomicFileOperations/DeleteFile.json,atomicFileOperations/CountFiles.json,atomicFileOperations/GetFile.json -o ./output/AtomicOperations
 [ASAN: PASSED]
 <syscheckd>=============== Running TEST TOOL for Windows =====<syscheckd>
 [CleanAll: PASSED]
 [CleanExternals: PASSED]
 <winagent>=============== Running Make Deps   ===============<winagent>
 [MakeDeps: PASSED]
 <winagent>=============== Running Make project ==============<winagent>
 [MakeTarget: PASSED]
 <TESTTOOL>=============== Running TEST TOOL   ===============<TESTTOOL>
 WINEPATH="/usr/i686-w64-mingw32/lib;/home/francorivero/Desktop/Wazuh_repositories/vagrant/wazuh/src"                            WINEARCH=win64 /usr/bin/wine /home/francorivero/Desktop/Wazuh_repositories/vagrant/wazuh/src/syscheckd/build/bin/fimdb_test_tool.exe -c configWindows.json -a FimDBTransaction/StartTransactionRegistryKey.json,FimDBTransaction/SyncTxnRowsRegistryKey_1.json,FimDBTransaction/GetDeletedRows.json,FimDBTransaction/StartTransactionRegistryKey.json,FimDBTransaction/SyncTxnRowsRegistryKey_2.json,FimDBTransaction/GetDeletedRows.json -o ./output/registryKeyTransaction
 <TESTTOOL>=============== Running TEST TOOL   ===============<TESTTOOL>
 WINEPATH="/usr/i686-w64-mingw32/lib;/home/francorivero/Desktop/Wazuh_repositories/vagrant/wazuh/src"                            WINEARCH=win64 /usr/bin/wine /home/francorivero/Desktop/Wazuh_repositories/vagrant/wazuh/src/syscheckd/build/bin/fimdb_test_tool.exe -c configWindows.json -a FimDBTransaction/StartTransactionRegistryData.json,FimDBTransaction/SyncTxnRowsRegistryData_1.json,FimDBTransaction/GetDeletedRows.json,FimDBTransaction/StartTransactionRegistryData.json,FimDBTransaction/SyncTxnRowsRegistryData_2.json,FimDBTransaction/GetDeletedRows.json -o ./output/registryDataTransaction
 [TEST TOOL for Windows: PASSED]
 [TestTool check: PASSED]
 <syscheckd>[RTR: PASSED]<syscheckd>
```

Address sanitizer checks:
  1. Clean previous builds <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd> folder.
  2. Compiles with address sanitizers flags<data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd>.
  3. Runs smoke tests <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd>
  4. Runs valgrind on <data_provider|shared_modules/dbsync|shared_modules/rsync|shared_modules/utils|wazuh_modules/syscollector|syscheckd> UTs.
If all the checks passed it returns 0 and prints a "[ASAN: PASSED]", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns and error code.

Output Example executing the ASAN tests with `dbsync` module:
```
#> python3 build.py --asan shared_modules/dbsync
<shared_modules/dbsync>=================== Running ASAN        ===================<shared_modules/dbsync>
[CleanInternals: PASSED]
[MakeTarget: PASSED]
[Cleanfolder : PASSED]
<shared_modules/dbsync>=================== Running CMake Conf  ===================<shared_modules/dbsync>
[ConfigureCMake: PASSED]
<shared_modules/dbsync>=================== Compiling library   ===================<shared_modules/dbsync>
shared_modules/dbsync > [make: PASSED]
[Cleanfolder : PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a snapshotsUpdate/insertData.json,snapshotsUpdate/updateWithSnapshot.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a InsertionUpdateDeleteSelect/inputSyncRowInsert.json,InsertionUpdateDeleteSelect/inputSyncRowModified.json,InsertionUpdateDeleteSelect/deleteRows.json,InsertionUpdateDeleteSelect/inputSelectRows.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/pksGetDeletedRows.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a txnOperation/createTxn.json,txnOperation/inputSyncRowInsertTxn.json,txnOperation/fullyGetDeletedRows.json,txnOperation/inputSyncRowModifiedTxn.json,txnOperation/closeTxn.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json -o ./output
[TestTool: PASSED]
<TESTTOOL>=================== Running TEST TOOL   ===================<TESTTOOL>
/root/repos/wazuh/src/shared_modules/dbsync/build/bin/dbsync_test_tool -c config.json -a triggerActions/insertDataProcesses.json,triggerActions/insertDataSocket.json,triggerActions/addTableRelationship.json,triggerActions/deleteRows.json -o ./output
[TestTool: PASSED]
<shared_modules/dbsync>[ASAN: PASSED]<shared_modules/dbsync>
```

Scan-build analysis agent/server:
  1. Clean previous compiled binaries.
  2. Remove externals libraries.
  3. Download externals libraries based on the specified target.
  4. Run scan-build on the specified target.
If all the checks passed it returns 0 and prints a "[SCANBUILD: PASSED]", otherwise it stops the execution checking on the first failure, prints the info related to the failure and returns an error code.

Scan-build analysis winagent:
  1. Clean previous compiled binaries.
  2. Remove externals libraries.
  3. Download externals libraries for windows.
  4. Compile winagent.
  5. Clean internals.
  6. Run scan-build for winagent specifying the cc and cxx compiler and the target.
Steps 4-5 were added to fix an issue found running scan-build on winagent using pre-compiled externals libraries. If all the checks passed it returns 0 and prints a "[SCANBUILD: PASSED]", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns an error code.
Output Example executing the SCANBUILD analysis with `agent` target:
```
#> python3 build.py --scanbuild agent
<agent>=================== Running Scanbuild   ===================<agent>
[CleanAll: PASSED]
[CleanExternals: PASSED]
[MakeDeps: PASSED]
[ScanBuild: PASSED]
<agent>[SCANBUILD: PASSED]<agent>
```
Output Example executing the SCANBUILD analysis with `winagent` target:
```
#> python3 build.py --scanbuild winagent
<winagent>=================== Running Scanbuild   ===================<winagent>
[CleanAll: PASSED]
[CleanExternals: PASSED]
[MakeDeps: PASSED]
[MakeTarget: PASSED]
[CleanInternals: PASSED]
[ScanBuild: PASSED]
<winagent>[SCANBUILD: PASSED]<winagent>
```