# DBSync Build Script
## Index
1. [Purpose](#purpose)
3. [Dependencies](#dependencies)
2. [How to use the tool](#how-to-use-the-tool)

## Purpose
The DBSync Build Script was created to compile, test and validate the dbsync module and its code readiness. This tool was meant to developers to speed up the code readiness checking and development and to be able to include the usage of the tool as part of automation processes and checks.

## Dependencies
There are several modules needed in order to the tool to work correctly.
  - cppcheck
  - valgrind
  - lcov
  - gcov

## How to use the tool
Usage:
./build.sh --help      :   Show this help.
./build.sh --rtr       :   Ready to Review checks.
./build.sh --config    :   Config dbsync.
./build.sh --make      :   Make dbsync.
./build.sh --remake    :   Clean and Make dbsync.
./build.sh --tests     :   Tests.
./build.sh --coverage  :   Coverage.
./build.sh --cppcheck  :   cppcheck.
./build.sh --valgrind  :   Valgrind on tests.

Ready to review checks:
  1- compiles dbsync.
  2- runs cppcheck on dbsync folder.
  3- runs dbsync UTs.
  4- runs valgrind on dbsync UTs.
  5- runs code coverage on dbsync tests and generates coverage reports.
If all the checks passed it returns 0 and prints a "RTR PASSED: code is ready to review.", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns and error code.