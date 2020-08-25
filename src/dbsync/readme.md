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
usage: build.py [-h] [-t] [-c] [-r] [-v] [-m] [--clean] [--cppcheck] [--config OS TYPE TEST] {} ...

positional arguments:
  {}

optional arguments:
  -h, --help            show this help message and exit
  -t, --tests           Run tests (should be configured with TEST=on)
  -c, --coverage        Collect tests coverage and generates report
  -r, --readytoreview   Run all the quality checks needed to create a PR
  -v, --valgrind        Run valgrind on tests
  -m, --make            Compile the lib
  --clean               Clean the lib
  --cppcheck            Run cppcheck on the code
  --config OS TYPE TEST
                        Configure the lib. OS=win|linux|mac TYPE=Release|Debug TEST=ON|OFF

Ready to review checks:
  1. runs cppcheck on dbsync folder.
  2. compiles dbsync.
  3. runs dbsync UTs.
  4. runs valgrind on dbsync UTs.
  5. runs code coverage on dbsync tests and generates coverage reports.
If all the checks passed it returns 0 and prints a "[RTR: PASSED]", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns and error code.
