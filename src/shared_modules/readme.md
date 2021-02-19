# General Build Script
## Index
1. [Purpose](#purpose)
3. [Dependencies](#dependencies)
2. [How to use the tool](#how-to-use-the-tool)

## Purpose
The Build Script was created to compile, test and validate the available modules and its code readiness. This tool was meant to developers to speed up the code readiness checking and development and to be able to include the usage of the tool as part of automation processes and checks.

## Dependencies
There are several modules needed in order to the tool to work correctly.
  - cppcheck
  - valgrind
  - lcov
  - gcov

## How to use the tool
´´´
usage: build.py [-h] [-r READYTOREVIEW] [-m MAKE] [-t TESTS] [-c COVERAGE] [-v VALGRIND] [--clean CLEAN] [--cppcheck CPPCHECK]

optional arguments:
  -h, --help            show this help message and exit
  -r READYTOREVIEW, --readytoreview READYTOREVIEW
                        Run all the quality checks needed to create a PR. Example: python3 build.py -r <dbsync|rsync|utils>
  -m MAKE, --make MAKE  Compile the lib. Example: python3 build.py -m <dbsync|rsync|utils>
  -t TESTS, --tests TESTS
                        Run tests (should be configured with TEST=on). Example: python3 build.py -t <dbsync|rsync|utils>
  -c COVERAGE, --coverage COVERAGE
                        Collect tests coverage and generates report. Example: python3 build.py -c <dbsync|rsync|utils>
  -v VALGRIND, --valgrind VALGRIND
                        Run valgrind on tests. Example: python3 build.py -v <dbsync|rsync|utils>
  --clean CLEAN         Clean the lib. Example: python3 build.py --clean <dbsync|rsync|utils>
  --cppcheck CPPCHECK   Run cppcheck on the code. Example: python3 build.py --cppcheck <dbsync|rsync|utils>
´´´

Ready to review checks:
  1. runs cppcheck on <dbsync|rsync|utils> folder.
  2. compiles <dbsync|rsync|utils>.
  3. runs <dbsync|rsync|utils> UTs.
  4. runs valgrind on <dbsync|rsync|utils> UTs.
  5. runs code coverage on <dbsync|rsync|utils> tests and generates coverage reports.
If all the checks passed it returns 0 and prints a "[RTR: PASSED]", otherwise it stops the execution of the checking on the first failure, prints the info related to the failure and returns and error code.
