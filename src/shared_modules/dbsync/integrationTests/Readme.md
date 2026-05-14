# Integration Tests
## Index
1. [Compile Wazuh](#compile-wazuh)
2. [Compile and run unit tests for Linux targets](#compile-and-run-unit-tests-for-linux-targets)

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `DEBUG` and `TEST` options as shown below:
```
make deps RESOURCES_URL=file:///path/to/deps/
make TARGET=server|agent DEBUG=1 TEST=1
```

## Compile and run unit tests for Linux targets
In order to run unit tests for dbsync, these need to be built using [CMake](#installing\ cmake) version 3.12 or higher.

Navigate into `wazuh/src/dbsync/` and run the following commands:
```
mkdir build
cd build
cmake -DEXTERNAL_LIB=~/path/to/wazuh/src/external/ -DCMAKE_BUILD_TYPE=Debug -DUNIT_TEST=ON ..
cmake --build .
```

### Running a specific test
In case you need to run a specific test, navigate into the subdirectory where the test resides and run it as you would any other Linux binary. As an example, if you want to run tests on `string_helper.cpp`
```
cd bin
./string_helper_unit_test
```
The output of the test will be written directly into the console.
