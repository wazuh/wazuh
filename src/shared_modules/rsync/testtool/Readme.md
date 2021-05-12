# rsync Testing Tool
## Index
1. [Purpose](#purpose)
2. [Architecture Diagram](#architecture-diagram)
3. [Compile Wazuh](#compile-wazuh)
4. [How to use the tool](#how-to-use-the-tool)

## Purpose
The rsync Testing Tool was created to test and validate the rsync module. This tool works as a black box where an user will be able execute it with different arguments and analyze the output data as desired.

## Architecture Diagram

![alt text](../images/rsyncTestToolArchDiagram.png)

## Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `DEBUG` and `TEST` options as shown below:
```
make deps RESOURCES_URL=file:///path/to/deps/
make TARGET=server|agent DEBUG=1 TEST=1
```

## How to use the tool
In order to run the `rsync_test_tool` utility the following steps need to be accomplished:
```
./rsync_test_tool -u 100 -o ./output
```
Considering the example above all databases will be located in ./output folder and will be updated with random values every 100 milliseconds.
```
./rsync_test_tool -c config.json -i input.json -o ./output
```
Considering the example above all databases will be located in ./output folder and will configure dbsync/rsync according to config.json file and will exercise the libraries according to the inputs defined in input.json file.
