# Tools

1. [Summary](#summary)
2. [Directory structure](#directory-structure)
3. [Scripts and Packages](#scripts-and-packages)
    - [API communication](#api-communication)
    - [Engine suite](#engine-suite)
    - [EVTX to XML](#evtx-to-xml)
    - [Check valgrind](#check-valgrind)
    - [Check ASAN](#check-asan)
    - [Check events diff](#check-events-diff)

# Summary

This directory includes several bash packages and scripts designed to make development easier.
and management of related tools. The following describes the directory structure and provides
detailed information about each component.

# Directory structure

```plaintext
tool/
│
├── api_communication/
├── engine-suite/
├── evtx2xml/
```

# Scripts and Packages

## API communication

The `api-communication` package is a tool designed to facilitate communication with the engine API, allowing the execution of commands and operations on engine components.

### Main Features

- **Communication with the Engine API**:
    Provides an interface to send requests to the engine API and receive responses efficiently, using messages in protobuf format.

- **API Command Management**:
    Translates messages into specific commands that the engine API can process, allowing operations to be performed on engine components

### Installation
```bash
pip3 install tools/api_communication
```

## Engine suite

The `engine-suite` package is a comprehensive tool designed to manage, clean, and compare resources, as well as update decoders and manage integrations within the Wazuh environment.

- **Resource Management and Deletion**: Allows the deletion of resources in specific namespaces, such as user, Wazuh, and system, ensuring that the environment remains clean and organized. It also includes the removal of policies and assets, ensuring that rules and configurations are aligned with the desired changes.

- **Decoder Update**: Facilitates the massive update of auxiliary function names in decoders and allows listing all fields extracted by a specific decoder, helping in the administration and maintenance of the decoders.

- **File Comparison**: Provides tools to compare event files in YAML or JSON format, detecting differences in keys and values. In addition, it integrates external tools such as Delta for a clear visualization of the differences.

- **Integrations Management**: Centralizes the creation, addition, update and removal of integrations, and also generates documentation, charts and manifests to facilitate the administration and monitoring of these integrations.

### Installation
```bash
pip3 install tools/engine_suite
```

## EVTX to XML

This module converts event files in EVTX format (used by Windows for event logs) to XML format. This allows you to view and work with Windows event logs in a more accessible and standard format. [By more information check herereadme](./evtx2xml/README.md)

## Check valgrind

- **Running Valgrind**: Run software tests with Valgrind to identify memory leaks and other similar problems.
- **Test Search Settings**: Allows you to specify the directory where to search for tests, exclude certain directories, and apply filters to the results.
- **Report Generation**: Creates a detailed report on Valgrind results in a specified output file.

### Usage
```bash
Usage: tools/check_Valgrind.sh [options] [arguments]

Options:
  -h, --help          Show this help message
  -e, --exclude DIRS  Colon-separated list of directories to exclude
  -t, --test-dir DIR  Directory to search for tests (default: build directory)
  -r, --regex PATTERN Optional regular expression to filter tests (default: no filtering)
  -o, --output FILE   File to redirect output (default: /valgrindReport.log)
```

- **Run only OrchestratorTest from router component**:
```bash
bash tools/check_Valgrind.sh -t build/source/router/ -r OrchestratorTesterTest*
```

- **Run all test except those of the builder and kvdb**:
```bash
bash tools/check_Valgrind.sh -e build/source/bk/:build/source/builder/:build/source/kvdb/
```

## Check ASAN

- **ASAN, TSAN, and MSAN check**: Check if the binaries are compiled with support for AddressSanitizer, ThreadSanitizer, or MemorySanitizer.
- **Test Execution**: Use `ctest` to run tests in the specified directory and redirect the results to a file if indicated.
- **Flexible Configuration**: Allows you to specify the test directory, exclude certain directories, apply filtering

### Usage
```bash
Usage: tools/check_ASAN.sh [options] [arguments]

Options:
  -h, --help          Show this help message
  -e, --exclude DIRS  Colon-separated list of directories to exclude
  -t, --test-dir DIR  Directory to search for tests (default: build directory)
  -r, --regex PATTERN Optional regular expression to filter tests (default: no filtering)
  -o, --output FILE   File to redirect output (default: stdout)
```
- **Run only OrchestratorTest from router component**:
```bash
bash tools/check_ASAN.sh -t build/source/router/ --regex OrchestratorTest*
```
- **Run all test except those of the builder and kvdb**:
```bash
bash tools/check_ASAN.sh -e build/source/bk/:build/source/builder/:build/source/kvdb/
```


## Check events diff

- **Download and Conversion**: Download files from URLs if necessary and convert EVTX files to XML.
- **Test Execution**: Use `engine-test` to process the input file events.
- **Format and Comparison**: Format and sort results before comparing them to a reference file using `jq` and `engine-diff`.

### Usage

```bash
usage: engine-diff [-h] [--version] [-in {yaml,json}] [-q, --quiet] [--no-order] fileA fileB

Compare two events in yaml format, returns SAME if no differences found, DIFFERENT otherwise. The script loads the events, orders them and makes a diff using
delta, credits to dandavison for his awesome tool (https://github.com/dandavison/delta)

positional arguments:
  fileA                 First file to compare
  fileB                 Second file to compare

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -in {yaml,json}, --input {yaml,json}
                        Input format (default: json)
  -q, --quiet           Print only the result
  --no-order            Do not order the events when comparing
```
