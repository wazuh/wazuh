# Tools

This directory includes several bash packages and scripts designed to make development easier.
and management of related tools. The following describes the directory structure and provides
detailed information about each component.

1. [Summary](#summary)
2. [Directory structure](#directory-structure)
3. [Scripts and Packages](#scripts-and-packages)
    - [API communication](#api-communication)
    - [Engine suite](#engine-suite)
        - [Engine clear](#engine-clear)
        - [Engine decoder](#engine-decoder)
        - [Engine diff](#engine-diff)
        - [Engine integration](#engine-integration)
        - [Engine test](#engine-test)
    - [EVTX to XML](#evtx-to-xml)
    - [Check valgrind](#check-valgrind)
    - [Check ASAN](#check-asan)
    - [Check events diff](#check-events-diff)

# Directory structure

```plaintext
tool/
│
├── api_communication/
│   └── src
│       └── api_communication
│           └── proto
│               └── component_pb2.pyi
│           └── __init__.py
│           └── client.py
│           └── command.py
│   └── README.md
│   └── setup.cfg
│   └── setup.py
├── engine-suite/
│   └── src
│       └── engine_clear
│           └── __init__.py
│           └── __main__.py
│       └── engine_decoder
│           └── cmds
│               └── __init__.py
│               └── list_extracted.py
│               └── syntax_update.py
│           └── __init__.py
│           └── __main__.py
│       └── engine_diff
│           └── __init__.py
│           └── __main__.py
│       └── engine_integration
│           └── cmds
│               └── __init__.py
│               └── add.py
│               └── create.py
│               └── delete.py
│               └── generate_doc.py
│               └── generate_graph.py
│               └── generate_manifest.py
│               └── update.py
│           └── __init__.py
│           └── __main__.py
│       └── engine_schema
│           └── cmds
│               └── __init__.py
│               └── add.py
│               └── _modules_.py
│               └── generate_.py
│               └── integrate.py
│           └── drivers
│               └── __init__.py
│               └── ecs.py
│               └── wazuh.py
│           └── __init__.py
│           └── __main__.py
│           └── field.py
│           └── fields.template.json
│           └── generate.py
│           └── logpar_types.json
│           └── mapping.template.json
│       └── engine_test
│           └── cmds
│               └── __init__.py
│               └── add.py
│               └── delete.py
│               └── get.py
│               └── list.py
│               └── run.py
│           └── formats
│               └── __init__.py
│               └── audit.py
│               └── command.py
│               └── eventchannel.py
│               └── full_command.py
│               └── json.py
│               └── macos.py
│               └── multi_line.py
│               └── remote_syslog.py
│               └── syslog.py
│           └── __init__.py
│           └── __main__.py
│           └── api_connector.py
│           └── command.json
│           └── config.py
│           └── crud_integration.py
│           └── event_format.py
│           └── event_collector.py
│           └── integration.py
│           └── parser.py
│       └── shared
│           └── __init__.py
│           └── executor.py
│           └── resource_handler.py
│   └── pyproject.toml
│   └── README.md
│   └── setup.cfg
│   └── setup.py
├── evtx2xml/
│   └── evtx2xml/
│       └── __init__.py
│       └── evtx_to_xml.py
│   └── MANIFEST.in
│   └── requirements.txt
│   └── setup.py
│   └── README.md
├── check_Valgrind.sh
├── check_ASAN.sh
└── checkEventsDiff.sh
```

# Scripts and Packages

## API communication

### Main Features

- **Communication with the Engine API**:
    Provides an interface to send requests to the engine API and receive responses efficiently, using messages in protobuf format.

- **API Command Management**:
    Translates messages into specific commands that the engine API can process, allowing operations to be performed on engine components

## Engine suite

### Engine clear

- **Resource Elimination**:
    You can delete user-specified or default resources in different namespaces such as `user`, `wazuh`, and `system`. This is useful for keeping the environment clean and organized.
    To prevent accidental deletions, the module requests confirmation before proceeding with resource deletion, unless the `--force` option is used to force execution without confirmation.

- **Support for Namespaces**:
    Users can specify which namespaces resources should be removed from. If not specified, the module removes them from the default namespaces.

- **Deletion of Policies and Assets**:
    In addition to kvdbs, can handle the removal of policies and other assets within the Wazuh environment, ensuring that all elements related to rules and configurations are aligned with the desired changes.


### Engine decoder

- **Updating Auxiliary Function Names**:
    Allows you to change the names of auxiliary functions in decoders in bulk. You can specify an old-new name pair or provide a file containing a list of names to replace.

- **Extraction of Decoder Fields**:
    Provides the ability to list all fields extracted by a specific decoder, by parsing the expressions used in the `parse` and `normalize` sections of the decoder file.

### Engine diff

- **File Comparison**: Compares two event files in YAML or JSON formats, determining if they are identical or different.

- **Sort and Difference Detection**: Sorts the events and detects different keys and values ​​between the compared files, showing key differences.

- **Integration with External Tools**: Use the Delta tool for a clear visualization of the differences.

- **Execution Options**: Includes a silent mode to show only the result and allows you to disable event sorting


### Engine integration

- **Integrations Management**: Allows you to create, add, update and delete integrations centrally.

- **Generation of Documentation and Resources**: Generates documentation, graphics and manifests for integrations, facilitating administration and monitoring.

### Engine test

- **Integrations Management**:
    - **Creation of Integrations**: Facilitates the creation of new integrations, where it is necessary to specify the format. Formats may include `audit`, `syslog`, `multiline`, `remote syslog`, `json`, among others.
    - **Deletion and Update**: Allows you to delete or update existing integrations, providing flexibility in configuration management.
    - **Getting Integrations**: Provides the ability to list and get details of configured integrations.

- **Test Execution**:
    - This subcommand allows you to test decoders or rules by creating test sessions.
    - Allows the introduction of specific events and following the trace of these events through the different assets (decoders, rules, etc.) that make up a particular policy.
    - Facilitates the analysis of how an event is processed by the engine, helping in the debugging.

## EVTX to XML

This module converts event files in EVTX format (used by Windows for event logs) to XML format. This allows you to view and work with Windows event logs in a more accessible and standard format. [By more information check herereadme](./evtx2xml/README.md)

## Check valgrind

- **Running Valgrind**: Run software tests with Valgrind to identify memory leaks and other similar problems.
- **Test Search Settings**: Allows you to specify the directory where to search for tests, exclude certain directories, and apply filters to the results.
- **Report Generation**: Creates a detailed report on Valgrind results in a specified output file.

## Check ASAN

- **ASAN, TSAN, and MSAN check**: Check if the binaries are compiled with support for AddressSanitizer, ThreadSanitizer, or MemorySanitizer.
- **Test Execution**: Use `ctest` to run tests in the specified directory and redirect the results to a file if indicated.
- **Flexible Configuration**: Allows you to specify the test directory, exclude certain directories, apply filtering

## Check events diff

- **Download and Conversion**: Download files from URLs if necessary and convert EVTX files to XML.
- **Test Execution**: Use `engine-test` to process the input file events.
- **Format and Comparison**: Format and sort results before comparing them to a reference file using `jq` and `engine-diff`.