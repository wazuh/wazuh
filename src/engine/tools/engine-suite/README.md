# Engine python suite tools

1. [Summary](#summary)
2. [Directory structure](#directory-structure)
    1. [Engine clear](#engine-clear)
    1. [Engine decoder](#engine-decoder)
    1. [Engine diff](#engine-diff)
    1. [Engine integration](#engine-integration)
    1. [Engine policy](#engine-policy)
    1. [Engine router](#engine-router)
    1. [Engine test](#engine-test)
3. [Installation](#installation)

## Summary

The `engine-suite` python package contains a set of tools that allow you to manage and interact with the Wazuh engine.
These tools are designed to facilitate the management of assets, policies, integrations, and other elements of the
Wazuh environment, providing a centralized and efficient way to perform these tasks.

# Directory structure

```plaintext
├── engine-suite/
│   └── src
│       └── engine_clear
│       └── engine_catalog
│       └── engine_decoder
│       └── engine_diff
│       └── engine_integration
│       └── engine_policy
│       └── engine_router
│       └── engine_schema
│       └── engine_test
│       └── shared
```

## Engine clear

- **Resource Elimination**:
    You can delete user-specified or default resources in different namespaces such as `user`, `wazuh`, and `system`. This is useful for keeping the environment clean and organized.
    To prevent accidental deletions, the module requests confirmation before proceeding with resource deletion, unless the `--force` option is used to force execution without confirmation.

- **Support for Namespaces**:
    Users can specify which namespaces resources should be removed from. If not specified, the module removes them from the default namespaces.

- **Deletion of Policies and Assets**:
    In addition to kvdbs, can handle the removal of policies and other assets within the Wazuh environment, ensuring that all elements related to rules and configurations are aligned with the desired changes.

## Engine catalog
- **Catalog Management**:
    - **List and Get assets**: Provides the ability to list and get details of assets such as decoders, rules, integrations, etc.
    - **Creation of Assets**: Allows you to create new assets, such as decoders, rules, integrations, etc.
    - **Deletion and Update**: Provides the ability to delete or update existing assets, providing flexibility in configuration management.
    - **Validation**: Validates the syntax of the asset files, ensuring that they are correctly formatted and can be used by the engine.

## Engine decoder

- **Updating Auxiliary Function Names**:
    Allows you to change the names of auxiliary functions in decoders in bulk. You can specify an old-new name pair or provide a file containing a list of names to replace.

- **Extraction of Decoder Fields**:
    Provides the ability to list all fields extracted by a specific decoder, by parsing the expressions used in the `parse` and `normalize` sections of the decoder file.

## Engine diff

- **File Comparison**: Compares two event files in YAML or JSON formats, determining if they are identical or different.

- **Sort and Difference Detection**: Sorts the events and detects different keys and values ​​between the compared files, showing key differences.

- **Integration with External Tools**: Use the Delta tool for a clear visualization of the differences.

- **Execution Options**: Includes a silent mode to show only the result and allows you to disable event sorting


## Engine integration

- **Integrations Management**: Allows you to create, add, update and delete integrations centrally.

- **Generation of Documentation and Resources**: Generates documentation, graphics and manifests for integrations, facilitating administration and monitoring.

## Engine policy
- **Policy Management**:
    - **List and Get Policies**: Provides the ability to list and get details of policies.
    - **Creation of Policies**: Allows you to create new policies, specifying assets such as decoders, rules, integrations, etc.
    - **Deletion and Update**: Provides the ability to delete or update existing policies, providing flexibility in configuration management.

## Engine router
- **Route management**:
    - **List and Get Routes**: Provides the ability to list and get details of routes.
    - **Creation of Routes**: Allows you to create new routes, specifying assets such as decoders, rules, integrations, etc.
    - **Deletion and Update**: Provides the ability to delete or update existing routes, providing flexibility in configuration management.
- **EPS management**:
    - **Set EPS Limit**: Allows you to set the EPS limit for routes, ensuring that the system does not exceed the specified limit.
    - **Get EPS Limit**: Provides the ability to get the EPS limit for routes.
    - **Enable/Disable EPS Limit**: Allows you to enable or disable the EPS limit for routes.

## Engine test

- **Integrations Management**:
    - **Creation of Integrations**: Facilitates the creation of new integrations, where it is necessary to specify the format. Formats may include `audit`, `syslog`, `multiline`, `remote syslog`, `json`, among others.
    - **Deletion and Update**: Allows you to delete or update existing integrations, providing flexibility in configuration management.
    - **Getting Integrations**: Provides the ability to list and get details of configured integrations.

- **Test Execution**:
    - This subcommand allows you to test decoders or rules by creating test sessions.
    - Allows the introduction of specific events and following the trace of these events through the different assets (decoders, rules, etc.) that make up a particular policy.
    - Facilitates the analysis of how an event is processed by the engine, helping in the debugging.

## Engine integration

- **Integrations Management**: Allows you to create, add, update and delete integrations centrally.

- **Generation of Documentation and Resources**: Generates documentation, graphics and manifests for integrations, facilitating administration and monitoring.

## Engine test

- **Integrations Management**:
    - **Creation of Integrations**: Facilitates the creation of new integrations, where it is necessary to specify the format. Formats may include `audit`, `syslog`, `multiline`, `remote syslog`, `json`, among others.
    - **Deletion and Update**: Allows you to delete or update existing integrations, providing flexibility in configuration management.
    - **Getting Integrations**: Provides the ability to list and get details of configured integrations.

- **Test Execution**:
    - This subcommand allows you to test decoders or rules by creating test sessions.
    - Allows the introduction of specific events and following the trace of these events through the different assets (decoders, rules, etc.) that make up a particular policy.
    - Facilitates the analysis of how an event is processed by the engine, helping in the debugging.

# Installation

Requires:
- `python 3.8`
- `pip3`
-`tools/engine-suite` package.

To install navigate where the Wazuh repository folder is located and run:
```
pip3 install tools/engine-suite
```
If we want to install for developing and modifying the scripts, install in editable mode and the additional dev packages:
```
pip3 install -e tools/engine-suite[dev]
```
**For developing we recommend to install it under a virtual environment.**

Once installed the following scripts are available in the path:
- [engine-schema](src/engine_schema/README.md)
- [engine-decoder](src/engine_decoder/README.md)
- [engine-catalog](src/engine_catalog/README.md)
- [engine-integration](src/engine_integration/README.md)
- [engine-diff](src/engine_diff/README.md)
- [engine-clear](src/engine_clear/README.md)
- [engine-test](src/engine_test/README.md)
