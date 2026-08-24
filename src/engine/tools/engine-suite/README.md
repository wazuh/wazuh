# Engine python suite tools

1. [Summary](#summary)
2. [Directory structure](#directory-structure)
    1. [Engine router](#engine-router)
    1. [Engine test](#engine-test)
    1. [Engine event dumper](#engine-event-dumper)
    1. [Engine public](#engine-public)
    1. [Engine private](#engine-private)
3. [Installation](#installation)

## Summary

The `engine-suite` python package contains a set of tools that allow you to manage and interact with the Wazuh engine.
These tools are designed to facilitate the management of assets, policies, integrations, and other elements of the
Wazuh environment, providing a centralized and efficient way to perform these tasks.

# Directory structure

```plaintext
├── engine-suite/
│   └── src
│       └── engine_event_dumper
│       └── engine_private
│       └── engine_public
│       └── engine_router
│       └── engine_test
│       └── shared
```

## Engine router

- **Route management**:
    - **List and Get Routes**: Provides the ability to list and get details of routes.
    - **Creation of Routes**: Allows you to create new routes, specifying assets such as decoders, rules, integrations, etc.
    - **Deletion and Update**: Provides the ability to delete or update existing routes, providing flexibility in configuration management.
- **EPS management**:
    - **Set EPS Limit**: Allows you to set the EPS limit for routes, ensuring that the system does not exceed the specified limit.
    - **Get EPS Limit**: Provides the ability to get the EPS limit for routes.
    - **Enable/Disable EPS Limit**: Allows you to enable or disable the EPS limit for routes.

For more details, refer to src/engine_router/README.md.

## Engine test

- **Integrations Management**:
    - **Creation of Integrations**: Facilitates the creation of new integrations, where it is necessary to specify the format. Formats may include `audit`, `syslog`, `multiline`, `remote syslog`, `json`, among others.
    - **Deletion and Update**: Allows you to delete or update existing integrations, providing flexibility in configuration management.
    - **Getting Integrations**: Provides the ability to list and get details of configured integrations.

- **Test Execution**:
    - This subcommand allows you to test decoders or rules by creating test sessions.
    - Allows the introduction of specific events and following the trace of these events through the different assets (decoders, rules, etc.) that make up a particular policy.
    - Facilitates the analysis of how an event is processed by the engine, helping in the debugging.

For more details, refer to src/engine_test/README.md.

## Engine event dumper

- **Event Dumper Management**: Activates, deactivates, and reports the status of the engine's internal event dumper, which persists raw events for forensic investigation.

For more details, refer to src/engine_event_dumper/README.md.

## Engine public

- **Content Validation**: Validates a full policy (`cm policy-validate`) or a single resource (`cm validate`) against the engine, optionally loading a validated policy into a testing session.
- **Logtest Cleanup**: Removes the active logtest testing session and its temporary namespace (`cm logtest-cleanup`).
- **Engine Status**: Reports whether the engine has all required resources available to process events (`status get`).

For more details, refer to src/engine_public/README.md.

## Engine private

- **Namespace Management**: Lists, creates, deletes, and imports namespaces.
- **Content Manager CRUD**: Lists, gets, upserts, and deletes policies and resources (decoders, rules, filters, integrations, kvdbs) within a namespace.
- **Geo**: Queries and lists the loaded GeoIP/ASN databases.
- **Raw Event Indexer**: Reports the status of the raw event indexer.

These are internal-only operations, not intended for use outside development and testing.

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
- [engine-router](src/engine_router/README.md)
- [engine-test](src/engine_test/README.md)
- [engine-event-dumper](src/engine_event_dumper/README.md)
- [engine-public](src/engine_public/README.md)
- `engine-private` (internal/private administrative commands — content manager, geo, namespace, and raw-event handling; no README yet, see `src/engine_private/cmds/`)
