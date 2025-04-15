# Architecture

This module uses a stateless design to process incoming messages and index them in the Wazuh Indexer. It integrates several design patterns (Facade, Factory Method, and Chain of Responsibility) to modularize responsibilities and simplify maintenance. Below is an overview of the main components and their roles.

## Main Components

- **`src/wazuh_modules/inventory_harvester/src/inventoryHarvester.cpp`**
  The primary module file that defines the `InventoryHarvester` class and its methods. It orchestrates how incoming messages are ingested and then handed off for indexing.

- **`src/wazuh_modules/inventory_harvester/src/inventoryHarvesterFacade.cpp`**
  A **Facade** class that provides a simplified interface to `InventoryHarvester`. By masking the underlying logic of:

  - Flatbuffer message handling
  - Index schema management
  - Bulk operations

  So the external components interact with `InventoryHarvester` through a unified, minimal interface.

- **`src/wazuh_modules/inventory_harvester/src/common/`**
  A folder containing common operations used by the `InventoryHarvester` module:

  - **`clearAgent`**: Removes all data related to an agent (when the agent is removed from the manager) by sending a `DELETED_BY_QUERY` message to the Wazuh Indexer.
  - **`clearElements`**: Similar to the previous operation, this function is triggered by `DeleteAllEntries` message types mapped to `integrity_clear` events from the `FIM` and `Syscollector` modules.
    - In the `Syscollector` module, `integrity_clear` events are sent to the manager for each provider when it is disabled in the configuration file. i.e. packages, ports, hardware.
    - In the `FIM` module, `integrity_clear` events are sent to the manager for the `fim_file` component when no directories are being monitored. Similarly, for `Windows` systems, they are sent for the `fim_registry_key` and `fim_registry_value` components when no registries are being monitored.
  - **`elementDispatch`**: Dispatches incoming elements to the correct handler based on the element type.
  - **`indexSync`**: Synchronizes indices with the Wazuh Indexer.
  - **`upgradeAgentDb`**: Action that performs that performs a re-synchronization when upgrading the manager from a legacy version.

- **`src/wazuh_modules/inventory_harvester/src/fimInventory/` and `src/wazuh_modules/inventory_harvester/src/systemInventory/`**
  These folders combine the **Factory Method** and **Chain of Responsibility** patterns:

  - **Factory Method**: Defines an interface for creating indexer-related objects (e.g., index writers or message handlers), while allowing subclasses to decide the specific type of object to instantiate. This ensures the creation logic is flexible and easily modifiable.
  - **Chain of Responsibility**: Organizes handlers (validation, indexing, error handling, etc.) in a chain. Each handler can either process a request or delegate it to the next handler, making the ingestion/indexing pipeline more maintainable and extensible.

- **`src/wazuh_modules/inventory_harvester/src/wcsModel/`**
  Contains schema definitions for the **Wazuh Common Schema (WCS)** models. By adhering to WCS, the InventoryHarvester ensures consistency and compatibility across Wazuh modules. The models capture essential information (system inventory, FIM data, etc.) and use a **JSON reflection mechanism** to convert internal data structures into JSON for the Wazuh Indexer.

## High-Level Architecture Diagram

@ToDo
