# InventoryHarvester

## Overview

The **InventoryHarvester** module receives inventory data events as flatbuffer messages through the router IPC mechanism and stores it in the Wazuh Indexer. By centralizing information about system inventory—such as hardware, software, network details, and File Integrity Monitoring (FIM) events, this module makes the data readily available for querying, visualization, and deeper analysis. Offloading this information to the Wazuh Indexer, rather than storing it on the Manager, helps prevent performance bottlenecks.

### Key Responsibilities

- **Receive** inventory data (e.g., hardware/software/network details, FIM data) via flatbuffer messages.
- **Index** all collected data in the Wazuh Indexer in accordance with global state requirements.
- **Manage** bulk operations, reducing overhead and improving overall performance.
- **Integrate** seamlessly with FIM and other Wazuh modules that rely on inventory data.

### Data Flow

1. **Message Ingestion**

   - Both the `System inventory` module and the `FIM` module event messages arrive to the manager.
   - Flatbuffer messages arrive to the Inventory Harvester module through the router.

2. **Deserialization & Validation**

   - Each message is deserialized, validated, and processed for indexing.

3. **Indexer Connector**

   - Validated data is batched and sent to the Wazuh Indexer in bulk, minimizing overhead.

4. **Storage**

   - The data is stored in a dedicated global state index, following Wazuh Common Schemas (WCS). There is one index for each type of inventory data.

5. **Monitoring & Feedback**
   - Any indexing issues or failures are reported to the relevant components for retries or error handling.

---

### Supported modules

1. **System inventory**

   - System: Operating system running on agent.
   - Programs: Installed programs in the agent endpoint.
   - Processes: Running programs in the agent endpoint at the moment of the scan.
   - Hotfixes: Installed vulnerability and fix patches for Windows system endpoints.
   - Hardware: Installed CPU and memory information.
   - Network protocol: Network protocol shows information for detected network interfaces.
   - Network address: Current network connection.
   - Network interface: Descriptive information of network interfaces.
   - Ports: Details about open ports in the agent endpoint.
   - Users: Detailed information for each user registered in the OS for control access and permissions.
   - Groups: Detailed information for each group present in the OS for control access and permissions.

2. **File Integrity Monitoring**

   - Files: Monitored files
   - Registries: Monitored registries for Windows system endpoints.

---

## Related Epic

FIM (File Integrity Monitoring) and Inventory modules can leverage global queries in the Wazuh Indexer to perform complex searches and filtering on collected data. This capability significantly enhances Wazuh’s security and compliance features.

- **Epic**: [#27894 – Global Queries for FIM and Inventory Modules](https://github.com/wazuh/wazuh/issues/27894)
- **Responsible Team**: [@wazuh/devel-xdrsiem-server](https://github.com/orgs/wazuh/teams/devel-xdrsiem-server)

---

## Functional Requirements

- Users can run **built-in** visualizations and queries on **FIM** and **System Inventory** global state data.
- Users can create **custom** visualizations and queries for the same data.
- Users **cannot edit or delete** a global state index or its data directly.
- When an **agent is removed**, the global state data reflects the removal.
- Supports both **Wazuh server cluster** and **Wazuh server standalone** deployments.
- **FIM** and **System Inventory** schemas must comply with **WCS**.

## Non-Functional Requirements

- Global state changes are reflected in the Wazuh Indexer based on whichever of the following occurs first:
  - **25,000** accumulated change events.
  - **20 seconds** after the last bulk operation.
- Hardware resource usage (CPU, memory, storage) must stay within acceptable limits.
- No new external libraries, frameworks, or dependencies are introduced.

## Implementation Restrictions

- **FIM** and **system inventory** global state data resides in the Wazuh Indexer.
- The **Indexer connector** handles the creation of required indices.
- Permissions to edit or delete **global state indices** differ from regular user permissions.
- **Manager-Indexer synchronization** is guaranteed when both operate under the same Wazuh version.
- FIM and system inventory fields follow a **common schema** wherever possible.
- The **UI** for FIM and system inventory is designed to mirror the **Vulnerability Detector** interface for consistency.

## Implementation Missing Features

- Currently, the events indexation for **agent 000 (Wazuh manager)** is not supported.
