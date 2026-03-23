# Introduction

The **Inventory Sync module** is a stateful synchronization component responsible for managing the exchange of system inventory data between Wazuh agents and the Wazuh Indexer. It receives inventory state information from agents via FlatBuffer messages and guarantees reliable, persistent storage in the Indexer through a session-based synchronization protocol.

The module supports both **full** and **delta synchronization modes**, enabling efficient updates while minimizing redundant data transfer. During synchronization, it leverages a local **RocksDB** database for temporary storage, ensuring durability and consistency even under high-volume data flows.

To provide resilience against network interruptions or agent disconnections, the module implements **session timeout mechanisms** and ensures recovery without compromising data integrity. By integrating with the Indexer Connector, the Inventory Sync module delivers scalable and fault-tolerant indexing of agent inventory data.
