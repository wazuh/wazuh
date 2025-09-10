# Introduction

The **Syscollector (Inventory)** module has been enhanced with a reliable synchronization mechanism that ensures system inventory changes are persisted and synchronized with the manager even during network interruptions or agent restarts.

The module implements a **dual event system** that provides both real-time alerts and reliable state synchronization. It leverages the **Agent Sync Protocol** to persist differences in a local SQLite database and synchronizes them periodically with the manager through a session-based protocol.

Unlike FIM which uses the C interface, Syscollector uses the **C++ interface** of the Agent Sync Protocol (`IAgentSyncProtocol`) for better integration with its C++ codebase.

Syscollector persistence supports **stateful synchronization** for complete system inventory including hardware, OS, network, packages, ports, processes, users, groups, services, and browser extensions, while maintaining **stateless real-time events** for immediate inventory change detection.
