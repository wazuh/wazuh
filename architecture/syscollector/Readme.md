<!---
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: Syscollector architecture
## Index
- [Wazuh module: Syscollector architecture](#wazuh-module-syscollector-architecture)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Sequence diagrams](#sequence-diagrams)


## Purpose
Everyone knows the importance of having detailed system information from our environment to take decisions based on specific use cases. Having detailed and valuable information about our environment helps us to react under unpredictable scenarios. The wazuh agents are able to collect interesting and valuable system information regarding processes, hardware, packages, OS, network and ports.

The System Inventory feature implements a **dual event system** with **persistent synchronization** to ensure reliability:

### Architecture Components:
- **Data Provider (SysInfo)**: Module in charge of gathering system information based on OSes. This involves information about current running processes, packages/programs installed, ports being used, network adapters and OS general information.
- **DBSync**: This module has one single main responsibility: Database management. It manages all database related operations like insertion, update, selection and deletion. This allows Wazuh to centralize and unify database management to make it more robust and to avoid possible data misleading.
- **Agent Sync Protocol**: Provides persistent, reliable synchronization between Wazuh agents and manager. It implements a session-based communication protocol that ensures data consistency even during network interruptions or agent restarts. Uses SQLite for persistent storage of pending synchronization data.
- **Syscollector**: Module in charge of getting system information from Data Provider module and updating the local agent database (through dbsync module). It implements a dual event system:
  - **Stateless event**: Immediate stateless notifications for inventory changes
  - **Persistent synchronization**: Stateful reliable data synchronization through Agent Sync Protocol

### Key Features:
- **Persistent Storage**: All inventory changes are stored in a dedicated sync protocol database for reliable delivery
- **Session-based Sync**: Synchronization uses unique session IDs to track progress and handle failures


## Sequence diagrams
The different sequence diagrams illustrate the flow of the different modules interacting on the syscollector general use, including the new persistent synchronization implementation:

- **001-sequence-wm-syscollector**: Explains the wazuh module syscollector initialization, construction, use, destruction and stop from the wazuh modules daemon perspective. Updated to show Agent Sync Protocol library dependency.
- **002-sequence-syscollector**: Explains the syscollector internal interactions with modules like dbsync, Agent Sync Protocol, and normalizer. This diagram shows how the dual event system works, including real-time alerts and persistent synchronization flow, checksum calculation, scan starting, etc.
- **003-sequence-manager-side**: It explains the modules interaction (analysisd, wdb) when a syscollector message arrives from the manager perspective. This diagram shows how is the flow from the modules initialization to the database storage.

