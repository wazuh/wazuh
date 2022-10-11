<!---
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: Data Provider architecture
## Index
- [Wazuh module: Data Provider architecture](#wazuh-module-data-provider-architecture)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Sequence diagrams](#sequence-diagrams)


## Purpose
Everyone knows the importance of having detailed system information from our environment to take decisions based on specific use cases. Having detailed and valuable information about our environment helps us react to under unpredictable scenarios. Wazuh agents are able to collect interesting and valuable system information regarding processes, hardware, packages, OS, network and ports.

The System Inventory feature interacts with different modules to split responsibilities and optimize internal dependencies:
- Data Provider: Module in charge of gathering system information based on OSes. This involves information about current running processes, packages/programs installed, ports being used, network adapters and OS general information.
- DBSync: This module has one single main responsibility: Database management. It manages all database related operations like insertion, update, selection and deletion. This allows Wazuh to centralize and unify database management to make it more robust and to avoid possible misleading data.
- RSync: It is in charge of database synchronization between Wazuh agents DBs and Wazuh  manager DBs (each agent DB). RSync implements a unified and generic communication algorithm used to maintain Wazuh agents and Wazuh manager datasets consistency.
- Syscollector: Module in charge of getting system information from Data Provider module and updating the local agent database (through dbsync module). Once this is done, the rsync module calculates the information to synchronize with the Wazuh manager.


## Sequence diagrams
The different sequence diagrams illustrate the data provider's workflow to obtain the information.

- 001-sequence-windows-store-packages-info: Explains how the data provider module obtains the packages information from the Windows Store.

