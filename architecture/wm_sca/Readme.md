<!---
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: SCA architecture
## Index
1. [Purpose](#purpose)
2. [Sequence Diagram](#sequence-diagram)

## Purpose
The security configuration assessment module (**SCA**) performs hardening and configuration scans following **YML** policies, which are created and maintained by Wazuh's team based on CIS benchmarks.

This module is composed of a main thread, from which two other secondary threads diverge. These threads are:

- The main thread: In charge of parsing and converting to **JSON** the **YML** policies. These policies are then stored and executed accordingly.

- `wm_sca_dump_db_thread`: In charge of dumping the scan results into the manager's **SCA** database.

- `wm_sca_request_thread`: In charge of processing dump requests from the manager when synchronization fails.

## Sequence Diagram
The provided sequence diagram shows the basic flow of Wazuh's **SCA** module. The main steps are:

1. **SCA** begins its start-up process:
    1. **SCA**'s main thread starts working according to the configuration provided in `ossec.conf`.
    2. Data structures are initialized. 
    3. Dump and request threads originate from the main one. They continue to run in parallel in an infinite loop.
2. The main thread starts its infinite loop, where the scans are performed:
    1. The **SCA** policies are dumped in memory
    2. The scan is conducted. Checks are tested/executed. 
    3. Results are stored in memory
3. Once the results are available, they are synchronized with the manager through `wm_sca_dump_db_thread`.
4. The `wm_sca_request_thread` keeps processing manager requests to ensure the synchronization succeeded
