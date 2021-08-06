<!---
Copyright (C) 2015-2021, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: SCA architecture
## Index
1. [Purpose](#purpose)
2. [Sequence Diagram](#sequence-diagram)

## Purpose
The security configuration assessment module (**SCA**) performs hardening and configuration scans based on custom policies, created and maintained by Wazuh's team based on CIS benchmarks.

This module is composed of a main thread, from which two other secondary threads diverge. These threads are:

- The main thread: In charge of parsing and converting to **JSON** the **YML** policies. These policies are then stored and executed accordingly. This thread contains high amounts of memory management and should be looked at closely, especially the `cis_db_for_hash` global structure, which seems to contain detailed information from all checks.

- `wm_sca_dump_db_thread`: In charge of dumping the scan results into the manager's **SCA** database.

- `wm_sca_request_thread`: In charge of requesting information if missing data is detected. Non-suspicious memory management.


## Sequence Diagram
The provided sequence diagram shows the basic flow of Wazuh's **SCA** module. The main steps are:
1. **SCA**'s main thread starts working according to the configuration provided in `ossec.conf`.
2. Policies are stored in memory.
3. Dump and request threads originate from the main one. They continue to run in parallel in an infinite loop. 
4. The main thread enters in its main, infinite loop.
5. Said thread sleeps according to the time set in the configuration.
6. The whole parsing and scanning process starts working for each policy:
    1. The **YAML** parser is created. The **YAML** to **CJSON** conversion is started.
    2. The policy is stored through different **CJSON** objects.
    3. Error handling.
    4. Checks are tested/executed.
7. Lastly, scanned policies are sent for database purge on manager side, and then the loops starts again.

## Findings
See https://github.com/wazuh/wazuh/issues/9281#issuecomment-887336323
