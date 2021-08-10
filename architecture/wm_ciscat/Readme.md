<!---
Copyright (C) 2015-2021, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: CIS-CAT architecture
## Index
1. [Purpose](#purpose)
2. [Sequence Diagram](#sequence-diagram)

## Purpose
The **CIS-CAT** Wazuh module integrates CIS benchmark assessments into Wazuh agents and reports the results of each scan in the form of an alert. The module requires the use of **CIS-CAT Pro**, an external tool developed for scanning target systems and generating a report comparing the system settings to the CIS benchmarks.

## Sequence Diagram
The provided sequence diagram shows the basic flow of Wazuh's **CIS-CAT** module. The main steps are:

1. The **SCIS-CAT** module is executed according to the configuration provided in `ossec.conf`. The module then sleeps, based on the specified timestamp.
2. Once the sleep time is over, the **CIS-CAT** script is executed.
3. The script scans the system and reports the results trough different files (**txt** and **xml**).
4. The **txt** file is parsed. The relevant information from this file is saved in memory (mostly `scan_info`). 
5. The **xml** file is parsed. The relevant information from this file is saved in memory (`rule_info`).
6. Once we have all the information (both generic and specific), we convert the data to a **JSON** structure to send the stored information to the manager.
7. The memory that has already been sent is freed.
8. The loop continues with its next iteration, starting again with the sleep.
