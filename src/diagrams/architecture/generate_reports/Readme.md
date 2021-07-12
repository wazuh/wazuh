<!--- 
Copyright (C) 2015-2021, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->
# Generate reports architecture
## Index
1. [Purpose](#purpose)
2. [Sequence diagram](#sequence-diagram)
3. [Findings](#findings)

## Purpose
Generate reports feature (Reportd) was created to generate and send reports via email based on several configurations.

## Sequence diagram
Sequence diagram shows the basic flow of generate reports feature hosted in monitord module. Each time the current day change is detected monitord module spawns a process per configured report to generate and send reports through email. Steps are:
1. Create a new child process using fork.
2. The process will generate and send the report through email.
3. Repeat step 1 to 2 for each configured report.
4. Wait until all the child processes terminates.
5. If a process is taking to long to finish, sleep and try again later.
6. If the wait retries reached 10 or all the processes terminated, return.

## Findings
A number of issues related to synchronization and timing were found during the code walkthrough when creating the sequence diagrams.
* Generate reports and logs rotations runs on the same thread and both features has different timings and synchronization needs that are configured independently and should no be affected by others features configurations. This issue affects agents monitoring as well.
* In the future each selfcontained feature that runs as part of monitord module should be isolated and executed in a dedicated thread to avoid coupling and timing/sync issues.
