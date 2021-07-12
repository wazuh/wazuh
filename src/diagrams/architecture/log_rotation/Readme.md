<!--- 
Copyright (C) 2015-2021, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Logs rotation architecture
## Index
1. [Purpose](#purpose)
2. [Sequence diagram](#sequence-diagram)
3. [Findings](#findings)

## Purpose
Logs rotation feature was created to rotate the internal logs on daily basis or when they reach a configured max size. Logs rotation runs as part of monitord module and it's responsible of compressing and signing the old logs as well.

## Sequence diagram
Sequence diagram shows the basic flow of logs rotation feature hosted in monitord module. Each time the current day change is detected monitord module performs logs rotation, signing and compression based on the current configuration. Steps are:
1. Rotate logs.
2. Sign rotated logs.
3. Compress rotated logs.
Monitord checks every 1 seconds the size of the logs and decides if they need to be rotated based on the max size configured. In this case, logs are only rotated but not singed neither compressed.

## Findings
A number of issues related to synchronization and timing were found during the code walkthrough when creating the sequence diagrams.
* Generate reports and logs rotations runs on the same thread and both features has different timings and synchronization needs that are configured independently and should no be affected by others features configurations. This issue affects agents monitoring as well.
* In the future each selfcontained feature that runs as part of monitord module should be isolated and executed in a dedicated thread to avoid coupling and timing/sync issues.
