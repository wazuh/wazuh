<!---
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: Azure architecture
## Index
1. [Purpose](#purpose)
2. [Sequence diagram](#sequence-diagram)
3. [Findings](#findings)

## Purpose
Microsoft Azure infrastructure resources can be divided into two types of logs, the Activity logs and the Diagnostic logs. The operations performed on a resource outside of the infrastructure are stored in the Activity logs, providing information on those operations. On the other hand, the data referring to the operation of a resource is stored in the Diagnostic logs.

Wazuh has the ability to obtain and read Microsoft Azure logs through:
- Azure Log Analytics
- Azure Active Directory Graph
- Azure Storage


## Sequence diagram
Sequence diagram shows the basic flow of Wazuh azure integration based on the configuration provided. Steps are:
1. Setup the azure module based on the configuration information.
2. Get the configuration information to create a command with specific azure flags (depending de type of logs).
3. Execute the complete command.
4. At the end, the specific command being executed is the '/var/ossec/wodles/azure/azure-logs' one.
5. 'azure-logs' utility invokes a python script which is in charge of https communication with the Azure REST API.


## Findings
* Every time the 'azure-logs' script is being executed, sensitive information can be easily detected (secret keys) because is used as a plain text without obfuscation. This can lead to potential attacks and information theft.
