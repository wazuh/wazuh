<!---
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: Office365 architecture
## Index
1. [Purpose](#purpose)
2. [Sequence Diagram](#sequence-diagram)
3. [Findings](#findings)

## Purpose
The audit log allows organization admins to quickly review the actions performed by members of your organization. It includes details such as who performed the action, what the action was, and when it was performed. 

Wazuh allows you to collect all the logs from Office 365 using its API through:
- Office365 module

## Sequence Diagram
Sequence diagram shows the basic flow of Wazuh Office365 integration based on the configuration provided. Steps are:
1. Setup the Office365 module based on the configuration information, set tenant_id, client_id, and client_secret or client_secret_path.
2. Generate a request with configuration information to get access token.
3. Generate a request to start a subscription for each content type.
4. Generate a request to get content blobs for each content type.
5. Generate a request to get logs for each content blob.
6. Process answered request and audit logs.
7. Submit the events to be processed by the Wazuh manager.


## Findings
* Sensitive information can be detected (tenant_id, client_id, and client_secret or client_secret_path) into ossec.conf file, because is used as a plain text without obfuscation. This can lead to potential attacks and information theft.
