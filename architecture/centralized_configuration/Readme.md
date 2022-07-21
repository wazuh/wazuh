<!---
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Centralized Configuration
## Index
- [Centralized Configuration](#centralized-configuration)
  - [Index](#index)
  - [Purpose](#purpose)
  - [Sequence diagram](#sequence-diagram)

## Purpose

One of the key features of Wazuh as a EDR is the Centralized Configuration, allowing to deploy configurations, policies, rootcheck descriptions or any other file from Wazuh Manager to any Wazuh Agent based on their grouping configuration. This feature has multiples actors: Wazuh Cluster (Master and Worker nodes), with `wazuh-remoted` as the main responsible from the managment side, and Wazuh Agent with `wazuh-agentd` as resposible from the client side.


## Sequence diagram
Sequence diagram shows the basic flow of Centralized Configuration based on the configuration provided. There are mainly three stages:
1. Wazuh Manager Master Node (`wazuh-remoted`) creates every `remoted.shared_reload` (internal) seconds the files that need to be synchronized with the agents.
2. Wazuh Cluster as a whole (via `wazuh-clusterd`) continuously synchronize files between Wazuh Manager Master Node and Wazuh Manager Worker Nodes
3. Wazuh Agent `wazuh-agentd` (via ) sends every `notify_time` (ossec.conf) their status, being `merged.mg` hash part of it. Wazuh Manager Worker Node (`wazuh-remoted`) will check if agent's `merged.mg` is out-of-date, and in case this is true, the new `merged.mg` will be pushed to Wazuh Agent.