
<!--- 
Copyright (C) 2015-2021, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Agent disconnection handling

## Index
  - [Purpose](#purpose)
  - [Configurations](#configurations)
  - [Sequence diagram](#sequence-diagram)
  - [Findings](#findings)

## Purpose

One of the responsabilities of `monitor` module, part of Wazuh Manager, is to check and update [agent status](https://documentation.wazuh.com/current/user-manual/agents/agent-life-cycle.html) periodically from the Wazuh Manager perspective, specifically the `active` to `disconnected` transition. Agent status is stored in `connection_status` column in `global.db` database in the Wazuh Master node.

While `monitor` module focus on `active` to `disconnected` status transition, other processes/modules are also closely involved in other status modifications.

## Configurations

- From `internals_options.conf`:
  - `monitord.delete_old_agents`: Number of minutes for deleting a disconnected agent. [0,9600]. Default: 0 (disabled)
  - `monitord.monitor_agents`: Toggle to enable or disable monitoring of agents.[0=do not monitor, 1=monitor]. Default: 1
- From `ossec.conf:`
  - `agents_disconnection_time`: time after which the manager considers an agent as disconnected since its last keepalive. [0;inf+). Default: 10m.
  - `agents_disconnection_alert_time`: time after which an alert is generated since an agent was considered as disconnected [0;inf+). Default: 0s.

## Sequence diagram

As sequence diagram shows, agent disconnection handling and alerting feature has four mayors activities:

- Scheduler with seconds granularity that triggers the next activities.
- Trigger agent disconnection mechanism against Wazuh DB using configured `agents_disconnection_time` criteria, 
- In case of `monitord.monitor_agents` is enabled, generate alert for those disconnected agents using configured `agents_disconnection_alert_time` criteria.
- In case of `monitord.monitor_agents` and `monitord.delete_old_agents` are enabled, delete all disconnected agents using configured `monitord.delete_old_agents`criteria.


## Findings

- Original `monitord.monitor_agents` meaning it is not current one. Nowdays this could be deprecated by adding disabling semantics to other configuration variables. 
- **Prevent pending agents from keeping their state indefinitely [#8975](https://github.com/wazuh/wazuh/issues/8975)]**.
- There's a fixed sleep of 10 seconds in the main loop of `monitor` in order to wait wazuh daemons settle. This should be replaced for a asynchronous mechanism.
- Scheduler is affected/skewed by the operations sequentially executed in monitor main loop,
