# Logcollector

## Introduction

Log data collection involves gathering and consolidating logs from different log sources within a network. Log data collection helps security teams to meet regulatory compliance, detect and remediate threats, and identify application errors and other security issues.

Wazuh collects, analyzes, and stores logs from endpoints, network devices, and applications. The Wazuh agent, running on a monitored endpoint, collects and forwards system and application logs to the Wazuh server for analysis. Additionally, you can send log messages to the Wazuh server via third-party API integrations.

## Table of content

- [Log collectors](collectors.md)
- [Configuration](configuration.md)

## How it works

Logcollector runs on the agent as the `wazuh-logcollector` daemon; the manager does not run it. It reads the
sources configured with `<localfile>` in the agent's `/var/ossec/etc/ossec.conf` or in a group's centralized
`agent.conf`, and hands each event to `wazuh-agentd`, which sends it to the manager. A `<localfile>` can instead send
its events to a local Unix socket (`<socket>`).

Wazuh uses the Logcollector module to collect logs from monitored endpoints, applications, and network devices. The Wazuh server then analyzes the collected logs in real-time using decoders and rules, and extracts relevant information from the logs and maps them to appropriate fields, generating alerts when the logs meet certain criteria.
