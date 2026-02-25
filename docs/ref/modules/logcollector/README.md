# Logcollector

## Introduction

Log data collection involves gathering and consolidating logs from different log sources within a network. Log data collection helps security teams to meet regulatory compliance, detect and remediate threats, and identify application errors and other security issues.

Wazuh collects, analyzes, and stores logs from endpoints, network devices, and applications. The Wazuh agent, running on a monitored endpoint, collects and forwards system and application logs to the Wazuh server for analysis. Additionally, you can send log messages to the Wazuh server via syslog, or third-party API integrations.

## Table of content




## How it works

Wazuh uses the Logcollector module to collect logs from monitored endpoints, applications, and network devices. The Wazuh server then analyzes the collected logs in real-time using decoders and rules, and extracts relevant information from the logs and maps them to appropriate fields , generating alerts when the logs meets certain criteria.
