# Wazuh Docker Listener Integration


|   |   |
|---|---|
| event.module | docker-listener |

This integration processes logs obtained with the docker-listener wodle from docker. This are real-time events from the docker server.


## Compatibility

This module has been tested against docker version 20.10.12 and wazuh 4.4


## Configuration

Event are collected setting the ossec in the agent or the manager in the following way:
```xml <wodle name="docker-listener">
    <interval>10m</interval>
    <attempts>5</attempts>
    <run_on_start>yes</run_on_start>
    <disabled>no</disabled>
</wodle>
```


## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/docker-listener/0 | Process events that comes from the Docker listener wodle |
## Rules

| Name | Description |
|---|---|
## Outputs

| Name | Description |
|---|---|
## Filters

| Name | Description |
|---|---|
## Changelog

| Version | Description | Details |
|---|---|---|
| 0.0.1-dev | Created integration for docker-listener wodle | [#17406](https://github.com/wazuh/wazuh/pull/17406) |
