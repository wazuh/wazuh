# Wazuh Docker Listener Integration


|   |   |
|---|---|
| event.module | docker-listener |
| event.dataset | wodle-docker-listener |

This integration receives, parses and processes logs obtained with the docker-listener wodle from docker. This are real-time events from the docker server.

Docker events can be of different types:
* Containers
* Images
* Plugins
* Volumes
* Networks
* Daemons
* Services
* Nodes
* Secrets
* Configs

Each one of them having they're own event status and fields.
More details of this fields [here](https://docs.docker.com/engine/reference/commandline/events/).

This events are received and forwarded directly with the docker-listener wodle.
More information on how to use and a example on how to achieve this [here](https://documentation.wazuh.com/current/proof-of-concept-guide/monitoring-docker.html).


## Compatibility

This module has been tested against docker version 24.0.2 wazuh agent 4.4.3 in ubuntu 22


## Configuration

Docker-listener wodle can be configured and set on the manager or the agent, depending on where is docker used.
The default configuration sets:
 * _interval_ to 1m: This is the waiting time to rerun the wodle in case it fails.
 * _attempts_ to 5: Number of attempts to execute the wodle.
 * _run_on_start_ to yes: Run command immediately when service is started.

More information on each configuration field [here](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-docker.html).

Example on the wodle configuration:
```xml
<wodle name="docker-listener">
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
