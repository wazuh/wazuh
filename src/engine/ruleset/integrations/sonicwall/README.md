# SonicWall Firewall Integration


|   |   |
|---|---|
| event.module | sonicwall |

This integration processes logs from SonicWall Firewall


## Compatibility

This integration has been tested with logs from version 6.5


## Configuration

Events may be collected in two ways:
1. Logcollector Using the logcollector source localfile to ingest the logs from the agent. Add to the ossec.conf file in the monitored agent the following block:
```xml <localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[SonicWall Firewall log path]</location>
  <log_format>json</log_format>
  <label key="event.module">sonicwall</label>
  <label key="event.dataset">sonicwall.firewall</label>
</localfile> ```
2. Remote Syslog
#TODO: Add remote syslog configuration


## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/sonicwall-syslog/0 | Syslog header |
| decoder/sonicwall-firewall-generated/0 | Decoder for generated Firmware module logs belonging to Sonicwall |
| decoder/sonicwall-firewall/0 | Decoder for Firmware module logs belonging to Sonicwall |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for SonicWall Firewall | [#16766](#) |
