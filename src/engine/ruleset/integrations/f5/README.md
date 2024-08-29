# F5 BIG-IP Integration


|   |   |
|---|---|
| event.module | f5 |

This integration processes logs from:
  - F5 BIG-IP Advanced Firewall Manager
  - F5 BIG-IP Access Policy Manager


## Compatibility

This integration has been tested against F5 BIG-IP version 16.1.0


## Configuration

Events may be collected in two ways:
1. Logcollector Using the logcollector source localfile to ingest the logs from the agent. Add to the ossec.conf file in the monitored agent the following blocks:
```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[AFM log path]</location>
  <log_format>json</log_format>
  <label key="event.module">f5</label>
  <label key="event.dataset">f5.bigipafm</label>
</localfile>

<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[APM log path]</location>
  <log_format>json</log_format>
  <label key="event.module">f5</label>
  <label key="event.dataset">f5.bigipapm</label>
</localfile>
```

2. Remote Syslog

#TODO: Add remote syslog configuration


## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/f5-apm/0 | Decodes F5 BIG-IP Access Policy Manager logs |
| decoder/f5-afm/0 | Decodes F5 BIG-IP Advanced Firewall Manager logs |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for F5 BIG-IP | [#16766](#) |
