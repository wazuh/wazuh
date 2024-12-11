# Fortinet Integration


|   |   |
|---|---|
| event.module | fortinet |

This integration processes logs from:
  - Fortinet FortiClient Endpoint
  - Fortinet FortiGate Firewall
  - Fortinet FortiMail
  - Fortinet FortiManager Endpoint


## Compatibility

This integration has been tested against FortiOS version 6.0.x and 6.2.x.


## Configuration

Events may be collected in two ways:
1. Logcollector Using the logcollector source localfile to ingest the logs from the agent. Add to the ossec.conf file in the monitored agent the following blocks:
```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[FortiClient log path]</location>
  <log_format>json</log_format>
  <label key="event.module">fortinet</label>
  <label key="event.dataset">fortinet.clientendpoint</label>
</localfile>
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[Fortinet firewall log path]</location>
  <log_format>json</log_format>
  <label key="event.module">fortinet</label>
  <label key="event.dataset">fortinet.firewall</label>
</localfile>
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[FortiMail log path]</location>
  <log_format>json</log_format>
  <label key="event.module">fortinet</label>
  <label key="event.dataset">fortinet.fortimail</label>
</localfile>
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[FortiManager log path]</location>
  <log_format>json</log_format>
  <label key="event.module">fortinet</label>
  <label key="event.dataset">fortinet.fortimanager</label>
</localfile>
```

2. Remote Syslog

#TODO: Add remote syslog configuration


## Schema

| Field | Description | Type |
|---|---|---|
| fortinet.firewall.severity | The severity of the event as reported by the Fortinet firewall. | keyword |
| fortinet.firewall | The event reported by the Fortinet firewall. | object |
## Decoders

| Name | Description |
|---|---|
| decoder/fortinet-firewall/0 | Decoder for parsing fortinet firewall logs |
| decoder/fortinet-fortimail/0 | Decoder for Fortinet fortimail |
| decoder/fortinet-client-endpoint/0 | Decoder for Fortinet FortiClient Endpoint Security |
| decoder/fortinet-fortimanager/0 | Decoder for Fortinet FortiManager Endpoint Security |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Fortinet | [#16766](#) |
