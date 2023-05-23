# Syslog Integration


|   |   |
|---|---|
| event.module | syslog |

This integration processes logs with Syslog RFC 3164 format. By default, `/var/log/auth.log`, `/var/log/syslog/`, `/var/log/dpkg.log` and `/var/log/kern.log` files are read but it can be extended to any syslog-formatted inputs.


## Compatibility

This integration allows ingesting logs that are formatted as specified in the Syslog RFC 3164 standard. Please, see https://www.ietf.org/rfc/rfc3164.txt.


## Configuration

For example, a localfile can be added to the `ossec.conf` file in a monitored agent as in the following block:
```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/tmp/syslog_formatted.log</location>
  <log_format>syslog</log_format>
</localfile>
```


## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/syslog/0 | Syslog header |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Syslog | [#17194](#) |
