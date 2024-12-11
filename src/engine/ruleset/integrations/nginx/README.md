# NGINX Integration


|   |   |
|---|---|
| event.module | nginx |

This integration processes NGINX access logs and NGINX error logs.

## Compatibility

The integration was tested with logs from version 1.23.2

## Configuration

This integration uses the logcollector source localfile to ingest the logs from /var/log/nginx/access.log and /var/log/nginx/error.log. Add to the ossec.conf file in the monitored agent the following blocks:

```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/nginx/error.log</location>
  <log_format>json</log_format>
  <label key="event.module">nginx</label>
  <label key="event.dataset">nginx-error</label>
</localfile>
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/nginx/access.log</location>
  <log_format>json</log_format>
  <label key="event.module">nginx</label>
  <label key="event.dataset">nginx-access</label>
</localfile>
```
## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/nginx-access/0 | Parses nginx access logs |
| decoder/nginx-error/0 | Nginx error log decoder |
| decoder/nginx-access-base/0 | Parses nginx access logs |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for NGINX | [#16766](#) |
