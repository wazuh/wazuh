# Redis Integration


|   |   |
|---|---|
| event.module | redis |

This integration processes Redis logs

## Compatibility

All Redis versions

## Configuration

This integration uses the logcollector source localfile to ingest the logs from the agent. Add to the ossec.conf file in the monitored agent the following block:

```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/redis/redis-server.log</location>
  <log_format>json</log_format>
  <label key="event.module">redis</label>
</localfile>
```

## Schema

| Field | Description | Type |
|---|---|---|
| redis.log.role | Role of the process. | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/redis/0 | Decoder for Linux redis logs |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Redis | [#16766](#) |
