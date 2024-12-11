# PostgreSQL Integration


|   |   |
|---|---|
| event.module | postgresql |

This integration processes messages from postgreSQL in CSV log format.

## Compatibility

The integration was tested with logs from version 11 to 15.

## Configuration

This integration uses the logcollector source localfile to ingest the logs from the agent. Add to the ossec.conf file in the monitored agent the following block:

```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/postgresql.csv</location>
  <log_format>json</log_format>
  <label key="event.module">postgresql</label>
  <label key="event.dataset">postgresql.log</label>
</localfile>
```

## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/postgresql-csv/0 | Decoder for PostgreSQL in CSV log format |
| decoder/postgresql-csv-msg-parse/0 | Decoder for messages from PostgreSQL in CSV log format |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for PostgreSQL | [#16766](#) |
