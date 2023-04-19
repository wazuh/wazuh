# Windows Integration


|   |   |
|---|---|
| event.module | windows |

This integration processes events from Windows Event Logs

## Compatibility

All Windows versions

## Configuration

This integration will work with standard Wazuh configuration. Additional configuration may be needed to capture specific logs.

## Schema

| Field | Description | Type |
|---|---|---|
| winlog.message | Event messsage
 | keyword |
| winlog.channel | The name of the channel from which this record was read.
 | keyword |
| winlog.process.pid | Process id that generated the log
 | long |
| winlog.process.thread.id | Thread id that generated the log
 | long |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0.
 | keyword |
| winlog.original_event_data | This is a non-exhaustive list of parameters that are used in Windows events.
 | object |
| winlog.level | Log level, one of AUDIT, INFORMATIONAL, CRITICAL, ERROR, VERBOSE
 | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/windows-json/0 | Partial parent decoder for Windows events |
| decoder/windows-event-decoder/0 | Parent decoder for Windows events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Windows | [#15469](#) |
