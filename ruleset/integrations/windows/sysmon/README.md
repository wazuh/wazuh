# Windows Sysmon Integration


|   |   |
|---|---|
| event.module | windows-sysmon |

This integration processes events from Windows Sysmon

## Compatibility

All Sysmon versions

## Configuration

Add the following stub in the agent configuration file  ''' <localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile> '''


## Schema

| Field | Description | Type |
|---|---|---|
| sysmon.dns.status | Windows status code returned for the DNS query. | keyword |
| sysmon.file.archived | Indicates if the deleted file was archived. | keyword |
| sysmon.file.is_executable | Indicates if the deleted file was an executable. | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/windows-sysmon/0 | Decoder for Windows Sysmon events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Windows Sysmon | [#15469](#) |
