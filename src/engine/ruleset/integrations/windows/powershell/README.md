# Windows Powershell Integration


|   |   |
|---|---|
| event.module | windows-powershell |

This integration processes Powershell events

## Compatibility

All Powershell versions

## Configuration

Add the following stub to the agent configuration file
```html
<localfile>
  <location>Microsoft-Windows-Powershell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-Powershell</location>
  <log_format>eventchannel</log_format>
</localfile>
```


## Schema

| Field | Description | Type |
|---|---|---|
| powershell.sequence | Sequence number of the powershell execution.
 | long |
| powershell.total | Total number of messages in the sequence.
 | long |
| powershell.id | Shell Id.
 | keyword |
| powershell.engine.version | Version of the PowerShell engine version used to execute the command.
 | keyword |
| powershell.engine.new_state | New state of the PowerShell engine.
 | keyword |
| powershell.provider.new_state | New state of the PowerShell provider.
 | keyword |
| powershell.provider.name | Provider name.
 | keyword |
| powershell.engine.previous_state | Previous state of the PowerShell engine.
 | keyword |
| powershell.pipeline_id | Pipeline id.
 | keyword |
| powershell.runspace_id | Runspace id.
 | keyword |
| powershell.process.executable_version | Version of the engine hosting process executable.
 | keyword |
| powershell.command.value | The invoked command.
 | keyword |
| powershell.command.path | Path of the executed command.
 | keyword |
| powershell.command.name | Name of the executed command.
 | keyword |
| powershell.command.type | Type of the executed command. | keyword |
| powershell.file.script_block_id | Id of the executed script block. | keyword |
| powershell.file.script_block_text | Text of the executed script block. | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/windows-powershell-operational/0 | Decoder for Windows Powershell Operational events |
| decoder/windows-powershell/0 | Decoder for Windows Powershell events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Windows Powershell | [#15469](#) |
