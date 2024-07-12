# Windows Security Integration


|   |   |
|---|---|
| event.module | windows |
| event.dataset | EventChannel |

This integration processes events from Windows Security channel, Powershell, Powershell/Operational and Sysmon

## Compatibility

All Windows versions

## Configuration

To capture Powershell and Sysmon events, modify the `ossec.conf` file in a monitored agent as in the following block:
  ```xml
<ossec_config>
    <localfile>
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
        <location>Microsoft-Windows-Powershell/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
        <location>Microsoft-Windows-Powershell</location>
        <log_format>eventchannel</log_format>
    </localfile>
</ossec_config>
```

## Schema

## Decoders

| Name | Description |
|---|---|
| decoder/windows-sysmon/0 | Decoder for Windows Sysmon events |
| decoder/windows-powershell/0 | Decoder for Windows Powershell events |
| decoder/windows-powershell-operational/0 | Decoder for Windows Powershell Operational events |
| decoder/windows-json/0 | Partial parent decoder for Windows events |
| decoder/windows-event/0 | Parent decoder for Windows events |
| decoder/windows-security/0 | Decoder for Windows Security events |

## Rules

| Name | Description |
|---|---|

## Outputs

| Name | Description |
|---|---|

## Filters

| Name | Description |
|---|---|

## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Windows | [#17158](#) |
