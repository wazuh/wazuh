# Windows Security Integration


|   |   |
|---|---|
| event.module | windows-security |

This integration processes events from Windows Security channel

## Compatibility

All Windows versions

## Configuration

This integration will work with Wazuh default configuration

## Schema

| Field | Description | Type |
|---|---|---|
| winlog.event_data.UserAccountControl | List of changes in userAccountControl attribute. You will see a line of text for each change.| keyword |
| winlog.event_data.StatusDescription | Kerberos Encryption Types| keyword |
| winlog.event_data.SubCategory | Audit subcategories| keyword |
| winlog.event_data.Category | Audit categories| keyword |
| winlog.event_data.PrivilegeList | List of privileges assigned on Logon| keyword |
| winlog.event_data.OldTargetUserName | User name to be updated| keyword |
| winlog.event_data.NewTargetUserName | New user name to be assigned| keyword |
| winlog.event_data.NewSd | New security descriptor| keyword |
| winlog.event_data.OldSd | Old security descriptor| keyword |
| winlog.event_data.ObjectType | Object type accessed during the operation| keyword |
| winlog.event_data.ObjectServer | Object server| keyword |
| winlog.event_data.ObjectName | Acces route or full name of the object accessed during operation| keyword |
| winlog.logon.failure.status | The reason the logon failed. This is textual description based on the value of the hexadecimal `Status` field.| keyword |
| winlog.logon.failure.sub_status | Additional information about the logon failure. This is a textual description based on the value of the hexidecimal `SubStatus` field.| keyword |
| winlog.logon.failure.reason | The reason the logon failed.| keyword |
| winlog.logon.id | Logon ID that can be used to associate this logon with other events related to the same logon session.| keyword |
| winlog.logon.type | Logon type name. This is the descriptive version of the `winlog.event_data.LogonType` ordinal. This is an enrichment added by the Security module.| keyword |
| winlog.trustAttribute | The decimal value of attributes for new trust created to a domain.| keyword |
| winlog.trustDirection | The direction of new trust created to a domain. Possible values are `TRUST_DIRECTION_DISABLED`, `TRUST_DIRECTION_INBOUND`, `TRUST_DIRECTION_OUTBOUND` and `TRUST_DIRECTION_BIDIRECTIONAL`| keyword |
| winlog.trustType | The account name that was added, modified or deleted in the event. Possible values are `TRUST_TYPE_DOWNLEVEL`, `TRUST_TYPE_UPLEVEL`, `TRUST_TYPE_MIT` and `TRUST_TYPE_DCE`| keyword |
| winlog.computerObject.domain | The domain of the account that was added, modified or deleted in the event. | keyword |
| winlog.computerObject.id | A globally unique identifier that identifies the target device.| keyword |
| winlog.computerObject.name | The account name that was added, modified or deleted in the event.| keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field.| keyword |
| winlog.user_data.BackupPath | Full path to the created log backup.| keyword |
| winlog.user_data.Channel | Windows event log channel that is being backed up.| keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/windows-security/0 | Decoder for Windows Security events |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Windows Security | [#15469](#) |
