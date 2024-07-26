# Auditd Integration


|   |   |
|---|---|
| event.module | auditd |

This integration processes logs from Linux audit daemon (auditd).

## Compatibility

None

## Configuration

This integration uses the logcollector source localfile to ingest the logs from /var/log/audit/audit.log. Add to the ossec.conf file in the monitored agent the following block:
```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/audit/audit.log</location>
  <log_format>json</log_format>
  <label key="event.module">auditd</label>
  <label key="event.dataset">auditd.log</label>
</localfile>
```

## Schema

| Field | Description | Type |
|---|---|---|
| auditd.log.new_auid | For login events this is the new audit ID. The audit ID can be used to trace future events to the user even if their identity changes (like becoming root). | keyword |
| auditd.log.old_auid | For login events this is the old audit ID used for the user prior to this login. | keyword |
| auditd.log.new_ses | For login events this is the new session ID. It can be used to tie a user to future events by session ID. | keyword |
| auditd.log.old_ses | For login events this is the old session ID usedfor the user prior to this login. | keyword |
| auditd.log.record_type | Alias of event.action. This describes the information in the event. It is more specific than event.category. Examples are group-add, process-started, file-created. The value is normally defined by the implementer. | keyword |
| auditd.log.sequence | The audit event sequence number. | long |
| auditd.data.apparmor | apparmor event information | keyword |
| auditd.data.cgroup | path to cgroup in sysfs | keyword |
| auditd.data.file | file name | keyword |
| auditd.data.device | device name | keyword |
| auditd.data.dir | directory name | keyword |
| auditd.data.grp | group name | keyword |
| auditd.data.invalid_context | SELinux context | keyword |
| auditd.data.new-chardev | new character device being assigned to vm | keyword |
| auditd.data.new-disk | disk being added to vm | keyword |
| auditd.data.new-fs | file system being added to vm | keyword |
| auditd.data.new-net | MAC address being assigned to vm | keyword |
| auditd.data.new-rng | device name of rng being added from a vm | keyword |
| auditd.data.ocomm | objects command line name | keyword |
| auditd.data.old-chardev | present character device assigned to vm | keyword |
| auditd.data.old-disk | disk being removed from vm | keyword |
| auditd.data.old-fs | file system being removed from vm | keyword |
| auditd.data.old-net | present MAC address assigned to vm | keyword |
| auditd.data.old-rng | device name of rng being removed from a vm | keyword |
| auditd.data.success | whether the syscall was successful or not | keyword |
| auditd.data.vm | virtual machine name | keyword |
| auditd.data.watch | file name in a watch record | keyword |
| auditd.log.denied_mask | possible hex key | keyword |
| auditd.log.new_group | possible hex key | keyword |
| auditd.log.info | possible hex key | keyword |
| auditd.log.operation | possible hex key | keyword |
| auditd.log.proctitle | possible hex key | keyword |
| auditd.log.profile | possible hex key | keyword |
| auditd.log.requested_mask | possible hex key | keyword |
| auditd.log.root_dir | possible hex key | keyword |
| auditd.log.sw | possible hex key | keyword |
| auditd.log.data | possible hex key | keyword |
| auditd.log.path | possible hex key | keyword |
| auditd.log.node | node name | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/auditd-kv/0 | Decoder for parsing the msg field of Linux auditd logs |
| decoder/auditd/0 | Decoder for Linux auditd logs |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Auditd | [#16766](#) |
