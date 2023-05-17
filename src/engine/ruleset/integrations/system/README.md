# System syslog and auth events


|   |   |
|---|---|
| event.module | system |


The system module collects and parses logs created by the system logging service of common Unix/Linux based distributions.

System-syslog logs include standar services syslog logging logs
System-auth logs include auth logs like sudo, ssh, and cron logs


## Compatibility

This integration was tested with logs from OSes like Ubuntu 12.04, Centos 7, and macOS Sierra.

## Configuration

This integration ingests logs from /var/log/syslog and /var/log/auth.log (the location of the files
can be configured in the localfile configuration).

As mentioned above, we use the logcollector source localfile to ingest the logs from both files.

Adding to the ossec.conf file in the monitored agent the following blocks:
```xml
<localfile>
  <location>/var/log/syslog</location>
  <log_format>syslog</log_format>
</localfile>
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>

```


## Schema

## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for system auth and syslog events | [#16910](https://github.com/wazuh/wazuh/pull/16910) |
