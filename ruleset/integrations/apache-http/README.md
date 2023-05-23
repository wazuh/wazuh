# Apache http server


|   |   |
|---|---|
| event.module | apache-http |

This integration supports [Apache](https://httpd.apache.org/) http server on linux (configuration details for
different operating systems can be changed, more information in the configuration section).

Specifically it adds the ability to ingest logs from the [apache-access](https://httpd.apache.org/docs/2.4/logs.html#accesslog)
and [apache-error](https://httpd.apache.org/docs/2.4/logs.html#errorlog) modules, that will be
normalized according to the schema (check the schema fields section for a list of fields used), and enriched with IoCs specific to the Apache http server (see rule section for a list of all rules used).


## Compatibility

The integration was tested with logs from version 2.4.41.

## Configuration

This integration ingests logs from /var/log/apache2/access.log and /var/log/apache2/error.log (the location of the files
can be configured in the localfile configuration).

For both files the default format is supported.
  - [apache-error default format](https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat):
    ```
    "[%{u}t] [%-m:%l] [pid %P:tid %T] %7F: %E: [client\ %a] %M% ,{referer}i"
    ```
  - apache-access default format ([CLF](https://httpd.apache.org/docs/2.4/mod/mod_log_config.html)):
    ```
    "%h %l %u %t \"%r\" %>s %b"
    ```

As mentioned above, we use the logcollector source localfile to ingest the logs from both files.

Adding to the ossec.conf file in the monitored agent the following blocks:
```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/apache2/error.log</location>
  <log_format>json</log_format>
  <label key="event.module">apache</label>
  <label key="event.dataset">apache-error</label>
</localfile>
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>/var/log/apache2/access.log</location>
  <log_format>json</log_format>
  <label key="event.module">apache</label>
  <label key="event.dataset">apache-access</label>
</localfile>
```


## Schema

| Field | Description | Type |
|---|---|---|

## Decoders

| Name | Description |
|---|---|
| decoder/apache-access/0 | Decoder for Apache HTTP Server access logs. |
| decoder/apache-error/0 | Decoder for Apache HTTP Server error logs. |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for apache http server | [#16910](https://github.com/wazuh/wazuh/pull/16910) |
