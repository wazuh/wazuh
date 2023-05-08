# Sophos Integration


|   |   |
|---|---|
| event.module | sophos |

This integration processes logs from Sophos:
  - UTM dataset: supports Unified Threat Management (formerly known as Astaro Security Gateway) logs.
  - XG dataset: supports Sophos XG SFOS logs.


## Compatibility

This module has been tested against SFOS version 17.5.x and 18.0.x.


## Configuration

Events may be collected in two ways:
1. Logcollector Using the logcollector source localfile to ingest the logs from the agent. Add to the ossec.conf file in the monitored agent the following blocks:
```xml
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[Sophos UTM log path]</location>
  <log_format>json</log_format>
  <label key="event.module">sophos</label>
  <label key="event.dataset">sophos.utm</label>
</localfile>
<localfile>
  <!-- Edit location to appropriate path if needed -->
  <location>[Sophos XG log path]</location>
  <log_format>json</log_format>
  <label key="event.module">sophos</label>
  <label key="event.dataset">sophos.xg</label>
</localfile>
```

2. Remote Syslog

#TODO: Add remote syslog configuration


## Schema

| Field | Description | Type |
|---|---|---|
| filename | Name of the file being analyzed. | keyword |
| fileset.name | Name of the fileset this data belongs to. | keyword |
| fullreqtime | Date and time of the request in ISO8601 format. | keyword |
| input.type | The type of input from which this data was obtained. | keyword |
| reputation | A value indicating the reputation of an object or entity, such as an IP address or domain. | keyword |
| sophos.xg.ap | The access point name associated with the event. | keyword |
| sophos.xg.app_is_cloud | A value indicating whether the application is cloud-based. | boolean |
| sophos.xg.appfilter_policy_id | The identifier of the application filtering policy associated with the event. | keyword |
| sophos.xg.application_risk | The risk score associated with the application. | keyword |
| sophos.xg.appresolvedby | The method by which the application was resolved, such as "lookup" or "cache". | keyword |
| sophos.xg.auth_client | The name of the authentication client associated with the event. | keyword |
| sophos.xg.auth_mechanism | The authentication mechanism used in Sophos XG Firewall, such as "LDAP", "RADIUS", "AD", etc. | keyword |
| sophos.xg.av_policy_name | The name of the antivirus policy associated with an event. | keyword |
| sophos.xg.backup_mode | The backup mode of the device. | keyword |
| sophos.xg.category | The category of the event. | keyword |
| sophos.xg.category_type | The type of category of the event. | keyword |
| sophos.xg.collisions | The number of collisions that occurred. | float |
| sophos.xg.configuration | The configuration of the device. | keyword |
| sophos.xg.con_id | The ID of the connection. | keyword |
| sophos.xg.connectionname | The name of the connection. | keyword |
| sophos.xg.connectiontype | The type of connection. | keyword |
| sophos.xg.connevent | The connection event. | keyword |
| sophos.xg.connid | The ID of the connection. | keyword |
| sophos.xg.cookie | The cookie value. | keyword |
| sophos.xg.device | The device type. | keyword |
| sophos.xg.device_name | The name of the device. | keyword |
| sophos.xg.dst_country_code | The country code of the destination. | keyword |
| sophos.xg.dst_zone_type | The destination zone type. | keyword |
| sophos.xg.email_subject | The subject of the email. | keyword |
| sophos.xg.eventtype | The type of event. | keyword |
| sophos.xg.ether_type | The Ethernet type. | keyword |
| sophos.xg.exceptions | The exceptions that occurred. | keyword |
| sophos.xg.extra | Additional information about the event, if available. | keyword |
| sophos.xg.free | The amount of free space. | long |
| sophos.xg.fw_rule_id | The ID of the firewall rule. | keyword |
| sophos.xg.hb_health | The health of the heartbeat. | keyword |
| sophos.xg.host | The hostname. | keyword |
| sophos.xg.iap | The IAP ID. | keyword |
| sophos.xg.ips_policy_id | The ID of the IPS policy associated with an event in Sophos XG Firewall. | keyword |
| sophos.xg.log_component | Registry component. | keyword |
| sophos.xg.log_id | Record ID. | keyword |
| sophos.xg.log_subtype | Record subtype. | keyword |
| sophos.xg.log_type | Record type. | keyword |
| sophos.xg.mailid | Email ID. | keyword |
| sophos.xg.mailsize | Email size. | long |
| sophos.xg.platform | operating system platform. | keyword |
| sophos.xg.priority | Alert priority. | keyword |
| sophos.xg.quarantine_reason | Quarantine reason. | keyword |
| sophos.xg.querystring | HTTP query string. | keyword |
| sophos.xg.receiveddrops | Number of received packets that were dropped because the queue was full. | long |
| sophos.xg.receivederrors | Number of packets received that had errors and were dropped. | long |
| sophos.xg.receivedkbits | Total number of kilobits received. | long |
| sophos.xg.remotenetwork | Remote network. | keyword |
| sophos.xg.reports | Report ID. | keyword |
| sophos.xg.rule_priority | Firewall rule priority. | keyword |
| sophos.xg.server | Server. | keyword |
| sophos.xg.signature | Signature of the threat. | keyword |
| sophos.xg.source | Source IP address. | ip |
| sophos.xg.spamaction | Action taken in relation to spam. | keyword |
| sophos.xg.ssid | Wireless access point ID. | keyword |
| sophos.xg.system_cpu | System CPU usage percentage. | float |
| sophos.xg.src_country_code | Country of origin code. | keyword |
| sophos.xg.src_zone_type | Source zone type. | keyword |
| sophos.xg.subject | Email subject. | keyword |
| sophos.xg.status | Alert status. | keyword |
| sophos.xg.status_code | Alert status code. | keyword |
| sophos.xg.target | Destination IP address. | ip |
| sophos.xg.temp | The value of this field varies based on the event. Please refer to the documentation for more information. | keyword |
| sophos.xg.threatname | The name of the threat that was detected. | keyword |
| sophos.xg.total_memory | The total memory used by the device. | long |
| sophos.xg.transmitteddrop | The number of packets that were dropped during transmission. | long |
| sophos.xg.transmittederrors | The number of errors that occurred during transmission. | long |
| sophos.xg.transmittedkbits | The number of kilobits that were transmitted. | long |
| sophos.xg.unit | The unit of measurement for some metrics, such as the number of packets. | keyword |
| sophos.xg.used | The amount of memory currently in use by the device. | long |
| sophos.xg.user_name | The name of the user associated with the event. | keyword |
| sophos.xg.user_cpu | The percentage of CPU usage by the user. | float |
| sophos.xg.virus | The name of the virus that was detected. | keyword |
| sophos.xg.xss | The type of cross-site scripting (XSS) attack that was detected. | keyword |
## Decoders

| Name | Description |
|---|---|
| decoder/sophos-sandstorn/0 | Decoder for Sophos Sandstorn |
| decoder/sophos-wifi/0 | Decoder for Sophos Wifi |
| decoder/sophos-waf/0 | Decoder for Sophos Waf |
| decoder/sophos-atp/0 | Decoder for Sophos Atp |
| decoder/sophos-utm/0 | Decoder for Sophos Utm |
| decoder/sophos-antispam/0 | Decoder for Sophos Antispam |
| decoder/sophos-idp/0 | Decoder for Sophos Idp |
| decoder/sophos-antivirus/0 | Decoder for Sophos Antivirus |
| decoder/sophos-cfilter/0 | Decoder for Sophos Cfilter |
| decoder/sophos-systemhealth/0 | Decoder for Sophos Systemhealth |
| decoder/sophos-event/0 | Decoder for Sophos-Event |
| decoder/sophos-firewall/0 | Decoder for Sophos Firewall |
## Changelog

| Version | Description | Details |
|---|---|---|
| 1.0.0-dev | Created integration for Sophos | [#16766](#) |
