#ifndef __CATALOG_JSON_ASSETS_H__
#define __CATALOG_JSON_ASSETS_H__


/** @brief Valid decoder json  to test*/
constexpr auto json_decoder_valid = R"(
---
name: syslog2
draft: true

metadata:
  description: Syslog header
  references: [ https://datatracker.ietf.org/doc/html/rfc3164, https://datatracker.ietf.org/doc/html/rfc5424 ]
  product.name: Syslog
  formats: [ rfc3164, rfc5424 ]
  json_event_name: syslog

define:
  header: <timestamp/SYSLOG> <host.hostname>

check:
  - wazuh.event.format: text

parse:
  logql:
    # BSD Syslog RFC 3164
    - event.original: "<$header> <process.name>[<process.pid>]: <message>"

    # IETF Syslog RFC 5424
    - event.original: <timestamp/ISO8601> <host.hostname> <process.name> <process.pid> <_> <_/quoted/[/]> <message>

)";

#endif // __CATALOG_JSON_ASSETS_H__
