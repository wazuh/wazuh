# Socket Configuration

The `<socket>` section defines named output sockets that the Log Collector can forward events to. Multiple `<socket>` blocks are allowed, one per socket.

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parser: `src/config/src/socket-config.c`

## Configuration Options

### name

Identifier for this socket. Used by Logcollector `<socket_output>` references. The name `agent` is reserved and cannot be used.

- **Required**: yes
- **Allowed values**: Any string except `agent`

### location

Filesystem path or `host:port` address of the target socket.

- **Required**: yes
- **Allowed values**: A Unix socket path or a `host:port` string

### mode

Transport protocol used to send events.

- **Default value**: `udp`
- **Allowed values**: `tcp`, `udp`

### prefix

String prepended to every message before it is sent to this socket.

- **Default value**: none
- **Allowed values**: Any string

## Configuration Example

```xml
<socket>
  <name>custom_siem</name>
  <location>/var/run/custom-siem.sock</location>
  <mode>tcp</mode>
  <prefix>wazuh: </prefix>
</socket>
```

### UDP to a remote syslog server

```xml
<socket>
  <name>syslog_out</name>
  <location>192.168.1.10:514</location>
  <mode>udp</mode>
</socket>
```

## Usage with Logcollector

Once a socket is defined here, reference it from a Logcollector `<localfile>` block using `<socket_output>`:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/app.log</location>
  <socket_output>
    <name>custom_siem</name>
  </socket_output>
</localfile>
```
