# Remote Configuration

The `<remote>` section configures the manager listener that receives events from agents. Each `<remote>` block defines one listener; multiple blocks are allowed.

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parser: `src/config/src/remote-config.c`

For the full remoted module reference (architecture, event protocol, stateless metadata) see [Remoted](../modules/remoted/README.md).

## Configuration Options

### port

Port on which the manager listens for incoming agent connections.

- **Default value**: `1514`
- **Allowed values**: Integer from `1` to `65535`

### protocol

Network protocol used for agent communication. Accepts a comma-separated list to enable both simultaneously.

- **Default value**: `tcp`
- **Allowed values**: `tcp`, `udp`, `tcp,udp` (or `udp,tcp` — order does not matter)

### ipv6

Enable IPv6 support for this listener.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### local_ip

Bind this listener to a specific local IP address. Useful on hosts with multiple network interfaces.

- **Default value**: none (binds to all interfaces)
- **Allowed values**: Any valid IPv4 or IPv6 address present on the host. IPv6 addresses are expanded to their full form.

### queue_size

Internal message queue capacity. Events are held in this queue while being processed by worker threads.

- **Default value**: `131072`
- **Allowed values**: Positive integer (minimum: `1`). Values above `262144` produce a startup warning about potential memory usage.

### rids_closing_time

Time after which idle agent RIDS (registration identifier) file handles are closed to free file descriptors.

- **Default value**: `300` (5 minutes)
- **Allowed values**: Positive time value with optional suffix — `s`, `m`, `h`, `d`. The value `300` without a suffix is treated as seconds.

### connection_overtake_time

Seconds the manager waits before allowing a new connection to take over an existing registered slot for the same agent. Set to `0` to disable overtake protection.

- **Default value**: `60`
- **Allowed values**: Integer from `0` to `3600`

### agents / allow_higher_versions

Controls whether agents running a newer Wazuh version than the manager are accepted.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

> **Note:** This option controls the **connection gate** (remoted, port 1514). There is an independent option with the same name under `<auth><agents>` that controls the **enrollment gate** (authd, port 1515). Both must be set to `yes` for a higher-version agent to both enroll and connect. Setting them differently — for example allowing connection but not enrollment — will result in agents that cannot obtain keys and therefore cannot communicate.

This option is nested under an `<agents>` sub-element:

```xml
<remote>
  <agents>
    <allow_higher_versions>no</allow_higher_versions>
  </agents>
</remote>
```

## Configuration Example

```xml
<remote>
  <port>1514</port>
  <protocol>tcp</protocol>
  <queue_size>131072</queue_size>
  <rids_closing_time>5m</rids_closing_time>
  <connection_overtake_time>60</connection_overtake_time>
  <agents>
    <allow_higher_versions>no</allow_higher_versions>
  </agents>
</remote>
```
