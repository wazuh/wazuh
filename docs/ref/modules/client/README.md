# Client Module (agentd)

The client module (`agentd`) manages the communication between Wazuh agents and the manager.

**Daemon:** `wazuh-agentd`

**Platform:** Linux, Windows, macOS, Unix

**Type:** Agent-only

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<agent>`, `<anti_tampering>`

---

## Overview

The client module is responsible for:
- Establishing and maintaining secure connections with the Wazuh manager
- Sending collected data (events, inventory, security assessments) to the manager
- Receiving and processing centralized configuration updates
- Managing local message buffering when the manager is unreachable
- Protecting agent integrity with anti-tampering features
- Auto-enrollment and key management

---

## Key Features

### Connection Management
- **Auto-connection:** Automatically connects to configured manager
- **Keep-alive:** Maintains persistent connection with heartbeat
- **Auto-reconnection:** Automatically reconnects after network issues
- **Multiple managers:** Failover support for high availability

### Data Transmission
- **Event forwarding:** Sends alerts, logs, and events to manager
- **Compression:** Optional compression for bandwidth optimization
- **Encryption:** AES encryption for secure communication

### Buffering
- **Local queue:** Buffers events when manager is unreachable
- **Queue limits:** Configurable queue size and overflow behavior
- **Queue persistence:** Events survive agent restarts

### Security
- **Anti-tampering:** Monitors agent files for unauthorized modifications
- **Key-based auth:** Pre-shared key authentication with manager
- **Auto-enrollment:** Optional automatic agent registration

---

## Configuration

For complete configuration options, see:
- [Client Configuration Reference](configuration.md)

Quick configuration example:

```xml
<agent>
  <server>
    <address>manager.example.com</address>
    <port>1517</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>web-servers</config-profile>
  <auto_restart>yes</auto_restart>
</agent>

<anti_tampering>
  <disabled>no</disabled>
</anti_tampering>
```

---

## Architecture

### Process Flow

1. **Startup:** Agent reads configuration and establishes connection
2. **Authentication:** Validates pre-shared key with manager
3. **Data collection:** Other modules collect events and send to agentd
4. **Transmission:** agentd compresses, encrypts, and forwards events
5. **Buffering:** If manager unreachable, events queued locally
6. **Configuration sync:** Receives and applies centralized config updates

### Component Interaction

```
┌─────────────────────┐
│   Data Collection   │
│  (syscheck, sca,    │
│   syscollector...)  │
└──────────┬──────────┘
           │ Events
           ▼
┌─────────────────────┐
│   agentd (client)   │
│  - Compression      │
│  - Encryption       │
│  - Buffering        │
└──────────┬──────────┘
           │ Encrypted
           ▼
┌─────────────────────┐
│   Wazuh Manager     │
│   (remoted)         │
└─────────────────────┘
```

---

## Management

### Start/Stop Service

Linux:
```bash
systemctl start wazuh-agent
systemctl stop wazuh-agent
systemctl status wazuh-agent
```

Windows:
```powershell
NET START WazuhSvc
NET STOP WazuhSvc
```

### Check Connection Status

```bash
/var/ossec/bin/wazuh-control status
```

Look for `wazuh-agentd is running...`

### View Agent Information

```bash
/var/ossec/bin/wazuh-control info
```

Shows:
- Agent ID
- Manager address
- Connection status
- Configuration version

---

## Troubleshooting

### Agent Not Connecting

Check configuration:
```bash
/var/ossec/bin/wazuh-logtest-config
```

Check logs:
```bash
tail -f /var/ossec/logs/ossec.log
```

Common issues:
- Incorrect manager address or port
- Firewall blocking port 1517
- Agent key not registered on manager
- Manager not accepting connections (`remoted` not running)

### Buffer Overflow

If events are being dropped due to buffer overflow:

1. Check the accumulator limits in `<client><batch>` (`size`, `interval`)
2. Verify network connectivity is stable

### Anti-Tampering Alerts

If anti-tampering is triggering false positives:

1. Review recent legitimate changes to agent files
2. Verify file permissions are correct
3. Check if system updates modified agent files
4. Temporarily disable to test: `<disabled>yes</disabled>` in `<anti_tampering>`

---

## See Also

- [Client Configuration Reference](configuration.md) - Complete configuration options
- [Remote Configuration](../../configuration/manager/remote.md) - Manager-side connection settings
- [Centralized Configuration](../../configuration/centralized/index.html) - Remote agent configuration
- [Agent Enrollment](../agent-management/enrollment.md) - Agent registration process
