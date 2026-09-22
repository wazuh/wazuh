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
- **Single manager:** Only one `<manager>` block is honored; a second one replaces the first instead of adding failover

### Data Transmission
- **Event forwarding:** Sends alerts, logs, and events to manager
- **Compression:** Optional compression for bandwidth optimization
- **Encryption:** AES encryption for secure communication

### Buffering
- **Local queue:** Buffers events when manager is unreachable
- **Queue limits:** Configurable queue size and overflow behavior
- **Queue persistence:** Events survive agent restarts

### Security

- **Manager identity:** every connection to the manager is HTTPS, and the agent verifies who answers against a trust anchor it holds on disk. The mode is resolved from `<agent><ssl>` and that anchor -- see [`verification_mode`](configuration.md#verification_mode).
- **Enrollment token:** registration uses a token minted on the manager, which names the manager, pins its certificate authority and carries a scoped, revocable credential.
- **Trust anchor:** `etc/certs/root-ca.pem`, owned by the `wazuh` user (`0640`) inside `etc/certs`, which is root-owned, group-writable and sticky (`01770 root:wazuh`). The agent replaces the anchor itself when the manager publishes a new CA bundle, so the directory has to admit that write; it is made by renaming a staging file over the anchor, never by writing through it. What bounds that: the sticky bit limits the agent to entries it owns, and the directory staying root-owned keeps the agent from loosening its own mode. The `.anchor-committed` marker beside it is root-owned, so an agent that has held an anchor cannot erase the record of it -- an anchor that later goes missing is refused at startup (`4125`) instead of silently resolving to no verification, unless `<verification_mode>` says explicitly what was intended. It lives outside `ossec.conf` so a configuration-management converge cannot remove it, and the manager cannot push one through centralized configuration.
- **Per-agent key:** every request after enrollment is authenticated with the agent's own key from `client.keys`, which is never transmitted.
- **Re-enrollment secret:** a per-agent credential that recovers a lost key without an operator visit and without a shared secret.
- **Anti-tampering:** monitors agent files for unauthorized modifications.

---

## Configuration

For complete configuration options, see:
- [Client Configuration Reference](configuration.md)

Quick configuration example:

```xml
<agent>
  <manager>
    <endpoint>manager.example.com:1517</endpoint>
  </manager>
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

### Enrolling or re-pointing an agent

`wazuh-agent-auth` registers an installed agent, registers it again, or points it at a manager whose certificate authority or address has changed. It ships on Linux, macOS and Windows, and is the path for every install that did not carry a token.

It is installed in the agent's `bin/` directory, which is not on `PATH` (`/Library/Ossec/bin/` on macOS), and runs as root:

```bash
sudo /var/ossec/bin/wazuh-agent-auth --token-file /root/token                  # enroll
sudo /var/ossec/bin/wazuh-agent-auth --token-file /root/token --force-enroll   # re-register, new id
sudo /var/ossec/bin/wazuh-agent-auth --token-file /root/token --certs-only     # refresh CA + address
sudo /var/ossec/bin/wazuh-agent-auth --show-token --token-file /root/token     # decode a token
```

The token is read from `--token-file` or standard input, never from the command line. The file it is read from is never modified or deleted.

**Actions**

| Action | Effect |
|---|---|
| *(none)* | Establishes the manager's certificate authority, enrolls, and writes the address the token names into `<manager><endpoint>`. Refused if the agent already has a key |
| `--certs-only` | Installs the trust anchor and, when the token names a different address, writes that too. The registration is left alone, so the agent keeps its id. Refused on an agent that was never enrolled |
| `--show-token` | Prints what a token carries, without its credential. Contacts nothing and writes nothing |
| `-h`, `--help` | Usage |

**Options**

| Option | Effect |
|---|---|
| `--token-file <path>` | Read the token from `<path>`, or from standard input with `-` |
| `-n`, `--dry-run` | Report what would change. Contacts nothing, writes nothing |
| `-d` | Debug output, repeatable |
| `--force-enroll` | Required when the agent already has a key. It is registered again and receives a **new** id. The previous id is named; what becomes of it is the manager's replacement policy |

The agent name, groups and address come from `<enrollment>` in `ossec.conf`, so the command takes none of them and a later re-enrollment by the agent itself registers the same way.

It refuses to run while `wazuh-agentd` is running, with no override. A restart is needed either way, since the agent loads its identity once at startup.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Done |
| `1` | Could not run |
| `2` | Token rejected |
| `3` | CA not established |
| `4` | Enrollment refused by the manager |
| `5` | Not committed |
| `6` | Configuration not updated |

**Moving an agent to another manager.** Which action applies depends on whether the new manager already knows this agent:

- **The same deployment, after the manager rotated its certificate authority or changed its address** — `--certs-only`. The agent keeps its id and its history.
- **A different deployment, which has never seen this agent** — `--force-enroll`. The agent registers from scratch and receives a new id.

Behind a load balancer there is nothing to re-point between nodes: the agent addresses the balancer, and which node answers a given request is not something it tracks.

---

## Troubleshooting

### Agent Not Connecting

Start with the agent's own log:

```bash
sudo grep -E "cacerts|pin_mismatch|TLS verification|\(41[0-9]{2}\)" /var/ossec/logs/ossec.log | tail -20
```

| What the agent says | What it means | What to do |
|---|---|---|
| `/cacerts adr_unreachable` | The address in the token answers nothing | Check routing, and that the manager is listening on 1517 |
| `/cacerts not_found` | The manager answered, but has no CA to hand out | Nothing on the endpoint changes this. The manager has to be given its CA before any agent can bootstrap against it |
| `/cacerts ca_mismatch` | The CA the manager hands out does not sign the certificate it serves | Nothing on the endpoint changes this. Retrying will keep failing until the manager's certificate and CA match |
| `pin_mismatch` | The CA the manager served is not the one the token pins | Wrong token, wrong manager, or the CA was rotated. Use a fresh token |
| `(4118)` | The mode needs a CA, and neither `<certificate_authorities>` nor the trust anchor is present | Enroll with a token, or name a CA |
| `(4120)` | `system` together with an explicit `<certificate_authorities>` | Drop one of the two: remove the CA to use the OS trust store, or keep it and set the mode to `full` |
| `(4121)` | `system` on a host with no OS CA bundle | Use `full` against the trust anchor instead |
| `(4123)` | The CA file is readable but holds no certificate the agent can parse | Replace the file; truncated copies are the usual cause |
| `(4124)` | `system`, and the trust anchor is readable but holds no certificate the agent can parse | Replace the anchor, or enroll with a token to reinstall it; truncated copies are the usual cause |
| `(4125)` | The trust anchor is gone, but this install has held one (`.anchor-committed` is still beside it) | Restore the anchor, or set `<verification_mode>` explicitly to say what was intended. Starting unverified is refused rather than done silently |
| `(4122)` | An explicit `none` on a host that holds a usable anchor | Remove `<verification_mode>none</verification_mode>` to verify against it |
| `TLS verification failed connecting to …: the certificate does not include that name` | The address the agent dials is not in the certificate | The line lists the names the certificate does carry |
| `TLS verification failed connecting to …: the certificate has expired` / `is not valid yet` | The manager's certificate is outside its validity window, or the clock is wrong | The line gives the date it checked against |
| `TLS verification is DISABLED (verification_mode=none)` | The resolved mode is `none` | See the resolution table under [`verification_mode`](configuration.md#verification_mode) |
| `verification_mode=system: … falling back to the local trust anchor ('…')` | The OS trust store did not vouch for the manager, so the agent verified against its own anchor instead | Nothing, if the agent connects after it. Add the manager's CA to the OS trust store to verify there instead |
| `verification_mode=system: … no local trust anchor is configured to fall back to` | The OS trust store does not vouch for this manager, and there is no anchor to fall back to | Add the manager's CA to the OS trust store, or enroll with a token so the agent holds an anchor. Logged once per run; the agent keeps retrying and recovers once the store carries the CA |
| `verification_mode=system: … no time remains in this attempt's budget to try the local fallback anchor ('…')` | The attempt against the OS trust store used the whole request timeout, so the anchor was never tried | Usually a slow or overloaded manager. Logged once per run, then at debug level |
| `local fallback anchor ('…') could not be loaded (missing, unreadable, or not a certificate this agent can parse)` | The anchor was present when the agent started and is not usable now | The agent stops. Restore the anchor file, or enroll with a token to reinstall it, then start the agent |
| `local fallback anchor ('…') does not verify the manager's certificate either` | Neither the OS trust store nor the anchor vouches for this manager | The agent stops. Usually the manager's CA was rotated: enroll with a fresh token |
| `verification_mode=system found no OS trust store on this system … and the local fallback anchor ('…') does not verify it either` | There is no OS trust store to consult, and the anchor does not match this manager | The agent stops. Enroll with a fresh token, or use `full` against a correct anchor |

> [!NOTE]
> If nothing above matches, raise the agent's log level with `agent.debug=1` in `local_internal_options.conf` and restart it. Not every TLS failure is reported at normal level so a connection problem with nothing in the log is a reason to turn debug on rather than to rule TLS out.

Confirm what the agent holds:

```bash
sudo ls -l /var/ossec/etc/certs/root-ca.pem /var/ossec/etc/client.keys
sudo grep -A4 "<ssl>" /var/ossec/etc/ossec.conf
```

The trust anchor should be `0640 root:wazuh`. A root-owned file the `wazuh` user cannot read fails closed just as a missing one does, and a directory listing looks right until the group is checked.

If the agent has no anchor, or the manager's has changed, refresh it with [`wazuh-agent-auth --certs-only`](#enrolling-or-re-pointing-an-agent) rather than copying the file by hand.

#### Auditing a fleet

An in-place upgrade from 4.x whose CA delivery did not run leaves an agent that upgrades, connects and works while verifying nothing, so those have to be looked for rather than waited for.

The trust anchor is the signal. An agent that has one verifies, unless `ossec.conf` names a mode explicitly:

```bash
sudo test -s /var/ossec/etc/certs/root-ca.pem && echo "anchor present" || echo "NO ANCHOR"
sudo grep -c "<verification_mode>" /var/ossec/etc/ossec.conf
```

An anchor and no explicit mode is a verifying agent. No anchor is one that is not, and an explicit mode is one to read before deciding.

The log corroborates it, with the caveat that `ossec.log` spans earlier boots until it rotates, so read the timestamp rather than the presence of a match:

```bash
sudo grep "TLS verification is DISABLED" /var/ossec/logs/ossec.log | tail -1
```

See [Trust anchor delivery to legacy agents](../../../guide/migration/remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents) for the delivery and for confirming it ran.

### Buffer Overflow

If events are being dropped due to buffer overflow:

1. Check the accumulator limits in `<agent><batch>` (`size`, `interval`)
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
- [Manager Configuration Reference](../../configuration/manager/reference.md) - Manager-side `<remote>` settings
- [Centralized Configuration](../../configuration/centralized/index.html) - Remote agent configuration
- [Enrollment lifecycle](../authd/enrollment-lifecycle.md) - Agent registration, end to end
- [Trust anchor delivery to legacy agents](../../../guide/migration/remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents) - How an agent upgraded from 4.x receives its CA
