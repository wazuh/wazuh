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
- **HTTPS only:** every exchange with the manager is a separate HTTPS request to `wazuh-manager-remoted` on port `1517`; there is no persistent connection
- **Keep-alive:** `POST /control` every [`<notify_time>`](configuration.md#notify_time) seconds (10 by default). Its answer carries the agent's groups, its configuration hash and any pending task
- **Retries:** a failed request is retried with a jittered backoff, within the per-stream budgets of the `agent.https_*` [internal options](configuration.md#https-connection-timing)
- **Single manager:** Only one `<manager>` block is honored; a second one replaces the first instead of adding failover. A legacy 4.x `<client>` block with several `<server>` blocks connects to one of them and logs a warning naming the others

### Data Transmission
- **Events:** batched and sent with `POST /stateless`; inventory synchronization (FIM, SCA, Syscollector) uses `POST /stateful`
- **Compression:** request bodies are zstd-compressed (`agent.https_compression_enabled`, on by default)
- **Transport security:** TLS on every request. Each request after enrollment is authenticated with a token signed with the agent's key; the key itself is never sent

### Buffering
- **In-memory accumulator:** events wait in memory and are sent every `<batch><interval>` or once `<batch><size>` bytes are queued
- **Limit:** the accumulator holds up to four times `<batch><size>`. When it is full, new events are dropped
- **Not persistent:** on a clean stop the agent sends what it can before it exits (best effort). Events still queued when the agent stops are lost

### Security

- **Manager identity:** every connection to the manager is HTTPS, and the agent verifies who answers against a trust anchor it holds on disk. The mode is resolved from `<agent><ssl>` and that anchor -- see [`verification_mode`](configuration.md#verification_mode).
- **Enrollment token:** registration uses a token minted on the manager, which names the manager, pins its certificate authority and carries a scoped, revocable credential.
- **Trust anchor:** `etc/certs/root-ca.pem`, owned by the `wazuh` user (`0640`) inside `etc/certs`, which is root-owned, group-writable and sticky (`01770 root:wazuh`). The agent replaces the anchor itself when the manager publishes a new CA bundle, so the directory has to admit that write; it is made by renaming a staging file over the anchor, never by writing through it. What bounds that: the sticky bit limits the agent to entries it owns, and the directory staying root-owned keeps the agent from loosening its own mode. The `.anchor-committed` marker beside it is root-owned, so an agent that has held an anchor cannot erase the record of it -- an anchor that later goes missing is refused at startup (`4125`) instead of silently resolving to no verification, unless `<verification_mode>` says explicitly what was intended. It lives outside `ossec.conf` so a configuration-management converge cannot remove it, and the manager cannot push one through centralized configuration.
- **Per-agent key:** every request after enrollment is authenticated with the agent's own key from `client.keys`, which is never transmitted.
- **Re-enrollment secret:** a per-agent credential that recovers a lost key without an operator visit and without a shared secret.
- **Anti-tampering:** refuses to remove the agent package unless the removal is validated against the Server API (Linux agents installed from a DEB or RPM package).

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
  <package_uninstallation>yes</package_uninstallation>
</anti_tampering>
```

---

## Architecture

### Process Flow

1. **Startup:** agentd reads its configuration, runs the enrollment-token bootstrap if a token is waiting, and enrolls if it has no key
2. **Authentication:** every request carries a token signed with the agent's key from `client.keys`
3. **Data collection:** the other daemons (`wazuh-syscheckd`, `wazuh-logcollector`, `wazuh-modulesd`, ...) send their events to agentd through the local queue
4. **Transmission:** agentd batches, compresses and sends them over HTTPS
5. **Buffering:** while the manager cannot be reached, events stay in the in-memory accumulator, up to its limit
6. **Configuration sync:** when the configuration hash in the keep-alive answer differs from the local one, agentd downloads the group configuration and reloads the agent to apply it (see [After enrollment](#after-enrollment))

### Component Interaction

```
┌─────────────────────┐
│   Data Collection   │
│  (syscheck, sca,    │
│   syscollector...)  │
└──────────┬──────────┘
           │ Events (local queue)
           ▼
┌─────────────────────┐
│   agentd (client)   │
│  - Batching         │
│  - zstd compression │
│  - Buffering        │
└──────────┬──────────┘
           │ HTTPS (TLS), port 1517
           ▼
┌─────────────────────────┐
│   Wazuh Manager         │
│ (wazuh-manager-remoted) │
└─────────────────────────┘
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

Prints `WAZUH_VERSION`, `WAZUH_REVISION` and `WAZUH_TYPE` (`-v`, `-r` or `-t` prints just one).
The connection state is in `/var/ossec/var/run/wazuh-agentd.state` (`status='connected'`, last
keepalive, event counters), rewritten every `agent.state_interval` seconds.

### Enrolling or re-pointing an agent

An agent that installed without a token needs one of these afterwards to register, register again, or point at a manager whose certificate authority or address has changed.

**On Windows**, the tray GUI (`win32ui.exe`, the tray icon) is the normal way to do this: **Manage → Enroll** asks for a token and registers or re-registers the agent, confirming first when it is already enrolled since that assigns a new id; **Manage → Update CA** refreshes the trust anchor and manager address on an already-enrolled agent. Both stop the agent service first if it's running — the underlying tool refuses otherwise — and offer to start it again once the operation finishes.

Both actions drive `wazuh-agent-auth`, the same command-line tool used directly on Linux and macOS (and available on Windows too, for scripting). It is installed in the agent's `bin/` directory, which is not on `PATH` (`/Library/Ossec/bin/` on macOS), and runs as root:

```bash
echo '<TOKEN>' | sudo /var/ossec/bin/wazuh-agent-auth                          # enroll
sudo /var/ossec/bin/wazuh-agent-auth --token-file /root/token                  # enroll from a file
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
| `--show-token` | Prints what a token carries, including the token id the manager lists and revokes it by, without its credential. Contacts nothing and writes nothing |
| `-h`, `--help` | Usage |

**Options**

| Option | Effect |
|---|---|
| `--token-file <path>` | Read the token from `<path>`, or from standard input with `-` |
| `-n`, `--dry-run` | Report what would change. Contacts nothing, writes nothing |
| `-d` | Debug output, repeatable |
| `--force-enroll` | Required when the agent already has a key. It is registered again and receives a **new** id. The previous id is named; what becomes of it is the manager's replacement policy |

The agent name, groups and address come from `<enrollment>` in `ossec.conf`, so the command takes none of them and a later re-enrollment by the agent itself registers the same name and address; its groups stay those on the manager.

It refuses to run while `wazuh-agentd` is running, with no override. A restart is needed either way, since the agent loads its identity once at startup.

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Done |
| `1` | Could not run |
| `2` | Token rejected |
| `3` | CA not established |
| `4` | Enrollment refused by the manager, or not completed. When the failure may clear on its own (no answer, a `429` or `5xx`, a node that does not know the token, or a clock the manager refuses), the first line reads `the enrollment did not go through` and the command says what to try. A token the manager does not know may also be one that no longer exists there: if it keeps failing, mint a new one |
| `5` | Not committed |
| `6` | Configuration not updated |

On exit code `4` the manager's reason is printed after `The manager said:`. When the manager refused the token itself (expired, revoked, out of uses, or unknown to the master, not merely to a worker that has not received it yet), a `Token refused:` line comes first, naming the token id, what happened to it and the fix. The Windows agent GUI shows that line's text in its message box, after "The manager refused the enrollment request:":

```text
wazuh-agent-auth: the manager refused the enrollment.
  Token refused: enrollment token e0093KT752obCNyE_JHPKA was revoked. Create a new enrollment token on the manager.
  The manager said: Invalid client authentication
  Nothing was changed.
```

**Moving an agent to another manager.** Which action applies depends on whether the new manager already knows this agent:

- **The same deployment, after the manager rotated its certificate authority or changed its address** — `--certs-only`. The agent keeps its id and its history.
- **A different deployment, which has never seen this agent** — `--force-enroll`. The agent registers from scratch and receives a new id.

Behind a load balancer there is nothing to re-point between nodes: the agent addresses the balancer, and which node answers a given request is not something it tracks.

### After enrollment

An agent that has just enrolled reloads itself once, shortly after it starts talking to the manager. This is expected.

1. **Key in use.** After the enrollment-token bootstrap, or after `wazuh-agent-auth` and a start, the agent uses its new key at once. An enrollment run by the agent's own loop (an agent with no key and no token) waits [`<delay_after_enrollment>`](configuration.md#delay_after_enrollment) seconds (20 by default) first.
2. **Modules on hold.** With `agent.remote_conf=1` (the default), `wazuh-syscheckd`, `wazuh-logcollector` and `wazuh-modulesd` wait at every start until the agent holds the configuration of its groups. The keep-alive answer names that configuration by its hash. If the local `etc/shared/merged.mg` already matches it, or the manager reports no configuration for the groups, the modules start at once and nothing is reloaded.
3. **Download and reload.** A newly enrolled agent has no matching `merged.mg`, so it downloads the group configuration (`POST /download`), validates it and reloads to start the modules with it. The reload runs whatever [`<auto_restart>`](configuration.md#auto_restart) says, because the modules are waiting for it. `ossec.log` shows `Agent is reloading due to shared configuration changes.`, or `Agent is reloading to apply startup hash validated configuration.` when `auto_restart` is `no`.

On Linux and macOS the reload is `wazuh-control reload` (`systemctl reload wazuh-agent` while systemd runs the agent): it restarts every daemon except `wazuh-agentd`. On Windows it stops and starts the agent service. A configuration that fails validation is not applied, and the modules stay on hold until the manager provides a valid one (see [Centralized configuration](../agent-management/centralized-configuration.md)).

When the manager later reports the agent's key as unknown, the running agent enrolls again on its own (with its [re-enrollment secret](configuration.md#re-enrollment) when it holds one), waits `<delay_after_enrollment>`, and logs `https_client: re-enrollment succeeded; reloading the signing identity.` Its daemons keep running; a reload follows only if the manager then reports a different configuration hash, and only with `auto_restart` enabled.

---

## Troubleshooting

### Agent Not Connecting

Start with the agent's own log:

```bash
sudo grep -E "cacerts|pin_mismatch|verified enrollment|TLS verification|\(41[0-9]{2}\)" /var/ossec/logs/ossec.log | tail -20
```

| What the agent says | What it means | What to do |
|---|---|---|
| `/cacerts adr_unreachable` | The address in the token answers nothing | Check routing, and that the manager is listening on 1517 |
| `tls_rejected` (on `/cacerts` or `/enroll`) | The manager was reached but refused the TLS handshake over the agent's client certificate; the alert it sent is named in parentheses (`certificate required`: none was presented; `unknown ca`, `bad certificate`, `certificate expired`: the one presented is not accepted). Retrying does not change it, so the agent does not retry | Set `<ssl><certificate>` and `<key>` to a certificate signed by the CA the manager checks client certificates against (`remote.https` `verification_mode` `certificate` or `full`). The token bootstrap presents it on both `/cacerts` and `/enroll`. A token does not replace it |
| `/cacerts not_found` | The manager answered, but has no CA to hand out | Nothing on the endpoint changes this. The manager has to be given its CA before any agent can bootstrap against it |
| `/cacerts ca_mismatch` | The certificate the manager serves does not chain to the CA it would hand out — a CA that expired, or whose validity window has not opened yet, counts as not chaining | Nothing on the endpoint changes this. Retrying will keep failing until the manager's certificate and CA match (a CA that is merely not yet valid heals on its own once its window opens) |
| `pin_mismatch` | The CA the manager served is not the one the token pins | Wrong token, wrong manager, or the CA was rotated after the token was minted (see [Enrollment tokens and a rotation](../remoted/ca-rotation.md#enrollment-tokens-and-a-rotation)). Use a fresh token |
| `The verified enrollment request could not be sent: (60) SSL peer certificate … was not OK` | The certificate of the manager node the agent enrolls through failed verification: it does not chain to the CA the token gave the agent, or it does not name the token's address | The detail after `(60)` says which. A chain error usually means a token minted before a CA rotation (see [Enrollment tokens and a rotation](../remoted/ca-rotation.md#enrollment-tokens-and-a-rotation)); use a fresh token. A name error means that node's certificate lacks the token's address in its SAN |
| `(4118)` | The mode needs a CA, and neither `<certificate_authorities>` nor the trust anchor is present | Enroll with a token, or name a CA |
| `(4120)` | `system` together with an explicit `<certificate_authorities>` | Drop one of the two: remove the CA to use the OS trust store, or keep it and set the mode to `full` |
| `(4121)` | `system` on a host with no OS CA bundle | Use `full` against the trust anchor instead |
| `(4123)` | The CA file is readable but holds no certificate the agent can parse | Replace the file; truncated copies are the usual cause |
| `(4124)` | `system`, and the trust anchor is readable but holds no certificate the agent can parse | Replace the anchor, or enroll with a token to reinstall it; truncated copies are the usual cause |
| `(4125)` | The trust anchor is gone, but this install has held one (`.anchor-committed` is still beside it) | Restore the anchor, or set `<verification_mode>` explicitly to say what was intended. Starting unverified is refused rather than done silently |
| `(4122)` | An explicit `none` on a host that holds a usable anchor | Remove `<verification_mode>none</verification_mode>` to verify against it |
| `(4126)` | No anchor, but a remote upgrade delivered the manager's CA and could not install it (usually the `openssl` command is missing), so it is still in `var/incoming/root-ca.pem`. The agent runs with `none` | Install the anchor with [`--certs-only`](#enrolling-or-re-pointing-an-agent); a token minted with `--no-credential` is enough. See [When the CA cannot be validated on the agent](../../../guide/migration/remote-agent-upgrade.md#when-the-ca-cannot-be-validated-on-the-agent) |
| `(4127)` | An explicit `none` on an agent enrolling with a token. `none` applies only after enrollment, and the enrollment is still verified against the token's CA | Nothing, if the enrollment succeeds. If it then fails with `pin_mismatch` or `The verified enrollment request could not be sent: (60)`, see those rows: `none` does not bypass either. Logged once per run, then at debug level |
| `(4128)` | Logged after `(4112)`: `<manager><endpoint>` still holds the package's placeholder and `client.keys` is empty, so the agent was installed without a token and never enrolled. It does not start | Enroll it as described in [Enrolling or re-pointing an agent](#enrolling-or-re-pointing-an-agent), then start the agent |
| `(4129)` | `<verification_mode>` is not set and there is no readable trust anchor, so the agent connects with `none` without checking the manager's certificate. An install that has held an anchor gets `(4125)` instead; this one has no `.anchor-committed` beside it | Install the anchor with [`--certs-only`](#enrolling-or-re-pointing-an-agent), or set `<verification_mode>none</verification_mode>` if running unverified is intended |
| `/enroll answered HTTP <code> with no message the agent could read` (from `wazuh-agent-auth`) | Something answered `/enroll` with an error page or an empty body instead of the manager's JSON error: usually a load balancer or proxy in front of the manager. A `404` has its own message, below | Check the balancer and the manager nodes behind it. A `5xx` usually clears on its own; run the command again |
| `/enroll answered HTTP 404: nothing serves /enroll under the path '/<path>'` (from `wazuh-agent-auth`) | The path in the enrollment address does not match the prefix the manager serves. The manager always serves `/enroll`, so its 404 means a wrong path. With a token that embeds the CA, `/cacerts` is skipped, so this is where a wrong prefix first shows | Correct the path in the token's address (or `<endpoint>`) to the manager's prefix, then run the command again; waiting does not help |
| `TLS verification failed connecting to …: the certificate does not include that name` | The address the agent dials is not in the certificate | The line lists the names the certificate does carry |
| `TLS verification failed connecting to …: the certificate has expired` / `is not valid yet` | The manager's certificate is outside its validity window, or the clock is wrong | The line gives the date it checked against |
| `TLS verification is DISABLED (verification_mode=none)` | The resolved mode is `none` | See the resolution table under [`verification_mode`](configuration.md#verification_mode) |
| `verification_mode=system: … falling back to the local trust anchor ('…')` | The OS trust store did not vouch for the manager, so the agent verified against its own anchor instead | Nothing, if the agent connects after it. To verify against the OS trust store instead, add the manager's CA there and restart the agent |
| `verification_mode=system: … no local trust anchor is configured to fall back to` | The OS trust store does not vouch for this manager, and there is no anchor to fall back to | Add the manager's CA to the OS trust store, or enroll with a token so the agent holds an anchor. Logged once per run; the agent keeps retrying and recovers once the store carries the CA |
| `verification_mode=system: … no time remains in this attempt's budget to try the local fallback anchor ('…')` | The attempt against the OS trust store used the whole request timeout, so the anchor was never tried | Usually a slow or overloaded manager. Logged once per run, then at debug level |
| `local fallback anchor ('…') could not be loaded (missing, unreadable, or not a certificate this agent can parse)` | The anchor was present when the agent started and is not usable now | The agent stops. Restore the anchor file, or enroll with a token to reinstall it, then start the agent |
| `local fallback anchor ('…') does not verify the manager's certificate either` | Neither the OS trust store nor the anchor vouches for this manager | The agent keeps retrying. Usually the manager's CA was rotated: add the new CA to the OS trust store and restart the agent. If nothing changed on the manager, something between the agent and the manager is presenting its own certificate |
| `verification_mode=system found no OS trust store on this system … and the local fallback anchor ('…') does not verify it either` | There is no OS trust store to consult, and the anchor does not match this manager | The agent keeps retrying. Install the OS CA bundle, add the manager's CA to it, and restart the agent. Alternatively, set the mode to `full`, stop the agent, refresh the anchor with [`wazuh-agent-auth --certs-only`](#enrolling-or-re-pointing-an-agent) and a fresh token, and start it; under `full` the agent follows later CA rotations on its own. If nothing changed on the manager, something between the agent and the manager is presenting its own certificate |

> [!NOTE]
> If nothing above matches, raise the agent's log level with `agent.debug=1` in `local_internal_options.conf` and restart it. Not every TLS failure is reported at normal level so a connection problem with nothing in the log is a reason to turn debug on rather than to rule TLS out.

Confirm what the agent holds:

```bash
sudo ls -l /var/ossec/etc/certs/root-ca.pem /var/ossec/etc/client.keys
sudo grep -A4 "<ssl>" /var/ossec/etc/ossec.conf
```

The trust anchor should be `0640 wazuh:wazuh`. A root-owned file the `wazuh` user cannot read fails closed just as a missing one does, and a directory listing looks right until the group is checked.

If the agent has no anchor, or the manager's has changed, refresh it with [`wazuh-agent-auth --certs-only`](#enrolling-or-re-pointing-an-agent) rather than copying the file by hand. That includes a CA a remote upgrade left in `var/incoming/root-ca.pem` without installing it: once an anchor is in place, `--certs-only` (and a token enrollment) removes that staged copy, so a later upgrade cannot install it over the anchor.

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

A CA still in `var/incoming` names the cause for an agent upgraded remotely: the manager delivered it but the installer could not validate it, usually for lack of the `openssl` command:

```bash
sudo test -f /var/ossec/var/incoming/root-ca.pem && echo "DELIVERED CA NOT INSTALLED"
```

See [Trust anchor delivery to legacy agents](../../../guide/migration/remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents) for the delivery and for confirming it ran.

### Buffer Overflow

Events wait in an in-memory accumulator that holds up to four times `<agent><batch><size>`. While the manager
cannot be reached or does not keep up, it fills, and `ossec.log` reports each level:

| Message | Meaning |
|---|---|
| `Agent buffer at <agent.warn_level> %.` | Warning level reached |
| `Agent buffer is full: Events may be lost.` | Full: new events are dropped |
| `Agent buffer is flooded: Producing too many events.` | Still full after `agent.tolerance` seconds |
| `Agent buffer is under <agent.normal_level> %. Working properly again.` | Back to normal (debug level) |

Each change of level is also sent to the manager as an event. To act on it:

1. Check that the agent reaches the manager: `status='connected'` in `/var/ossec/var/run/wazuh-agentd.state`.
2. If the agent is connected and still fills up, raise `<agent><batch><size>` within the manager's request limits
   (see [`batch`](configuration.md#batch)), or reduce what the agent collects.

### Agent package cannot be removed

If `apt remove` or `yum remove` of the agent fails with `Validation host not provided. Uninstallation
cannot be continued.`, uninstall protection is on: `<anti_tampering><package_uninstallation>` is `yes` in
the group's `agent.conf` (which wins) or in the local `ossec.conf`.

1. Check the value the agent applies: its [configuration report](configuration.md#config_report), indexed in
   `wazuh-agent-config`, carries it as `wazuh.agent.configuration.content.agent.package_uninstallation.package_uninstallation`
2. Validate the removal: set `VALIDATION_HOST` and `VALIDATION_TOKEN` (or `VALIDATION_LOGIN`) for the
   package command, or in a root-owned `/var/ossec/etc/uninstall_validation.env`
3. Or turn it off: set `package_uninstallation` to `no` where it is set, and wait for the agent to apply it

---

## See Also

- [Client Configuration Reference](configuration.md) - Complete configuration options
- [Manager Configuration Reference](../../configuration/manager/reference.md) - Manager-side `<remote>` settings
- [Centralized Configuration](../agent-management/centralized-configuration.md) - Remote agent configuration
- [Enrollment lifecycle](../authd/enrollment-lifecycle.md) - Agent registration, end to end
- [Trust anchor delivery to legacy agents](../../../guide/migration/remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents) - How an agent upgraded from 4.x receives its CA
