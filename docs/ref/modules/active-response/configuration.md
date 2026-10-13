# Active Response Configuration Reference

The Wazuh Indexer decides when a response fires, the manager relays it to the agent as a task, and
the agent's `wazuh-execd` runs the executable. What runs and when is configured in the dashboard;
the only configuration file involved is the agent's own `ossec.conf`, whose `<active-response>`
block can turn execution off or lengthen the timeouts of repeat offenders.

For module overview and architecture, see [Active Response Module](README.md).

---

## Agent Configuration

**Configuration file:** `etc/ossec.conf` under the agent's installation directory
(`/var/ossec/etc/ossec.conf`, `/Library/Ossec/etc/ossec.conf` on macOS,
`C:\Program Files (x86)\ossec-agent\ossec.conf` on Windows)

**XML Section:** `<active-response>`

**Read by:** `wazuh-execd`, once at start: a change takes effect when the agent restarts

**Internal Options:** `execd.*`

`wazuh-execd` reads this block only from the agent's local `ossec.conf`. An `<active-response>`
block in a centralized `agent.conf` is accepted without error and has no effect.

### disabled

Enable or disable active response execution on this agent.

- **Default value:** `no` when the option is absent. The agent installer writes `<disabled>no</disabled>`,
  or `yes` for a from-source install run with `USER_ENABLE_ACTIVE_RESPONSE=n`
- **Allowed values:** `yes`, `no`; any other value is a configuration error and `wazuh-execd` does not start
- **Note:** with `yes`, `wazuh-execd` logs `(1350): Active response disabled.` and does not open its
  queue. The agent still receives `active_response` tasks — they are marked delivered on the
  manager — and drops them (`active_response task <id> dropped: execd queue not available.` at debug
  level)

### repeated_offenders

Longer timeouts for stateful responses that recur for the same keys.

- **Default value:** none (every repetition uses the channel's `stateful_timeout`)
- **Allowed values:** a comma-separated list of up to six durations, in **minutes**; values after
  the sixth are ignored
- **Note:** applies only to stateful responses. The first time execd sees a key, the response uses
  its `stateful_timeout`; the n-th repetition of that key uses the n-th value of the list, and the
  last value once the list is exhausted. The count lives in execd's memory and restarts with it.
  execd logs `Adding offenders timeout: <n> (for #<k>)` for each value it reads

### ca_store, ca_verification

The installer also writes `<ca_store>` and `<ca_verification>` into this block. `wazuh-execd` does
not read them: they are the former location of the WPK signature settings, which the agent upgrade
module still reads from here when its own block sets no `ca_store`. See
[Agent upgrade configuration](../agent_upgrade/configuration.md).

---

## Agent Configuration Examples

### Default Configuration

```xml
<active-response>
  <disabled>no</disabled>
</active-response>
```

### Disable Active Response

Prevent this agent from executing any active response:

```xml
<active-response>
  <disabled>yes</disabled>
</active-response>
```

### Repeat offenders

The second occurrence of a stateful response for the same keys is reverted after 30 minutes, the
third after 60, and every later one after 120:

```xml
<active-response>
  <disabled>no</disabled>
  <repeated_offenders>30,60,120</repeated_offenders>
</active-response>
```

---

## Manager Configuration

There is no `<active-response>` section in `wazuh-manager.conf`: in 5.0 the manager neither defines
response triggers nor runs response scripts. A response is configured in the Wazuh Indexer, from the
dashboard:

1. a **notification channel** of the Active Response type says what to run: `name`, `executable`,
   `extra_arguments`, `type` and `stateful_timeout`, `location` and, for `defined-agent`, `agent_id`;
2. an **Alerting monitor** says when: a trigger whose action targets that channel writes one response
   document per matching event into `wazuh-active-responses`. The monitor must watch
   `wazuh-events-v5-*` or `wazuh-findings-v5-*`: the manager discards a response whose event lives
   in any other index.

The manager's part is the poller in `wazuh-manager-clusterd`, described in
[Manager-side ingestion](architecture.md#manager-side-ingestion). Its settings are internal, in
`intervals.common` of `framework/wazuh/core/cluster/cluster.json`, a file that is not meant for user
editing and is replaced on upgrade: `active_response_polling`, `active_response_page_size` and
`active_response_event_grace`. Defaults and trade-offs are in
[Settings](architecture.md#settings).

Manager-side log lines are in `logs/cluster.log` under the `[Active Response]` tag; the message
catalogue is in [Messages](architecture.md#messages).

---

## Internal Options

Set agent internal options in `etc/local_internal_options.conf` under the agent's installation
directory. The one that concerns Active Response:

```ini
# wazuh-execd debug level (0-2, default 0)
execd.debug=2
```

`execd.request_timeout` and `execd.max_restart_lock`, also in the `execd` group, belong to the WPK
upgrade path, not to Active Response:

```ini
# Longest restart lock, in seconds, that a WPK upgrade can request (0-3600)
execd.max_restart_lock=600

# Seconds the agent upgrade module lets the WPK installer run before killing it (1-3600)
execd.request_timeout=60
```

---

## Behavior

### Execution

The agent receives the task in the response to its `POST /control`, `wazuh-agentd` forwards the
payload to `wazuh-execd`, and execd runs `active-response/bin/<executable>` with the message on stdin
and `"command": "enable"`. The step-by-step flow is in [Message Flow](architecture.md#message-flow)
and the message format in [JSON protocol](architecture.md#json-protocol).

Executables run with:
- **Privileges:** those of `wazuh-execd`: root on Unix, the agent service's account on Windows
- **Working directory:** the agent's installation directory
- **Standard input:** the message, one JSON line; never positional arguments

### Response Timing

There is no timeout option in the agent's XML configuration or in internal options: the timing of a
response travels with it. It is the `stateful_timeout` of the Active Response notification channel,
delivered to execd in `wazuh.active_response.stateful_timeout` of the JSON message:

- **`type: stateless`:** the executable runs once with `command: enable`; `stateful_timeout` is ignored.
- **`type: stateful`:** the executable runs with `command: enable`, and execd runs it again with
  `command: disable` once more than `stateful_timeout` seconds have passed (execd checks every
  second). A missing, `null` or `0` value makes the response stateless. The reversal is only
  scheduled if the executable answers on stdout with its keys (see
  [Deduplication and timeouts](architecture.md#deduplication-and-timeouts)); one that writes nothing
  is run once.
- A stateful response repeated for the same keys while its reversal is pending is answered `abort`
  (the action is not run twice) and restarts that countdown. Pending reversals run when execd stops.
- [`repeated_offenders`](#repeated_offenders) is the only agent-side override.

execd does not bound how long an executable runs, and runs one at a time: an executable that can
hang must enforce its own limit (see [Custom Timeout per Script](#custom-timeout-per-script)).

---

## Active Response Executables

### Location

- Linux/Unix: `/var/ossec/active-response/bin/`
- macOS: `/Library/Ossec/active-response/bin/`
- Windows: `C:\Program Files (x86)\ossec-agent\active-response\bin\`

Shipped: `block-ip` (all platforms) and `disable-account` (Linux, macOS). The `executable` of the
channel names the file; on Windows execd appends `.exe` when the name has no `.`. Per-platform
behaviour and how to write your own: [Executables Reference](executables.md).

---

## Security Considerations

- Active response executables run with root/administrator privileges: install only trusted ones,
  owned `root:wazuh` with mode `0750`, as the installer does for the shipped executables
- A custom executable must validate every field it reads before passing it to a command
- Responses reach execd only as tasks the agent fetched from its manager; execd itself listens only
  on its local queue (`queue/sockets/execq` on Unix)

---

## Troubleshooting

### Active Response Not Executing on Agent

**Check that it is enabled:**
```bash
# On Linux/Unix agent
grep -A3 "<active-response>" /var/ossec/etc/ossec.conf
grep "Active response disabled" /var/ossec/logs/ossec.log

# On Windows agent
findstr /C:"active-response" "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

**Check that the manager created the task:** on the manager, the poller's cycle summary says how
many responses it read and how many tasks it created; a response it discarded has its own WARNING
or ERROR line (see [Messages](architecture.md#messages)):
```bash
grep '\[Active Response\]' /var/wazuh-manager/logs/cluster.log | tail -20
```

**Check what execd did:** every refused message has an ERROR line (see
[Agent-side messages](architecture.md#agent-side-messages)):
```bash
grep wazuh-execd /var/ossec/logs/ossec.log | tail -20
```

**Check the executable's own log:**
```bash
# On Linux/Unix
tail -f /var/ossec/logs/active-responses.log

# On Windows
type "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
```

**Verify execd is running:**
```bash
# On Linux/Unix
/var/ossec/bin/wazuh-control status | grep execd

# On Windows (execd runs inside the agent service)
sc query WazuhSvc
```

### Response Not Reverted

**Check the channel:** a response is reverted only when the notification channel's `type` is
`stateful` and its `stateful_timeout` is greater than `0` (see [Response Timing](#response-timing)).

**Check the executable answers with its keys, and how long it runs:** feed it the JSON execd sends on
stdin, followed by the `continue` answer execd gives to its `check_keys` line:
```bash
printf '%s\n' \
  '{"wazuh":{"active_response":{"name":"block-ip","executable":"block-ip","type":"stateful","stateful_timeout":600}},"source":{"ip":"192.168.1.100"},"command":"enable"}' \
  '{"wazuh":{"active_response":{"name":"block-ip","executable":"block-ip","type":"stateful","stateful_timeout":600}},"source":{"ip":"192.168.1.100"},"command":"continue"}' \
  > /tmp/ar-input.json
cd /var/ossec && time active-response/bin/block-ip < /tmp/ar-input.json
```
The `check_keys` line it prints is what execd uses to schedule the reversal. Revert the test block
by running it again with `"command":"disable"` as the only line.

### Permission Errors

```bash
ls -l /var/ossec/active-response/bin/

# Restore the installer's ownership and mode if needed
chown root:wazuh /var/ossec/active-response/bin/*
chmod 750 /var/ossec/active-response/bin/*
```

**Check SELinux/AppArmor:**
```bash
# On systems with SELinux
getenforce
ausearch -m avc -ts recent | grep execd

# On systems with AppArmor
aa-status | grep wazuh
```

### Executable Not Found

`(1311): Invalid command name '<name>' provided.` in the agent's `ossec.log` means
`active-response/bin/<name>` does not exist or cannot be read. The `executable` of the Active
Response notification channel must match a file name in that directory exactly.

```bash
ls -l /var/ossec/active-response/bin/<name>
```

### Responses Delayed

execd runs one executable at a time and waits for each to exit, so one slow or hung executable
delays every response after it:
```bash
# Executables currently running
ps -ef | grep active-response/bin
```

---

## Monitoring

**Agent:**
```bash
# What each executable did
grep -i "warning\|error\|failed" /var/ossec/logs/active-responses.log

# One executable
grep "block-ip" /var/ossec/logs/active-responses.log

# What execd received and ran (debug lines need execd.debug=1 or 2)
grep wazuh-execd /var/ossec/logs/ossec.log | tail -20
```

**Manager:**
```bash
grep '\[Active Response\]' /var/wazuh-manager/logs/cluster.log
```

---

## Advanced Configuration

### Custom Timeout per Script

execd imposes no run-time limit on an executable, so enforce one inside it:

```bash
#!/bin/bash
# Custom script with internal timeout
timeout 30 /path/to/actual-command
```

---

## See Also

- [Active Response Module](README.md) - Module overview
- [Active Response Architecture](architecture.md) - How active response works
- [Active Response Executables](executables.md) - Available response executables
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options
- [Manager Configuration Reference](../../configuration/manager/README.md) - Manager configuration (no Active Response section)
