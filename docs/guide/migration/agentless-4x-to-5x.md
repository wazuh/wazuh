# Migrating from Agentless to Supported Alternatives

In Wazuh 4.x, the **Agentless** module (`wazuh-agentlessd`) allowed the Wazuh
manager to monitor remote hosts directly over SSH without deploying a Wazuh
agent on them. The daemon ran on the manager, established SSH sessions using
Expect scripts, and forwarded results to the analysis pipeline.

Starting with Wazuh 5.0, the Agentless module has been fully removed. This
guide describes what Agentless did, identifies the most common use cases, and
maps each one to a supported alternative available in 5.0.

> **Manual migration required.** There is no automated converter. Every
> agentless entry in `ossec.conf` must be replaced by an equivalent 5.x
> mechanism.

## What Agentless did in 4.x

The `wazuh-agentlessd` daemon was configured through `<agentless>` blocks in
the manager's `ossec.conf`. Each block described a remote host (or set of
hosts), a built-in SSH script, and an operational mode.

### Configuration format

```xml
<!-- Wazuh 4.x: ossec.conf (manager) -->
<agentless>
  <type>ssh_integrity_check_linux</type>
  <frequency>3600</frequency>
  <host>user@192.168.1.10</host>
  <state>periodic</state>
  <arguments>/etc /usr/bin /usr/sbin</arguments>
</agentless>
```

| Option | Description |
|--------|-------------|
| `<type>` | SSH script to run (see built-in scripts below). |
| `<frequency>` | How often to run, in seconds (required for `periodic` and `periodic_diff` modes). |
| `<host>` | Defines the username and the name of the agentless host. |
| `<state>` | Determines whether the type of check is periodic or periodic_diff. |
| `<arguments>` | Defines the arguments passed to the agentless check. |


### Operational modes

| Mode | Description |
|------|-------------|
| `periodic` | Output from each check is analyzed with the Wazuh ruleset as if a monitored log. |
| `periodic_diff` | Output from each agentless check is compared to the output of the previous run. Changes are alerted on, similar to file integrity monitoring. |

### Built-in scripts

| Script | Purpose |
|--------|---------|
| `ssh_integrity_check_linux` | Collects MD5, SHA1 and stat metadata for files on a Linux host via SSH. |
| `ssh_integrity_check_bsd` | Same as above for BSD-based systems. |
| `ssh_generic_diff` | Runs arbitrary commands and stores their output for diff comparison. |
| `ssh_pixconfig_diff` | Retrieves and diffs the running configuration of a Cisco PIX firewall. |
| `ssh_asa-fwsmconfig_diff` | Retrieves and diffs the running configuration of a Cisco ASA or FWSM firewall (DES cipher, enable mode). |
| `ssh_foundry_diff` | Retrieves and diffs the running configuration of a Foundry/Brocade device. |

### Host registration

Hosts with password authentication were registered using the manager-side
helper:

```sh
/var/ossec/agentless/register_host.sh add user@192.168.1.10 password
```

SSH-key authentication (passphrase-less keys) required no registration.

---

## Use-case mapping

The table below lists the most common Agentless use cases and their recommended
replacement in Wazuh 5.0.

| 4.x use case | Recommended 5.0 alternative |
|---|---|
| File integrity monitoring on remote Linux/Unix hosts | Wazuh agent + FIM module |
| File integrity monitoring on remote hosts (agent not installable) | Custom SSH script on a relay agent + Logcollector `command` |
| Configuration diff on network devices (ASA, PIX, Foundry) | Custom SSH script on a relay agent + Logcollector `full_command` |
| Periodic command execution on remote hosts | Custom SSH script on a relay agent + Logcollector `command` or `<wodle name="command">` |
| Configuration assessment on remote Linux/Unix hosts | Wazuh agent + SCA module |

---

## Alternative 1: Wazuh agent (preferred)

For any remote host running a supported OS,
the preferred migration path is to install a Wazuh agent directly on that host.
The agent provides:

- **FIM** (`<syscheck>`), replaces `ssh_integrity_check_linux` / `ssh_integrity_check_bsd`
- **SCA** (`<sca>`), replaces periodic configuration auditing
- **Logcollector** (`<localfile>`), replaces periodic command execution

See the [installation documentation](../../INSTALLATION.md) for how to deploy
and enroll agents.

### FIM configuration replacing ssh_integrity_check_linux

```xml
<!-- Wazuh 5.0: agent ossec.conf -->
<syscheck>
  <disabled>no</disabled>
  <frequency>3600</frequency>
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
</syscheck>
```

### SCA configuration replacing periodic configuration auditing

Enable SCA on the agent and choose a policy for the OS. Built-in policies are
located in `/var/ossec/ruleset/sca/` on the agent.

```xml
<!-- Wazuh 5.0: agent ossec.conf -->
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
</sca>
```

See the [SCA policies migration guide](sca-policies-4x-to-5x.md) for custom
policy format changes between 4.x and 5.x.

---

## Alternative 2: Logcollector command monitoring on a relay agent

When a Wazuh agent cannot be installed on the target host (network appliances,
embedded devices, legacy systems), run an SSH command from a **relay host** that
does have a Wazuh agent. The agent collects the output with Logcollector and
forwards it to the manager for analysis.

This covers the `periodic` mode and all `ssh_*_diff` scripts.

> **These scripts are not provided by Wazuh 5.x.** The code blocks below are
> reference templates that you must create and deploy on the relay agent.
> Adjust paths, credentials, and target addresses to match your environment.

### Replacing ssh_integrity_check_linux (periodic mode)

Run the same stat/md5sum/sha1sum loop that the original script did, but from a
relay agent. Place the logic in a dedicated script so the XML stays clean:

```sh
#!/bin/bash
# /var/ossec/agentless/agentless_fim.sh
# Usage: agentless_fim.sh <ssh_target> <dir1> [dir2 ...]

TARGET="$1"
shift
DIRS="$*"

ssh -i /var/ossec/agentless/keys/relay_key \
    -o StrictHostKeyChecking=yes \
    -o UserKnownHostsFile=/var/ossec/agentless/keys/known_hosts \
    -o BatchMode=yes \
    "$TARGET" \
    "find $DIRS -type f 2>/dev/null | while IFS= read -r i; do
       md5=\$(md5sum \"\$i\" 2>/dev/null | cut -d' ' -f1)
       sha1=\$(sha1sum \"\$i\" 2>/dev/null | cut -d' ' -f1)
       stat --printf '%s:%a:%u:%g' \"\$i\" 2>/dev/null && echo \":\$md5:\$sha1 \$i\"
     done"
```

> **Linux targets only.** The remote commands above (`md5sum`, `sha1sum`,
> `stat --printf`) are GNU coreutils and are not available on BSD systems.
> On FreeBSD or OpenBSD targets, the equivalent commands are `md5 -q`,
> `sha1 -q`, and `stat -f '%z:%p:%u:%g'`. Install a Wazuh agent directly on
> BSD hosts where possible (Alternative 1); if that is not an option, adapt
> the remote commands before deploying the script.

```xml
<!-- Wazuh 5.0: relay agent ossec.conf -->
<localfile>
  <log_format>command</log_format>
  <command>/var/ossec/agentless/agentless_fim.sh user@192.168.1.10 /etc /usr/bin /usr/sbin</command>
  <alias>agentless_fim_192.168.1.10</alias>
  <frequency>3600</frequency>
</localfile>
```

> The `<frequency>` value is in seconds. The equivalent `<wodle name="command">`
> would use `<interval>1h</interval>` — see
> [Alternative 3](#alternative-3-wazuh-command-wodle) for the suffix syntax.

### Replacing ssh_generic_diff (periodic_diff mode)

`ssh_generic_diff` connected to the remote host and executed whatever command
was in `<arguments>`. The script itself did not produce the diff, it only
emitted `STORE: now` to signal the daemon to start capturing output. The
`agentlessd` daemon then wrote that output to a snapshot file, compared its
MD5 against the previous run, and if they differed, ran `diff` between the two
files and generated the alert.

In 5.0 that internal mechanism is gone. The equivalent is a wrapper script that
replicates the three steps: run the remote command, compare with the previous
snapshot, emit the diff if changed:

```sh
#!/bin/bash
# /var/ossec/agentless/agentless_diff.sh
# Usage: agentless_diff.sh <ssh_target> <remote_command> <snapshot_path>

TARGET="$1"
REMOTE_CMD="$2"
SNAPSHOT="$3"
CURRENT=$(ssh -i /var/ossec/agentless/keys/relay_key -o StrictHostKeyChecking=yes \
              -o UserKnownHostsFile=/var/ossec/agentless/keys/known_hosts \
              -o BatchMode=yes "$TARGET" "$REMOTE_CMD" 2>/dev/null)

if [ $? -ne 0 ] || [ -z "$CURRENT" ]; then
    # Keep the existing snapshot intact so the next run re-compares against it.
    exit 1
fi

if [ -f "$SNAPSHOT" ]; then
    DIFF=$(diff "$SNAPSHOT" <(echo "$CURRENT"))
    if [ -n "$DIFF" ]; then
        echo "ossec: agentless: Change detected:"
        echo "Target: $TARGET"
        echo "$DIFF"
    fi
fi

echo "$CURRENT" > "$SNAPSHOT"
```

```xml
<!-- Wazuh 5.0: relay agent ossec.conf -->
<localfile>
  <log_format>full_command</log_format>
  <command>/var/ossec/agentless/agentless_diff.sh admin@192.168.1.1 "show running-config" /var/ossec/agentless/snapshots/firewall_192.168.1.1.snap</command>
  <alias>agentless_diff_firewall_192.168.1.1</alias>
  <frequency>3600</frequency>
</localfile>
```

### Replacing Cisco ASA / PIX / Foundry config diff

The three device-specific scripts (`ssh_asa-fwsmconfig_diff`,
`ssh_pixconfig_diff`, `ssh_foundry_diff`) were not generic SSH wrappers. Each
one had hardcoded knowledge of its target platform:

| Aspect | Cisco PIX (`ssh_pixconfig_diff`) | Cisco ASA/FWSM (`ssh_asa-fwsmconfig_diff`) | Foundry/Brocade (`ssh_foundry_diff`) |
|--------|----------------------------------|---------------------------------------------|--------------------------------------|
| SSH cipher | `ssh -c des` (DES only) | `ssh -c des` (DES only) | Standard SSH |
| Disable paging | `no pager` + `term len 0` + `terminal pager 0` | `term pager 0` | `skip-page-display` |
| Enable mode | Always, two passwords required | Always, two passwords required | Optional, only if `addpass` set |
| Commands run | `show version \| grep -v "Configuration last\| up"`, then `show running-config`, then `$commands` | Same as PIX | `sh run`, then `$commands` |
| Uptime excluded | Yes, `grep -v` strips the uptime line to avoid spurious diffs | Yes | No |

The `show version | grep -v "Configuration last| up"` line was intentional: it
stripped the uptime and last-reload timestamp from the output so that the diff
would not fire an alert on every run simply because the device had been up one
hour longer.

The two-password model mapped to the `<host>` field in `ossec.conf`: the first
password (SSH login) and a second password (enable mode) were both stored in
`.passlist` via `register_host.sh`.

**Migration path.** These devices do not support `BatchMode=yes` or key-based
authentication in most firmware versions, and their interactive CLI cannot be
driven by a plain `ssh` command. The closest equivalent in 5.0 is a wrapper
script using `sshpass` or `expect` on the relay host, replicating the same
sequence: disable paging, run the commands, compare with the previous snapshot.

Example for a Cisco ASA using `sshpass` (install it on the relay host first:
`apt install sshpass` or `yum install sshpass`):

> **Limitation:** Cisco ASA and PIX SSH servers typically open an exec channel
> that accepts a **single command** and then closes the session. Passing multiple
> lines as one quoted string is not equivalent to an interactive CLI session, and
> on many firmware versions only the first line executes. For reliable
> multi-command sequences, replace the `sshpass`/`ssh` call with an `expect`
> script that drives the interactive CLI. The script below works on firmware
> versions that do process multi-line exec input, but must be validated against
> your specific device before use in production.

> **Security note:** With `-f`, `sshpass` reads the password from a file rather
> than from the process environment or command line. The risk is file exposure:
> set ownership to `wazuh:wazuh` and permissions to `600` on the password file.
> Restrict access to the relay host accordingly and prefer key-based
> authentication whenever the device firmware supports it.

```sh
#!/bin/bash
# /var/ossec/agentless/asa_diff.sh

HOST="$1"
SNAPSHOT="$2"

CURRENT=$(sshpass -f /var/ossec/agentless/keys/asa_pass \
    ssh -c aes256-ctr -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile=/var/ossec/agentless/keys/known_hosts \
        admin@"$HOST" \
    "term pager 0
show version | grep -v 'Configuration last\|up '
show running-config
exit" 2>/dev/null)

if [ $? -ne 0 ] || [ -z "$CURRENT" ]; then
    exit 1
fi

if [ -f "$SNAPSHOT" ]; then
    DIFF=$(diff "$SNAPSHOT" <(echo "$CURRENT"))
    if [ -n "$DIFF" ]; then
        echo "ossec: agentless: Change detected:"
        echo "Target: $HOST"
        echo "$DIFF"
    fi
fi

echo "$CURRENT" > "$SNAPSHOT"
```

> **Note:** The original scripts used `ssh -c des` because early PIX/ASA
> firmware only supported DES. Use `aes256-ctr` unless the device firmware is
> too old to support it, in which case fall back to `aes256-cbc`. To verify what your relay host accepts, run
> `ssh -Q cipher`. Modern ASA firmware (9.x+) supports `aes256-ctr`. For
> devices with RESTCONF or NETCONF support, prefer those APIs over interactive
> SSH.

---

## Alternative 3: Wazuh command wodle

For periodic command execution with checksum-verified scripts, use
`<wodle name="command">` on the relay agent. This is equivalent to the
`periodic` mode when the command output should be ingested as structured
events rather than plain log lines.

```xml
<!-- Wazuh 5.0: relay agent ossec.conf -->
<wodle name="command">
  <disabled>no</disabled>
  <tag>agentless_remote_check</tag>
  <command>/var/ossec/agentless/agentless_diff.sh admin@192.168.1.1 "show running-config" /var/ossec/agentless/snapshots/asa.snap</command>
  <interval>1h</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>120</timeout>
</wodle>
```

| Option | Description |
|--------|-------------|
| `<disabled>` | `yes`/`no`. Disables the module without removing it. Default: `no`. |
| `<tag>` | Label applied to the generated event (optional). |
| `<command>` | Full command line to execute. Required. |
| `<interval>` | How often to run. Number followed by a suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `M` (months). Default: `2s`. |
| `<timeout>` | Maximum execution time in seconds. The process is killed if it exceeds this value. `0` means no limit. |
| `<run_on_start>` | `yes`/`no`. Run immediately on startup before waiting for the first interval. Default: `yes`. |
| `<ignore_output>` | `yes`/`no`. Discard stdout/stderr. Use when the command is run for side effects only. Default: `no`. |
| `<verify_md5>` | Expected MD5 hash (32 hex chars) of the command binary. The module refuses to run if the hash does not match. |
| `<verify_sha1>` | Expected SHA1 hash (40 hex chars) of the command binary. |
| `<verify_sha256>` | Expected SHA256 hash (64 hex chars) of the command binary. |
| `<skip_verification>` | `yes`/`no`. Log a warning instead of aborting when a checksum fails. Default: `no`. |

---

## Security considerations

The 4.x Agentless module stored SSH passwords in plaintext in
`/var/ossec/agentless/.passlist`. When migrating to SSH key–based authentication
on the relay host:

1. Create the directory and generate a dedicated key pair for the relay host:
   ```sh
   mkdir -p /var/ossec/agentless/keys
   chown wazuh:wazuh /var/ossec/agentless/keys
   chmod 700 /var/ossec/agentless/keys
   ssh-keygen -t ed25519 -f /var/ossec/agentless/keys/relay_key -N ""
   ```
2. Install the public key on each monitored host:
   ```sh
   ssh-copy-id -i /var/ossec/agentless/keys/relay_key.pub user@192.168.1.10
   ```
3. Collect the SSH host key of each monitored host into the dedicated
   `known_hosts` file **before** running any script with
   `StrictHostKeyChecking=yes`:
   ```sh
   ssh-keyscan -H 192.168.1.10 >> /var/ossec/agentless/keys/known_hosts
   chown wazuh:wazuh /var/ossec/agentless/keys/known_hosts
   chmod 600 /var/ossec/agentless/keys/known_hosts
   ```
   Without this step, the first connection attempt fails with "Host key
   verification failed" even when credentials and key pairs are correct.
4. Restrict the key on the remote `authorized_keys` to the specific command it
   needs to run (if the target is a full Unix host). Place the full monitoring
   logic in a fixed script on the target (e.g.
   `/usr/local/bin/wazuh-fim-check`) and point `command=` at that wrapper.
   Inlining the full stat/checksum loop directly in `authorized_keys` is
   fragile because any change to the directories being monitored also requires
   updating `authorized_keys`. When a forced command is set, SSH ignores the
   command sent by the client and always executes `command=` instead:
   ```
   command="/usr/local/bin/wazuh-fim-check",no-port-forwarding,no-pty ssh-ed25519 AAAA... relay
   ```
5. Use `StrictHostKeyChecking=yes` (shown in the examples above) to prevent
   man-in-the-middle attacks.
6. Restrict permissions on snapshot files. These files store device running
   configurations and can contain sensitive data (credentials, ACLs). Set
   ownership and mode immediately after creating the snapshot directory:
   ```sh
   mkdir -p /var/ossec/agentless/snapshots
   chown wazuh:wazuh /var/ossec/agentless/snapshots
   chmod 700 /var/ossec/agentless/snapshots
   ```
   Any snapshot file written by the scripts (e.g. `firewall_192.168.1.1.snap`)
   will inherit the directory's restricted access. If you create snapshot files
   manually or outside the scripts, set their permissions explicitly:
   ```sh
   chown wazuh:wazuh /var/ossec/agentless/snapshots/*.snap
   chmod 600 /var/ossec/agentless/snapshots/*.snap
   ```

---

## Rule migration

In 4.x, Agentless diff alerts were generated with the message prefix
`ossec: agentless: Change detected:` and matched by built-in rules in the
`agentless` rule group. With the wrapper script approach above, the same prefix
is preserved so existing rules continue to fire:

```sh
echo "ossec: agentless: Change detected:"
```

If you relied on rules that matched on the `agentless` group or on specific
agentless rule IDs from the 4.x default ruleset, verify that your custom rules
still trigger against the new log source. Adjust the `<match>` or `<regex>`
field if needed.

> **Alternative 3 (command wodle) does not preserve rule compatibility.** The
> wodle emits a JSON event with the script output in `process.io.text` rather
> than as a plain log line, so text-based agentless rules will not fire against
> it. Use Alternative 2 (Logcollector) if you need compatibility with your
> existing agentless rule set, or write new rules that match on
> `<field name="process.io.text">` for Alternative 3 output.

---
