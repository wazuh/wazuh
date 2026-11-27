# Command Module Configuration Reference

Complete configuration reference for the Command wodle.

The command wodle executes custom commands or scripts on a schedule and optionally forwards their output to the manager for analysis. This module enables integration of custom monitoring tools, audit scripts, and data collectors into Wazuh.

For module overview and use cases, see [Command Module](README.md).

---

## Configuration

**Configuration file:** `/var/ossec/etc/ossec.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\ossec.conf` (Windows)

**XML Section:** `<wodle name="command">`

**Module:** Agent-only

**Internal Options:** `wazuh_command.*`

The manager does not run this module: `wazuh-manager.conf` has no `<wodle>` section, and `wazuh-manager-modulesd` reads only its own sections from it, so a command wodle is configured on agents only (in `ossec.conf`, or pushed through the shared `agent.conf`). Each `<wodle name="command">` block is independent, allowing multiple command instances.

### disabled

Enable or disable this command wodle instance.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Each `<wodle name="command">` block is independent; you can define multiple instances

### tag

Label for this command instance (included in events and logs).

- **Default value:** None
- **Allowed values:** Any string
- **Example:** `system-check`, `audit-script`, `custom-collector`
- **Note:** Used to identify command output in logs and alerts. Omitting it logs the warning `Option <tag> not found
  at module 'command'.`; an empty one logs `Empty content for tag 'tag' at module 'command'.`

### command

Command line to execute.

- **Required:** Yes
- **Allowed values:** Any valid command string (absolute or relative path)
- **Note:** Not run through a shell: the line is split into arguments and the program is executed directly, so
  pipes, redirections and variables are not interpreted (see [How the command runs](README.md#how-the-command-runs)).
  Use absolute paths for security and reliability. On Windows a network path is refused and the instance does not run

### interval

Time between command executions.

- **Default value:** `2s`
- **Allowed values:** A positive number, optionally with a suffix: `s` (seconds, the default), `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `M` (months)
- **Minimum:** `1s`
- **Note:** With `time`, `wday` or `day`, the interval must be a multiple of a day, a week or a month respectively;
  any other value is replaced with `1d`, `1w` or `1M` and a warning. An interval in months with none of the three
  runs on the first day of the month at `00:00`

### run_on_start

Execute immediately on wodle startup (before first interval).

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Useful for ensuring immediate execution on agent start

### ignore_output

Execute command without forwarding output to the manager.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Use case:** When you only want the side effects of the command, not its output

### timeout

Maximum execution time (0 = no timeout).

- **Default value:** `0` (no timeout)
- **Allowed values:** Non-negative integer (seconds)
- **Note:** A command that exceeds it is stopped (on Linux and macOS: `SIGTERM` to its process group, then `SIGKILL`
  after `wazuh_modules.kill_timeout` seconds), `Timeout overtaken.` is logged and the event reports exit code `-1`

### time

Specific time of day to execute.

- **Default value:** None (`00:00` when `day` or `wday` is set)
- **Allowed values:** `HH:MM` format (24-hour)
- **Example:** `02:00`, `14:30`
- **Note:** The interval must be a multiple of one day (of a week with `wday`, of a month with `day`); otherwise
  it is replaced, with a warning

### day

Day of the month to execute.

- **Default value:** None
- **Allowed values:** `1` to `31`
- **Note:** The interval must be in months; any other value is replaced with `1M` and the warning `Interval must be
  a multiple of one month. New interval value: 1M`. Cannot be combined with `wday`

### wday

Day of the week to execute.

- **Default value:** None
- **Allowed values:** `sunday`, `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`
- **Note:** The interval must be a multiple of one week; any other value is replaced with `1w` and a warning. Cannot
  be combined with `day`

### verify_md5

Expected MD5 hash of the executable (blocks execution if mismatch).

- **Default value:** None
- **Allowed values:** Valid MD5 hash string (32 hexadecimal characters)
- **Purpose:** Integrity verification to prevent execution of tampered scripts
- **Note:** Command is blocked if hash doesn't match (unless `skip_verification=yes`)

### verify_sha1

Expected SHA1 hash of the executable (blocks execution if mismatch).

- **Default value:** None
- **Allowed values:** Valid SHA1 hash string (40 hexadecimal characters)
- **Purpose:** Integrity verification to prevent execution of tampered scripts
- **Note:** Command is blocked if hash doesn't match (unless `skip_verification=yes`)

### verify_sha256

Expected SHA256 hash of the executable (blocks execution if mismatch).

- **Default value:** None
- **Allowed values:** Valid SHA256 hash string (64 hexadecimal characters)
- **Purpose:** Integrity verification to prevent execution of tampered scripts
- **Note:** Command is blocked if hash doesn't match (unless `skip_verification=yes`)

### skip_verification

Continue on hash verification failure (log warning instead of blocking).

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When `yes`, a mismatch found when the module starts is logged as a warning and the command runs; the
  check before each execution is skipped. When `no`, a mismatch stops that command instance until `wazuh-modulesd`
  restarts

---

## Internal Options

Additional command wodle settings can be configured in `internal_options.conf` or `local_internal_options.conf`:

```ini
# Allow remote commands from centralized configuration (0=no, 1=yes, default: 0)
wazuh_command.remote_commands=0

# Output longer than a single message (64 KB): send it in several events (1) or truncate it (0) (default: 1)
wazuh_command.split_output=1
```

**Note:** Most configuration is done via XML. The command timeout is set with the `<timeout>` XML option.

---

## Configuration Examples

### Default Configuration

Execute a system check script every 5 minutes:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>system-check</tag>
  <command>/usr/local/bin/check.sh</command>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <timeout>30</timeout>
</wodle>
```

### With Hash Verification

Ensure script integrity before execution using SHA256:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>audit-check</tag>
  <command>/usr/local/bin/audit.sh</command>
  <interval>1h</interval>
  <verify_sha256>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</verify_sha256>
  <skip_verification>no</skip_verification>
  <timeout>60</timeout>
</wodle>
```

### Scheduled Daily Execution

Run a report script daily at 2 AM:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>daily-report</tag>
  <command>/usr/local/bin/report.sh</command>
  <interval>1d</interval>
  <time>02:00</time>
  <timeout>300</timeout>
</wodle>
```

### Weekly Execution

Run a cleanup script every Monday at 3 AM:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>weekly-cleanup</tag>
  <command>/usr/local/bin/cleanup.sh</command>
  <interval>1w</interval>
  <wday>monday</wday>
  <time>03:00</time>
</wodle>
```

### Monthly Execution

Run a backup script on the 1st of each month at midnight:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>monthly-backup</tag>
  <command>/usr/local/bin/backup.sh</command>
  <interval>1M</interval>
  <day>1</day>
  <time>00:00</time>
</wodle>
```

### Execute Without Forwarding Output

Run a command for its side effects only:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>cache-clear</tag>
  <command>/usr/local/bin/clear-cache.sh</command>
  <interval>1h</interval>
  <ignore_output>yes</ignore_output>
</wodle>
```

### High-Frequency Monitoring

Execute a monitoring script every 30 seconds:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>service-monitor</tag>
  <command>/usr/local/bin/monitor-service.sh</command>
  <interval>30s</interval>
  <run_on_start>yes</run_on_start>
  <timeout>10</timeout>
</wodle>
```

### Multiple Command Wodles

You can define multiple command wodles in the same configuration:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>disk-check</tag>
  <command>/usr/local/bin/disk-check.sh</command>
  <interval>10m</interval>
  <timeout>30</timeout>
</wodle>

<wodle name="command">
  <disabled>no</disabled>
  <tag>network-check</tag>
  <command>/usr/local/bin/network-check.sh</command>
  <interval>5m</interval>
  <timeout>15</timeout>
</wodle>

<wodle name="command">
  <disabled>no</disabled>
  <tag>security-scan</tag>
  <command>/usr/local/bin/security-scan.sh</command>
  <interval>1d</interval>
  <time>01:00</time>
  <timeout>600</timeout>
</wodle>
```

---

## Command Output Format

Command output is forwarded to the manager as events. The manager can analyze the output with custom rules.

**Output format:** one JSON event per execution, with the complete output (all lines, newlines preserved) in `process.io.text`. See [Event format](README.md#event-format) for the full document.

**Example** (command `tag` `system-check`, output of two lines):
```json
{
  "event": {"module": "wazuh-wodle-cmd", "start": "2026-05-11T12:00:00Z"},
  "tags": ["system-check"],
  "process": {
    "name": "check.sh",
    "exit_code": 0,
    "io": {"text": "Disk usage: 75%\nMemory available: 2.5GB\n"}
  }
}
```
(Other `process.*` fields omitted for brevity.)

**Processing:**
- Each execution generates one event; multi-line output stays in a single `process.io.text` value. Output that does not fit in a single message (64 KB) is sent in several events split on line boundaries (see `wazuh_command.split_output`)
- Events carry the configured `tag` in the `tags` array
- Manager rules can parse and alert on the event
- If the command details alone fill the message, an event without output is sent (empty `process.io.text`)
- With `ignore_output` set to `yes`, no event is sent

---

## Script Execution Environment

### Working Directory

Commands execute in the agent's working directory:
- Linux/Unix: `/var/ossec/`
- Windows: `C:\Program Files (x86)\ossec-agent\`

### User Privileges

Commands run with the privileges of `wazuh-modulesd`:
- Linux/Unix: `root`, with group `wazuh`
- Windows: the account of the agent service (SYSTEM by default)

### Environment Variables

The command inherits the environment of `wazuh-modulesd`, with standard input from `/dev/null` on Linux/Unix. Set
custom variables in wrapper scripts if needed.

### Output Handling

- **Standard output and standard error:** captured together and forwarded to the manager in `process.io.text`
  (unless `ignore_output=yes`)
- **Exit codes:** reported in `process.exit_code`; a non-zero code is also logged as a warning,
  `Command '<tag>' returned exit code <N>.`

---

## Security Considerations

### Script Integrity

Always use hash verification for production scripts:

```bash
# Generate SHA256 hash
sha256sum /usr/local/bin/script.sh
```

Then add to configuration:
```xml
<verify_sha256>abc123...</verify_sha256>
```

### File Permissions

Ensure scripts have appropriate permissions:

```bash
# Set ownership to root (or wazuh user)
chown root:root /usr/local/bin/script.sh

# Set permissions (readable and executable by owner only)
chmod 700 /usr/local/bin/script.sh
```

### Input Validation

If your script accepts parameters:
- Validate all inputs to prevent injection attacks
- Avoid passing user-controlled data directly to shell commands
- Use absolute paths for all external commands

### Command Injection Prevention

**Vulnerable example:**
```bash
# DON'T DO THIS
eval "$USER_INPUT"
```

**Secure example:**
```bash
# Use parameterized commands
/usr/bin/command --option="$VALIDATED_INPUT"
```

### Best Practices

- Use absolute paths for commands and scripts
- Implement proper error handling
- Log all script actions for audit trails
- Test scripts in staging before production deployment
- Regularly review and update script permissions
- Monitor command execution logs for anomalies

---

## Performance Considerations

### Execution Frequency

**High-frequency (< 1 minute):**
- Suitable for critical service monitoring
- Ensure scripts execute quickly (< 5 seconds)
- Monitor resource consumption

**Medium-frequency (1-30 minutes):**
- Balanced for most use cases
- Allows more complex script logic

**Low-frequency (hourly/daily):**
- Suitable for resource-intensive operations
- Ideal for reporting and compliance checks

### Timeout Settings

Match timeouts to expected execution time:

**Quick checks (< 30 seconds):**
```xml
<timeout>30</timeout>
```

**Complex operations (1-5 minutes):**
```xml
<timeout>300</timeout>
```

**Long-running tasks (> 5 minutes):**
```xml
<timeout>600</timeout>
```

### Resource Usage

Monitor resource consumption when running multiple command wodles:

```bash
# View running command processes
ps aux | grep -E 'wodle|command'

# Monitor CPU/memory usage
top -p $(pgrep -d',' wazuh-modulesd)
```

---

## Troubleshooting

### Command Not Executing

**Check configuration:**
```bash
grep -A10 "wodle name=\"command\"" /var/ossec/etc/ossec.conf
```

**Check module logs:**
```bash
tail -f /var/ossec/logs/ossec.log | grep command
```

**Verify script is executable:**
```bash
ls -l /usr/local/bin/script.sh
test -x /usr/local/bin/script.sh && echo "Executable" || echo "Not executable"
```

**Check wodle is enabled:**
```bash
# Verify disabled is set to 'no'
grep -A2 "wodle name=\"command\"" /var/ossec/etc/ossec.conf | grep disabled
```

### Hash Verification Failures

**Recalculate hash:**
```bash
sha256sum /usr/local/bin/script.sh
```

**Compare with expected hash:**
```bash
# Compare calculated hash with configuration
echo "EXPECTED_HASH /usr/local/bin/script.sh" | sha256sum -c
```

**Check for script modifications:**
```bash
# View recent file changes
stat /usr/local/bin/script.sh
```

### Command Timeouts

**Increase timeout:**
```xml
<timeout>300</timeout>  <!-- 5 minutes -->
```

**Measure actual execution time:**
```bash
time /usr/local/bin/script.sh
```

**Optimize script performance:**
- Remove unnecessary operations
- Use efficient algorithms
- Cache expensive computations

### Output Not Appearing

**Verify ignore_output setting:**
```xml
<ignore_output>no</ignore_output>
```

**Test command output locally:**
```bash
/usr/local/bin/script.sh
```

**Check manager logs:**
```bash
# On manager, search for command tag
# (requires a policy with a `file` output; see ../engine/ref-output.md)
tail -f /var/wazuh-manager/logs/<channel>/$(date +%Y/%b)/wazuh-<channel>-$(date +%d).json | grep "command-tag"
```

### Permission Errors

**Check script permissions:**
```bash
ls -l /usr/local/bin/script.sh
```

**Check SELinux context (if applicable):**
```bash
ls -Z /usr/local/bin/script.sh
```

**Fix permissions:**
```bash
chmod 750 /usr/local/bin/script.sh
chown root:wazuh /usr/local/bin/script.sh
```

---

## Monitoring

### View Command Execution Logs

```bash
# View all command wodle activity
tail -f /var/ossec/logs/ossec.log | grep "wazuh-modulesd:command"

# View specific command tag
tail -f /var/ossec/logs/ossec.log | grep "system-check"
```

### View Command Output

The agent does not log the output, except at debug level 2 (`wazuh_modules.debug=2`) for a command that returned a
non-zero exit code (`OUTPUT: ...`).

```bash
# On manager (in alerts)
# (requires a policy with a `file` output; see ../engine/ref-output.md)
tail -f /var/wazuh-manager/logs/<channel>/$(date +%Y/%b)/wazuh-<channel>-$(date +%d).json | grep "command-tag"
```

### Monitor Execution Frequency

```bash
# Count executions of a specific command
grep "Starting command 'system-check'" /var/ossec/logs/ossec.log | wc -l

# View last execution time
grep "Starting command 'system-check'" /var/ossec/logs/ossec.log | tail -1
```

### Check for Errors

```bash
# Search for command errors
grep -i "error\|fail" /var/ossec/logs/ossec.log | grep command

# View timeout events
grep "timeout" /var/ossec/logs/ossec.log | grep command
```

---

## Advanced Configuration

### Conditional Execution

Use wrapper scripts for conditional execution:

```bash
#!/bin/bash
# Only run during business hours (9 AM - 5 PM)
hour=$(date +%H)
if [ $hour -ge 9 ] && [ $hour -lt 17 ]; then
    /usr/local/bin/actual-check.sh
fi
```

### Parametric Commands

Pass parameters through environment variables:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>parametric-check</tag>
  <command>/usr/local/bin/wrapper.sh</command>
  <interval>10m</interval>
</wodle>
```

Wrapper script:
```bash
#!/bin/bash
export CHECK_THRESHOLD=80
export CHECK_TYPE=disk
/usr/local/bin/actual-check.sh
```

### Debug Mode

Enable detailed logging:

```ini
# local_internal_options.conf
wazuh_modules.debug=2
```

Restart the agent to apply it.

View debug logs:
```bash
tail -f /var/ossec/logs/ossec.log | grep "wazuh-modulesd:command"
```

---

## See Also

- [Command Module](README.md) - Module overview and use cases
- [Log Collector Configuration](../logcollector/configuration.md) - Alternative: use `<localfile>` with `log_format=command` for simple command output
- [Centralized Configuration](../agent-management/centralized-configuration.md) - Deploy command wodles via centralized configuration
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
