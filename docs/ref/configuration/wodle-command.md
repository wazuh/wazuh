# Wodle: Command Configuration

The `<wodle name="command">` section runs a configured OS command on a schedule and optionally forwards its output for analysis. Multiple instances can be configured.

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parser: `src/config/src/wmodules-command.c`

For the full module reference (event format, checksum verification, centralized config) see [Command Module](../modules/command/README.md).

## Configuration Options

### disabled

Disables this command instance.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### tag

Label included in the generated event. Also used in log messages.

- **Default value**: none
- **Allowed values**: Any string

### command

Command line to execute. The first token is used as the executable for checksum verification.

- **Required**: yes
- **Allowed values**: Any valid command string

### interval

Time between executions.

- **Default value**: `2s`
- **Allowed values**: Positive number followed by a suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `M` (months)

### day

Day of the month for scheduled execution. If the configured interval is not a month-based value, the scheduler normalizes it to `1M` with a warning. Cannot be combined with `wday`.

- **Default value**: none
- **Allowed values**: Integer from `1` to `31`

### wday

Day of the week for scheduled execution. If the configured interval is not a weekly multiple, the scheduler normalizes it to `1w` with a warning. Cannot be combined with `day`.

- **Default value**: none
- **Allowed values**: `sunday`, `monday`, `tuesday`, `wednesday`, `thursday`, `friday`, `saturday`

### time

Time of day for scheduled execution, in `HH:MM` format.

- **Default value**: none
- **Allowed values**: `HH:MM`

### ignore_output

Execute the command without forwarding its output.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### run_on_start

Execute the command immediately when the module starts, before waiting for the first scheduled time.

- **Default value**: `yes`
- **Allowed values**: `yes`, `no`

### timeout

Maximum command execution time in seconds. `0` disables the timeout.

- **Default value**: `0`
- **Allowed values**: Non-negative integer

### verify_md5

Expected MD5 hash of the executable. Execution is blocked if the hash does not match.

- **Default value**: none
- **Allowed values**: String of exactly 32 characters (length validated by the parser; hex content is not validated at parse time and an invalid hash will cause a runtime verification failure)

### verify_sha1

Expected SHA1 hash of the executable. Execution is blocked if the hash does not match.

- **Default value**: none
- **Allowed values**: String of exactly 40 characters (length validated by the parser)

### verify_sha256

Expected SHA256 hash of the executable. Execution is blocked if the hash does not match.

- **Default value**: none
- **Allowed values**: String of exactly 64 characters (length validated by the parser)

### skip_verification

Log checksum verification failures as warnings and continue execution instead of blocking.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

## Configuration Example

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>system-check</tag>
  <command>/usr/local/bin/check.sh</command>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  <ignore_output>no</ignore_output>
  <timeout>30</timeout>
</wodle>
```

With checksum verification:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>system-check</tag>
  <command>/usr/local/bin/check.sh</command>
  <interval>1d</interval>
  <time>02:00</time>
  <verify_sha256>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</verify_sha256>
  <skip_verification>no</skip_verification>
</wodle>
```
