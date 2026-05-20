# Command Module

## Introduction

The Wazuh command module executes configured operating system commands at scheduled intervals and can forward their output for analysis. It runs inside `wazuh-modulesd` as the `<wodle name="command">` module.

Use this module for periodic command-based telemetry when a native collector is not available. The module executes the configured command locally on the agent where the configuration is applied.

## How it works

For each configured command wodle, `wazuh-modulesd`:

1. Reads the `<wodle name="command">` configuration from `ossec.conf` or `agent.conf`.
2. Builds the command schedule from `interval`, `day`, `wday`, and `time`.
3. Optionally validates the executable checksum before execution.
4. Executes the command with the configured timeout.
5. Sends a structured event to the local queue when `ignore_output` is set to `no`.

The command module uses the routing tag `command` for the generated events. The configured `tag` value is stored inside the event payload.

## Configuration

Configure the module inside the `<ossec_config>` block:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>periodic-whoami</tag>
  <command>/usr/bin/whoami</command>
  <interval>2m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>30</timeout>
</wodle>
```

Windows example with checksum verification:

```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>periodic-whoami</tag>
  <command>C:\\Windows\\System32\\whoami.exe</command>
  <interval>2m</interval>
  <ignore_output>no</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>30</timeout>
  <verify_sha1>9746e91bfc629d3a2e1fe6289b549c0452702004</verify_sha1>
</wodle>
```

### Configuration options

| Option | Required | Default | Description |
|--------|:--------:|---------|-------------|
| `disabled` | No | `no` | Disables this command when set to `yes`. |
| `tag` | No | Empty | Custom tag included in the generated event. It is also used in module log messages. |
| `command` | Yes | Not set | Command line to execute. The first token is treated as the executable for checksum verification and process metadata. |
| `interval` | No | `2s` | Time interval between executions. Supports `s`, `m`, `h`, `d`, `w`, and `M` suffixes. |
| `day` | No | Not set | Day of the month for scheduled execution. Cannot be combined with `wday`. |
| `wday` | No | Not set | Day of the week for scheduled execution. Cannot be combined with `day`. |
| `time` | No | Not set | Time of day for scheduled execution, in `HH:MM` format. |
| `ignore_output` | No | `no` | Executes the command without sending the command output event when set to `yes`. |
| `run_on_start` | No | `yes` | Executes the command immediately when the module starts. |
| `timeout` | No | `0` | Maximum command execution time in seconds. A value of `0` disables the timeout. |
| `verify_md5` | No | Not set | Expected MD5 hash of the executable. Must be 32 characters. |
| `verify_sha1` | No | Not set | Expected SHA1 hash of the executable. Must be 40 characters. |
| `verify_sha256` | No | Not set | Expected SHA256 hash of the executable. Must be 64 characters. |
| `skip_verification` | No | `no` | Logs checksum verification failures as warnings and continues execution when set to `yes`. |

### Scheduling

The command module uses the shared Wazuh module scheduler:

- `interval` executes the command periodically.
- `time` executes the command at a specific time of day and requires an interval that is a multiple of one day.
- `wday` executes the command on a specific weekday and requires an interval that is a multiple of one week.
- `day` executes the command on a specific day of the month and requires a month interval.

When `run_on_start` is `yes`, the first execution happens immediately. When it is `no`, the first execution waits for the next scheduled time.

## Centralized configuration

The command module can be configured through `agent.conf`, but remote commands are disabled by default. If a command wodle comes from centralized configuration, the agent only runs it when the `wazuh_command.remote_commands` internal option is enabled.

If remote commands are disabled, the agent logs the command as ignored and exits that module instance.

## Checksum verification

Checksum verification applies to the executable resolved from the first token of `command`. Command arguments are preserved for execution, but they are not part of the hash calculation.

When any of `verify_md5`, `verify_sha1`, or `verify_sha256` is configured, the module:

1. Splits the command line to identify the executable.
2. Resolves the executable path.
3. Validates each configured checksum.
4. Builds the full command line using the resolved executable path and the original arguments.
5. Revalidates the checksum before each scheduled execution unless `skip_verification` is set to `yes`.

On Windows, the module disables WOW64 file system redirection while resolving and validating the executable.

If verification fails, the command is not executed. When `skip_verification` is set to `yes`, the module logs a warning and continues.

## Event format

When `ignore_output` is `no`, the command module sends a JSON event with command metadata and output:

```json
{
  "event": {
    "module": "wazuh-wodle-cmd",
    "start": "2026-05-11T12:00:00Z"
  },
  "tags": ["periodic-whoami"],
  "process": {
    "args": [],
    "name": "whoami",
    "path": "/usr/bin/whoami",
    "command_line": "/usr/bin/whoami",
    "hash": {
      "sha1": "9746e91bfc629d3a2e1fe6289b549c0452702004"
    },
    "exit_code": 0,
    "io": {
      "text": "wazuh\n"
    }
  }
}
```

### Event fields

| Field | Description |
|-------|-------------|
| `event.module` | Static module identifier: `wazuh-wodle-cmd`. |
| `event.start` | UTC timestamp captured before command execution. |
| `tags` | Array containing the configured command `tag`. If `tag` is omitted, the value is an empty string. |
| `process.args` | Command arguments, excluding the executable. |
| `process.name` | Executable name. |
| `process.path` | Resolved executable path when available. |
| `process.command_line` | Full command line used for execution. |
| `process.hash` | Configured verification hashes. Present only when checksum verification is configured. |
| `process.exit_code` | Command exit code. Timeout and execution failures use `-1`. |
| `process.io.text` | Captured command output. |

If the output is too large for a single queue message, the module attempts to truncate `process.io.text`. If the event still does not fit, it sends a metadata-only event with an empty output field.

## Troubleshooting

Check the module logs:

```bash
grep "wazuh-modulesd:command" /var/ossec/logs/ossec.log
```

Common messages:

| Message | Meaning |
|---------|---------|
| `Remote commands are disabled. Ignoring '<tag>'.` | The command came from centralized configuration, but remote commands are disabled. |
| `Cannot check binary: '<binary>'. Cannot stat binary file.` | The executable could not be resolved for checksum verification. |
| `SHA1 checksum verification failed for command '<command>'.` | The executable hash did not match the configured `verify_sha1` value. |
| `Timeout overtaken.` | The command exceeded the configured `timeout`. |
| `Command output is too long to fit in a single message.` | The output was truncated or dropped to keep the event within queue limits. |
