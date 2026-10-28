# Creating custom SCA policies

When creating custom SCA policy files, you need to consider the following four sections, although not all of them are required.

## Policy file sections

| Section       | Required |
|--------------|----------|
| policy       | Yes      |
| requirements | No       |
| variables    | No       |
| checks       | Yes      |

---

## SCA policy example

```yaml
# Security Configuration Assessment
# Audit for UNIX systems
# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation

policy:
  id: "unix_audit"
  file: "sca_unix_audit.yml"
  name: "System audit for Unix based systems"
  description: "Guidance for establishing a secure configuration for Unix based systems."
  references:
    - https://www.ssh.com/ssh/

requirements:
  name: "Check that the SSH service and password-related files are present on the system"
  description: "Requirements for running the SCA scan against the Unix based systems policy."
  condition: any
  rules:
    - 'f:$sshd_file'
    - 'f:/etc/passwd'
    - 'f:/etc/shadow'

variables:
  $sshd_file: /etc/ssh/sshd_config
  $pam_d_files: /etc/pam.d/common-password,/etc/pam.d/password-auth,/etc/pam.d/system-auth,/etc/pam.d/system-auth-ac,/etc/pam.d/passwd

checks:
  - id: 3000
    name: "SSH Hardening: Port should not be 22"
    description: "The ssh daemon should not be listening on port 22 (the default value) for incoming connections."
    rationale: "Changing the default port you may reduce the number of successful attacks from zombie bots."
    remediation: "Change the Port option value in the sshd_config file."
    compliance:
      pci_dss: ["2.2.4"]
      nist_800_53: ["CM.1"]
    mitre:
      tactic:
        id:
          - "TA0008"
        name:
          - "Lateral Movement"
      technique:
        id:
          - "T1021"
        name:
          - "Remote Services"
    condition: all
    rules:
      - 'f:$sshd_file -> !r:^# && r:Port && !r:\s*\t*22$'

  - id: 3001
    name: "SSH Hardening: Protocol should be set to 2"
```

> **Note**  
> If the `requirements` are not satisfied for a specific policy file, the scan for that file will not start.

---

## Policy section

| Field        | Mandatory | Type             | Allowed values               | Description         |
|-------------|-----------|------------------|------------------------------|---------------------|
| id          | Yes       | String           | Any string                   | Policy ID           |
| file        | Yes       | String           | Any string                   | Policy filename     |
| name        | Yes       | String           | Any string                   | Policy name         |
| description | Yes       | String           | Any string                   | Brief description   |
| references  | No        | Array of strings | Any string                   | Reference links     |

---

## Requirements section

| Field       | Mandatory | Type             | Allowed values |
|------------|-----------|------------------|----------------|
| name       | Yes       | String           | Any string     |
| description| Yes       | String           | Any string     |
| condition  | Yes       | String           | Any string     |
| rules      | Yes       | Array of strings | Any string     |

---

## Variables section

| Field         | Mandatory | Type             | Allowed values |
|--------------|-----------|------------------|----------------|
| variable_name| Yes       | Array of strings | Any string     |

> **Note**  
> The `id` field under `policy` and `checks` must be unique across policy files.

---

## Variables

Variables are defined in the `variables` section and are prefixed with `$`.

Examples:

- `$list_of_files`: `/etc/ssh/sshd_config`, `/etc/sysctl.conf`, `/var/log/dmesg`
- `$list_of_folders`: `/etc`, `/var`, `/tmp`
- `$program_name`: `apache2`

Example rules using variables:

```yaml
f:$list_of_files -> r:^Content to be found
c:systemctl is-enabled $program_name -> r:^enabled
```

There is no limit on the number of variables per rule.

---

## Checks

Checks define what actions the agent performs and how results are evaluated.

### Checks section

| Field        | Mandatory | Type                      | Allowed values        |
|-------------|-----------|---------------------------|-----------------------|
| id          | Yes       | Numeric                   | Any integer           |
| name        | Yes       | String                    | Any string            |
| description | No        | String                    | Any string            |
| rationale   | No        | String                    | Any string            |
| remediation | No        | String                    | Any string            |
| compliance  | No        | Object                    | See [Compliance keys](#compliance-keys) |
| mitre       | No        | Object                    | See [MITRE keys](#mitre-keys) |
| references  | No        | Array of strings          | Any string            |
| condition   | Yes       | String                    | all, any, none        |
| rules       | Yes       | Array of strings          | Any string            |

SCA rules are evaluated with PCRE2. Custom policies migrated from 4.x must not rely on OSRegex syntax. See [SCA policies from 4.x to 5.x](../../../guide/migration/sca-policies-4x-to-5x.md) for migration guidance.

#### Compliance keys

The `compliance` field is an object that maps compliance framework keys to arrays of identifier strings. Only the following keys are allowed:

`cmmc`, `fedramp`, `gdpr`, `hipaa`, `iso_27001`, `nis2`, `nist_800_171`, `nist_800_53`, `pci_dss`, `tsc`

Unknown keys are rejected with a warning and excluded from the check.

#### MITRE keys

The `mitre` field is an object that maps MITRE ATT&CK categories to their identifiers and names. The following keys are supported:

`tactic`, `technique`, `subtechnique`

Each key is an object with two parallel arrays:

| Subkey | Type             | Description                          |
|--------|------------------|--------------------------------------|
| id     | Array of strings | MITRE ATT&CK identifiers (e.g. `TA0008`, `T1021`) |
| name   | Array of strings | Human-readable names matching each identifier in order (e.g. `Lateral Movement`, `Remote Services`) |

The `id` and `name` arrays must have the same length, with each name corresponding to the identifier at the same position. Names are taken from the MITRE ATT&CK catalog (https://attack.mitre.org/).

```yaml
mitre:
  tactic:
    id:
      - "TA0008"
    name:
      - "Lateral Movement"
  technique:
    id:
      - "T1021"
    name:
      - "Remote Services"
```

---

## Condition

Conditions define how rule results are aggregated:

- `all`: Pass if all rules pass
- `any`: Pass if at least one rule passes
- `none`: Pass if no rule passes

### Condition evaluation table

| Condition | Passed | Failed | Not applicable | Result           |
|----------|--------|--------|----------------|------------------|
| all      | yes    | no     | no             | Passed           |
| all      | *      | no     | yes            | Not applicable   |
| all      | *      | yes    | *              | Failed           |
| any      | yes    | *      | *              | Passed           |
| any      | no     | yes    | no             | Failed           |
| any      | no     | *      | yes            | Not applicable   |
| none     | yes    | *      | *              | Failed           |
| none     | no     | *      | yes            | Not applicable   |
| none     | no     | yes    | no             | Passed           |

`*` does not affect the final result.

---

## Rules

Rules define existence or content checks.

### Rule types

| Type      | Character |
|----------|-----------|
| File     | `f`       |
| Directory| `d`       |
| Process  | `p`       |
| Command  | `c`       |
| Registry | `r`       |

---

## Existence checking rules

```yaml
RULE_TYPE:target
```

Examples:

- `f:/etc/sshd_config`
- `d:/etc`
- `not p:sshd`
- `r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`

---

## Content checking rules

```yaml
RULE_TYPE:target -> OPERATOR:value
```

Examples:

```yaml
f:/etc/ssh_config -> !r:PermitRootLogin
f:/etc/ssh_config -> !r:^# && r:Protocol && r:2
c:systemctl is-enabled cups -> r:^enabled
```

> **Notes**
> - Content checks operate at line level
> - Spaces around `->`, `&&`, and `compare` are mandatory

---

## Patterns

The value after `->`, and the value of a process rule, is either a plain value or a pattern.

| Form | Passes when |
|------|-------------|
| `r:REGEX` | `REGEX` matches |
| `!r:REGEX` | `REGEX` does not match |
| `n:REGEX compare OPERATOR NUMBER` | the number captured by `REGEX` satisfies the comparison |
| `!n:REGEX compare OPERATOR NUMBER` | the comparison is not satisfied |
| `TERM && TERM ...` | every term holds (see below) |
| Any other value | plain value, compared as described below |

- **Engine:** every regular expression is PCRE2. The `regex_type` field of policies and checks is ignored.
- **Case:** regular expressions in `r:` and `n:` terms are case-insensitive, so `r:permitrootlogin` matches
  `PermitRootLogin`. Start the expression with `(?-i)` to make it case-sensitive: `r:(?-i)^PermitRootLogin`.
- **Lines:** the content is split into lines, and a pattern passes when one line satisfies every term. In
  `f:/etc/ssh/sshd_config -> !r:^# && r:Port\s+22`, the same line must not be a comment and must set the port.
  A single negated term is the exception: `!r:REGEX` on its own passes only when no line matches.
- **Numbers:** `n:` takes the first capture group of `REGEX` (the whole match if it has no group) as an integer.
  `OPERATOR` is one of `<`, `<=`, `==`, `!=`, `>=` or `>`.
- **Plain values** are compared whole, never as a substring:
  - files: a line equal to the value, case-sensitive (`f:/proc/sys/net/ipv4/ip_forward -> 1`);
  - commands: the whole output, standard output or standard error, without its trailing newlines;
  - processes: a process name equal to the value, case-insensitive.
- **Commands:** patterns are matched against standard output and standard error separately. A match in
  either counts.
- **Errors:** a regular expression that does not compile, or an `n:` term without `compare`, makes the rule
  invalid. The check is reported as `Not applicable` with the reason, and an error is logged.

Examples:

```yaml
f:/etc/ssh/sshd_config -> r:^\s*PermitRootLogin\s+no
f:/etc/ssh/sshd_config -> !r:^\s*PermitEmptyPasswords\s+yes
f:/etc/login.defs -> n:^PASS_MAX_DAYS\s+(\d+) compare <= 365
c:sysctl net.ipv4.ip_forward -> r:=\s*0$
c:stat -L /etc/passwd -> r:(?-i)Access:\s*\(0644
```

---

## Rule examples by type

### Files

- `f:/path/to/file`
- `f:/path/to/file -> r:REGEX`
- `f:/path/to/file -> n:REGEX(\d+) compare <= 4`

### Directories

- `d:/path/to/directory`
- `d:/path/to/directory -> file_name`

### Processes

- `p:process_name`
- `not p:process_name`
- `p:r:REGEX`
- `p:r:REGEX && !r:REGEX`

A process rule matches when any running process has a name that matches the value. The names
checked are the process name, its executable path or argv[0], and, on Linux, the kernel task name
(`/proc/<pid>/comm`). The kernel task name lets `p:nginx` match a process that rewrites its argv[0]
(`nginx: master process ...`) and `p:firewalld` match a script run through its interpreter
(`/usr/bin/python3 -s /usr/sbin/firewalld`). The kernel truncates it to 15 characters.

A plain value is compared case-insensitively. A value starting with `r:`, `n:`, `!r:` or `!n:`, or joining
terms with `&&`, is matched as a pattern (see [Patterns](#patterns)) against each name, and every term must
hold on the same name. On Linux the names do not include the process arguments. A process rule takes no
content pattern: `p:process_name -> r:REGEX` is reported as invalid.

To require that a process is not running, negate the rule (`not p:...`). A negated term such as
`p:!r:REGEX` passes as soon as any process has a name that does not match, which is almost always.

Examples, with nginx running (master and workers) and firewalld running through `/usr/bin/python3`:

| Rule | Result | Why |
|------|--------|-----|
| `p:nginx` | Passed | kernel task name `nginx` |
| `p:NGINX` | Passed | plain values ignore case |
| `p:firewalld` | Passed | kernel task name of the script |
| `p:r:^nginx$` | Passed | kernel task name |
| `p:r:^nginx: master process` | Passed | argv[0] of the master |
| `p:r:(?-i)NGINX` | Failed | case-sensitive expression |
| `p:r:nginx && !r:worker` | Passed | the master's names do not contain `worker` |
| `p:r:^nginx$ && r:master` | Failed | no single name satisfies both terms |
| `p:n:^python(\d+)$ compare >= 3` | Passed | process name `python3` |
| `p:r:/usr/sbin/firewalld` | Failed | on Linux the script path is an argument, not a name |
| `not p:r:^telnetd$` | Passed | no such process |
| `p:nginx -> r:master` | Not applicable | process rules take no content pattern |

### Commands

- `c:command -> r:REGEX`
- `c:command -> n:REGEX(\d+) compare >= number`

### Registry (Windows)

- `r:path/to/key`
- `r:path/to/key -> value -> content`

---

## Composite rules

- `f:/etc/ssh/sshd_config -> !r:^# && r:Port\s+22`
- `not f:/etc/ssh/sshd_config -> !r:^# && r:Port\s+22`

---

## Additional examples

- `f:/proc/sys/net/ipv4/ip_forward -> 1`
- `p:avahi-daemon`
- `d:/etc/mysql`
- `c:sshd -T -> !r:^\s*maxauthtries\s+4\s*$`
- `f:/etc/passwd -> !r:^# && !r:^root: && r:^[\w@-]+:[\w@-]+:0:`
