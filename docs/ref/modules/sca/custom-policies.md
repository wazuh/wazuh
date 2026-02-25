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
# Copyright (C) 2015, Wazuh Inc.
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
  title: "Check that the SSH service and password-related files are present on the system"
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
    title: "SSH Hardening: Port should not be 22"
    description: "The ssh daemon should not be listening on port 22 (the default value) for incoming connections."
    rationale: "Changing the default port you may reduce the number of successful attacks from zombie bots."
    remediation: "Change the Port option value in the sshd_config file."
    compliance:
      - pci_dss: ["2.2.4"]
      - nist_800_53: ["CM.1"]
    condition: all
    rules:
      - 'f:$sshd_file -> !r:^# && r:Port && !r:\s*\t*22$'

  - id: 3001
    title: "SSH Hardening: Protocol should be set to 2"
```

> **Note**  
> If the `requirements` are not satisfied for a specific policy file, the scan for that file will not start.

---

## Policy section

| Field        | Mandatory | Type             | Allowed values               | Description         |
|-------------|-----------|------------------|------------------------------|---------------------|
| id          | Yes       | String           | Any string                   | Policy ID           |
| file        | Yes       | String           | Any string                   | Policy filename     |
| name        | Yes       | String           | Any string                   | Policy title        |
| description | Yes       | String           | Any string                   | Brief description   |
| references  | No        | Array of strings | Any string                   | Reference links     |
| regex_type  | No        | String           | osregex, pcre2               | Regex engine        |

---

## Requirements section

| Field       | Mandatory | Type             | Allowed values |
|------------|-----------|------------------|----------------|
| title      | Yes       | String           | Any string     |
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
| title       | Yes       | String                    | Any string            |
| description | No        | String                    | Any string            |
| rationale   | No        | String                    | Any string            |
| remediation | No        | String                    | Any string            |
| compliance  | No        | Array of arrays of string | Any string            |
| references  | No        | Array of strings          | Any string            |
| condition   | Yes       | String                    | all, any, none        |
| rules       | Yes       | Array of strings          | Any string            |
| regex_type  | No        | String                    | pcre2, osregex        |

> **Note**  
> A `regex_type` defined at the check level overrides the policy-level regex engine.

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

### Commands

- `c:command -> r:REGEX`
- `c:command -> n:REGEX(\d+) compare >= number`

### Registry (Windows)

- `r:path/to/key`
- `r:path/to/key -> value -> content`

---

## Composite rules

- `f:/etc/ssh/sshd_config -> !r:^# && r:Port\.+22`
- `not f:/etc/ssh/sshd_config -> !r:^# && r:Port\.+22`

---

## Additional examples

- `f:/proc/sys/net/ipv4/ip_forward -> 1`
- `p:avahi-daemon`
- `d:/etc/mysql`
- `c:sshd -T -> !r:^\s*maxauthtries\s+4\s*$`
- `f:/etc/passwd -> !r:^# && !r:^root: && r:^\w+:\w+:0:`
