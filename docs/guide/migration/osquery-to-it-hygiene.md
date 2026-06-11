# Migrating from OSquery to IT Hygiene

In Wazuh 4.x, the **OSquery wodle** managed the **OSquery daemon** (`osqueryd`)
from the agent. OSquery is an open-source tool that had to be installed
separately on each endpoint; it exposes the operating system as a relational
database and lets you write SQL queries against OS tables (`users`, `processes`,
`services`, etc.).

The wodle could start `osqueryd` as a child process or attach to an already
running instance. It read the results log written by the daemon and forwarded
each result to the Wazuh manager, where the output was processed by the
**rules engine**. Wazuh ships a dedicated ruleset for OSquery (rule group
`osquery`), and you could write additional custom rules that match on specific
query names or column values to generate targeted alerts.

All OSquery-originated events landed in `wazuh-alerts-*` (or in the archives
if they did not trigger any rule). Each event carried the following fields:

- `data.osquery.name` — the scheduled query or pack query name
- `data.osquery.action` — `added` or `removed` (differential mode)
- `data.osquery.hostIdentifier` — the hostname reported by OSquery
- `data.osquery.columns.*` — one key per column returned by the SQL query
- `location` — always `osquery`

Users defined their queries in an `osquery.conf` schedule or in pack files,
and then used Wazuh rules and dashboards to act on the resulting alerts.

Starting with Wazuh 4.14, the **Syscollector** module (IT Hygiene) was
progressively extended to cover the same data OSquery provided — natively,
without requiring an external binary. Users, Groups, Services, and Browser
Extensions were all added to Syscollector during the 4.14 release cycle.

Starting with Wazuh 5.0, the OSquery wodle has been fully removed. If you are
still running the OSquery wodle in 4.x and have not yet migrated to
Syscollector, this guide will help you make that transition.

> **Note:** There is no automated migration tooling. You must map your existing
> OSquery queries to the equivalent Syscollector inventory category, then update
> any dashboards, alerts, or integrations that relied on OSquery output.

## Why the change

A technical feasibility evaluation concluded that embedding the OSquery library
as a runtime dependency was not viable across all supported platforms. Instead,
Wazuh replicated the OSquery state tables most relevant to enterprise security
and IT hygiene natively inside `syscollector`, normalizing field names to the
Wazuh Common Schema (WCS) and Elastic Common Schema (ECS) conventions used
across the rest of the platform.

## OSquery table coverage

The table below maps the most commonly used OSquery state tables to the
Syscollector inventory category that covers the same data. The "Since" column
indicates the Wazuh version in which that category was introduced.

| IT Hygiene category | OSquery source tables | Since | Platform notes |
|---|---|---|---|
| **Processes** | `processes` | &lt; 4.14 | All platforms. Collection backend differs: procps (Linux), Win32 API (Windows), libproc/`proc_pidinfo` (macOS). |
| **Packages** | `packages`, `programs`, `rpm_packages`, `deb_packages`, `pip_packages`, `npm_packages` | &lt; 4.14 | All platforms. Extended in 4.14 with PYPI and NPM discovery. |
| **OS** | `os_version`, `kernel_info` | &lt; 4.14 | All platforms. |
| **Hardware** | `system_info`, `cpu_info`, `memory_info` | &lt; 4.14 | All platforms. |
| **Network** | `interface_addresses`, `interface_details` | &lt; 4.14 | All platforms. |
| **Ports** | `listening_ports` | &lt; 4.14 | All platforms. |
| **Users** | `users`, `logged_in_users`, `user_groups` | 4.14 | All platforms (one document per user consolidates all sources). Linux also adds `shadow` (password policy) and `sudoers`. macOS also adds `sudoers`; password metadata and `is_hidden`/`created`/auth-failure fields come from Directory Services via `users`. Windows does not have `shadow` or `sudoers`; adds `user_type` (account type) and `uuid` (SID). |
| **Groups** | `groups`, `user_groups` | 4.14 | All platforms. `user_groups` is resolved to a `group.users` member list (not a separate document). Linux: no `description` or `uuid` (not available in `/etc/group`). Windows: adds `description` and `uuid` (Windows SID). macOS: adds `description`, `uuid`, and `is_hidden` from Directory Services. |
| **Services** | `systemd_units` (Linux), `services` (Windows), `launchd` (macOS) | 4.14 | Platform-specific source. On Linux the systemd D-Bus API is used; additional fields `enabled`, `following`, `object_path`, and `target.*` have no OSquery equivalent. On macOS the launchd plist reader adds `restart`, `frequency`, `starts_on_*`, and log file paths. |
| **Browser Extensions** | `chrome_extensions`, `firefox_addons` | 4.14 | Chrome/Chromium and Firefox on all platforms. Windows also collects `ie_extensions` (IE/Edge legacy). macOS also collects `safari_extensions` (requires Full Disk Access permission). Safari is not available on Linux or Windows. |
| **Disks & Devices** | `disk_info`, `memory_devices`, `pci_devices`, `usb_devices` | Planned (Tier 3) | |
| **Kernel Modules** | `kernel_modules`, `drivers`, `kernel_extensions` | Planned (Tier 3) | |
| **Firmware** | `platform_info`, `secureboot`, `tpm_info` | Planned (Tier 3) | |
| **WiFi** | `wifi_networks`, `wifi_status`, `wifi_survey` | Planned (Tier 3) | macOS only. |

## Configuration mapping

### Wazuh 4.x OSquery wodle

In Wazuh 4.x, OSquery had to be installed separately on each endpoint. Once
installed, you enabled the wodle by adding a `<wodle name="osquery">` block to
the agent's `ossec.conf`:

```xml
<!-- Wazuh 4.x: ossec.conf (agent) -->
<wodle name="osquery">
    <disabled>no</disabled>
    <run_daemon>yes</run_daemon>
    <bin_path>/usr/bin</bin_path>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>no</add_labels>
    <pack name="custom_pack">/path/to/custom_pack.conf</pack>
</wodle>
```

| Option | Default | Description |
|---|---|---|
| `run_daemon` | `yes` | Run `osqueryd` as a subprocess. Set to `no` to only monitor an existing results log. |
| `bin_path` | (system PATH) | Full path to the folder containing the `osqueryd` executable. |
| `log_path` | `/var/log/osquery/osqueryd.results.log` | Path to the results log written by OSquery. |
| `config_path` | `/etc/osquery/osquery.conf` | Path to the OSquery configuration file. |
| `add_labels` | `yes` | Add the agent labels as OSquery decorators. |
| `pack` | — | Add a query pack. Repeatable. |

Queries and packs were defined in `/etc/osquery/osquery.conf` using the standard
OSquery JSON format. A typical configuration combined inline scheduled queries
with references to OSquery's built-in pack files:

```json
{
    "options": {
        "config_plugin": "filesystem",
        "logger_plugin": "filesystem",
        "utc": "true"
    },
    "schedule": {
        "system_info": {
            "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
            "interval": 3600
        },
        "users_query": {
            "query": "SELECT username, uid, gid, shell, directory FROM users;",
            "interval": 3600
        },
        "chrome_extensions_query": {
            "query": "SELECT name, version, identifier, enabled FROM chrome_extensions;",
            "interval": 3600
        },
        "services_query": {
            "query": "SELECT name, display_name, status, start_type FROM services;",
            "interval": 3600
        }
    },
    "packs": {
        "osquery-monitoring": "/opt/osquery/share/osquery/packs/osquery-monitoring.conf",
        "incident-response": "/opt/osquery/share/osquery/packs/incident-response.conf",
        "hardware-monitoring": "/opt/osquery/share/osquery/packs/hardware-monitoring.conf"
    }
}
```

OSquery results reached the Wazuh manager as **alerts**. Each alert stored all OSquery fields nested under `data.osquery`,
with query results under `data.osquery.columns.*` and metadata fields
`data.osquery.name` (query name), `data.osquery.action` (`added`/`removed`),
`data.osquery.hostIdentifier`, `data.osquery.calendarTime`, and
`data.osquery.counter`:

```json
{
  "_index": "wazuh-alerts-4.x-2026.06.03",
  "_id": "LUAtjp4BCf0Lqs7QkDzK",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "10.0.2.15",
      "name": "vm-ubuntu2204",
      "id": "009"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "osquery": {
        "calendarTime": "Wed Jun  3 15:50:02 2026 UTC",
        "hostIdentifier": "vm-ubuntu2204",
        "unixTime": "1780501802",
        "columns": {
          "hostname": "vm-ubuntu2204",
          "cpu_brand": "AMD Ryzen 7 5800X 8-Core Processor",
          "physical_memory": "4114145280"
        },
        "name": "system_info",
        "numerics": "false",
        "action": "added",
        "epoch": "0",
        "counter": "0"
      }
    },
    "rule": {
      "firedtimes": 1,
      "mail": false,
      "level": 3,
      "description": "osquery: system_info query result",
      "groups": [
        "osquery"
      ],
      "id": "24010"
    },
    "location": "osquery",
    "decoder": {
      "name": "json"
    },
    "id": "1780501803.925947",
    "timestamp": "2026-06-03T15:50:03.789+0000"
  },
  "fields": {
    "timestamp": [
      "2026-06-03T15:50:03.789Z"
    ]
  },
  "highlight": {
    "data.osquery.name": [
      "@opensearch-dashboards-highlighted-field@system_info@/opensearch-dashboards-highlighted-field@"
    ],
    "location": [
      "@opensearch-dashboards-highlighted-field@osquery@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1780501803789
  ]
}
```

### Wazuh 5.0 Syscollector (IT Hygiene)

All inventory categories that cover OSquery data are available from Wazuh 4.14
onwards. Enable them in the agent's `ossec.conf`:

> **Note:** All categories shown below are enabled by default in new
> installations. You only need to explicitly set them if they were previously
> disabled in your configuration.

```xml
<!-- ossec.conf (agent) -->
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Available since earlier versions -->
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports>yes</ports>
    <processes>yes</processes>
    <hotfixes>yes</hotfixes> <!-- Windows only -->

    <!-- Added in 4.14 -->
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
</wodle>
```

> **Key difference:** Syscollector is not query-driven. It scans all fields for
> each enabled category on every interval. There is no per-field SQL filter at
> collection time. Use index queries or dashboard filters to slice the data after
> it has been ingested.

## Field mapping examples

The following subsections show how to translate some of the most common OSquery queries
into the equivalent data available through the Wazuh 5.0 IT Hygiene index.

### Processes

**OSquery 4.x** (`data.osquery.columns.*` in `wazuh-alerts-*`, query name `processes_query`):

```sql
SELECT pid, name, path, cmdline, state, ppid, start_time, uid, gid FROM processes;
```

**Wazuh 5.0 index** (`wazuh-states-inventory-processes-*`):

| OSquery field (`data.osquery.columns.*`) | Wazuh 5.0 field | Notes |
|---|---|---|
| `pid` | `process.pid` | |
| `name` | `process.name` | |
| `cmdline` | `process.command_line` | First token of the command line |
| `cmdline` (remaining tokens) | `process.args` | Arguments after the command, space-separated |
| — | `process.args_count` | Count of arguments; no OSquery equivalent |
| `state` | `process.state` | Single character: `S` (sleeping), `R` (running), `Z` (zombie), etc. |
| `ppid` | `process.parent.pid` | Parent process PID |
| `start_time` | `process.start` | OSquery: integer epoch; Wazuh 5.0: ISO 8601 timestamp |
| — | `process.utime` | CPU time in user mode (clock ticks); no direct OSquery equivalent |
| — | `process.stime` | CPU time in kernel mode (clock ticks); no direct OSquery equivalent |
| `path` | — | Binary path not collected separately; use `process.command_line` |
| `uid` | — | Not collected in Wazuh 5.0 |
| `gid` | — | Not collected in Wazuh 5.0 |

**Example alert 4.x:**

```json
{
  "_index": "wazuh-alerts-4.x-2026.06.04",
  "_id": "HIOIk54BLovIbi415BOF",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "10.0.2.15",
      "name": "vm-ubuntu2204-agent",
      "id": "009"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "osquery": {
        "calendarTime": "Thu Jun  4 16:48:00 2026 UTC",
        "hostIdentifier": "vm-ubuntu2204-agent",
        "unixTime": "1780591680",
        "columns": {
          "path": "/usr/sbin/sshd",
          "uid": "1000",
          "cmdline": "sshd: vagrant@pts/0",
          "gid": "1000",
          "name": "sshd",
          "pid": "2929",
          "state": "S"
        },
        "name": "processes_query",
        "numerics": "false",
        "action": "added",
        "epoch": "0",
        "counter": "0"
      }
    },
    "rule": {
      "firedtimes": 451,
      "mail": false,
      "level": 3,
      "description": "osquery: processes_query query result",
      "groups": [
        "osquery"
      ],
      "id": "24010"
    },
    "location": "osquery",
    "decoder": {
      "name": "json"
    },
    "id": "1780591681.2141306",
    "timestamp": "2026-06-04T16:48:01.307+0000"
  },
  "fields": {
    "timestamp": [
      "2026-06-04T16:48:01.307Z"
    ]
  },
  "highlight": {
    "data.osquery.name": [
      "@opensearch-dashboards-highlighted-field@processes_query@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1780591681307
  ]
}
```

**Example event 5.0:**

```json
{
  "_index": "wazuh-states-inventory-processes",
  "_id": "wazuh_015_189af860b2350094e0262ba2d9c3b693a1fefa0b",
  "_score": 0,
  "_source": {
    "wazuh": {
      "agent": {
        "groups": [
          "default"
        ],
        "host": {
          "architecture": "x86_64",
          "hostname": "vm-ubuntu2204-agent",
          "os": {
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "22.04.2 LTS (Jammy Jellyfish)"
          }
        },
        "id": "015",
        "name": "vm-ubuntu2204-agent",
        "version": "v5.0.0"
      },
      "cluster": {
        "name": "wazuh"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "7e97d06480493bf6c23da6a3fb7e0a8ad6b956fe"
      }
    },
    "process": {
      "args": null,
      "args_count": 0,
      "command_line": "sshd: vagrant@pts/0",
      "name": "sshd",
      "parent": {
        "pid": 2876
      },
      "pid": 2929,
      "start": "2026-06-04T12:20:38.000Z",
      "state": "S",
      "stime": 21,
      "utime": 22
    },
    "state": {
      "document_version": 1,
      "modified_at": "2026-06-04T18:34:15.306Z"
    }
  },
  "fields": {
    "state.modified_at": [
      "2026-06-04T18:34:15.306Z"
    ],
    "process.start": [
      "2026-06-04T12:20:38.000Z"
    ]
  }
}
```

### Users

In OSquery 4.x, user-related data was spread across multiple tables. In Wazuh
5.0, the `states-inventory-users-*` index consolidates all of them into a
single document per user.

**OSquery 4.x** — relevant source tables:

```sql
-- Basic user account info (/etc/passwd)
SELECT username, uid, gid, description, shell, directory FROM users;

-- Active login sessions (utmp/wtmp)
SELECT user, tty, type, time, pid, host FROM logged_in_users;

-- Password policy (/etc/shadow, Linux only)
SELECT username, password_status, hash_alg, last_change, min, max,
       warning, inactive, expire FROM shadow;

-- Group memberships
SELECT uid, gid FROM user_groups;

-- Sudo privileges (/etc/sudoers)
SELECT header FROM sudoers;
```

**Wazuh 5.0 index** (`wazuh-states-inventory-users-*`):

| OSquery source table | OSquery field | Wazuh 5.0 field | Notes |
|---|---|---|---|
| `users` | `username` | `user.name` | |
| `users` | `uid` | `user.id` | String in both versions |
| `users` | `gid` | `user.group.id` | |
| `users` | `shell` | `user.shell` | |
| `users` | `directory` | `user.home` | |
| `users` | `description` | `user.full_name` | May be `null` if not set |
| `logged_in_users` | `time` | `user.last_login` | ISO 8601 timestamp of most recent session |
| `logged_in_users` | `tty` | `login.tty` | |
| `logged_in_users` | `type` | `login.type` | |
| `logged_in_users` | `pid` | `process.pid` | PID of the login session |
| `logged_in_users` | `host` | `host.ip` | Remote host if applicable |
| `shadow` | `password_status` | `user.password.status` | Linux only |
| `shadow` | `hash_alg` | `user.password.hash_algorithm` | Linux only |
| `shadow` | `last_change` | `user.password.last_change` | Unix epoch |
| `shadow` | `min` / `max` | `user.password.min_days_between_changes` / `user.password.max_days_between_changes` | |
| `shadow` | `warning` | `user.password.warning_days_before_expiration` | |
| `shadow` | `inactive` | `user.password.inactive_days` | |
| `shadow` | `expire` | `user.password.expiration_date` | ISO 8601 or `null` |
| `user_groups` | (group names) | `user.groups` | Array of group names |
| `sudoers` | (header match) | `user.roles` | `"sudo"` if user appears in sudoers |

**Example alert 4.x:**

```json
{
  "_index": "wazuh-alerts-4.x-2026.06.04",
  "_id": "lIM9k54BLovIbi419hAW",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "10.0.2.15",
      "name": "vm-ubuntu2204-agent",
      "id": "009"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "osquery": {
        "calendarTime": "Thu Jun  4 15:26:05 2026 UTC",
        "hostIdentifier": "vm-ubuntu2204-agent",
        "unixTime": "1780586765",
        "columns": {
          "uid": "1000",
          "gid": "1000",
          "shell": "/bin/bash",
          "directory": "/home/vagrant",
          "username": "vagrant"
        },
        "name": "users_query",
        "numerics": "false",
        "action": "added",
        "epoch": "0",
        "counter": "0"
      }
    },
    "rule": {
      "firedtimes": 33,
      "mail": false,
      "level": 3,
      "description": "osquery: users_query query result",
      "groups": [
        "osquery"
      ],
      "id": "24010"
    },
    "location": "osquery",
    "decoder": {
      "name": "json"
    },
    "id": "1780586766.1471344",
    "timestamp": "2026-06-04T15:26:06.735+0000"
  },
  "fields": {
    "timestamp": [
      "2026-06-04T15:26:06.735Z"
    ]
  },
  "highlight": {
    "data.osquery.name": [
      "@opensearch-dashboards-highlighted-field@users_query@/opensearch-dashboards-highlighted-field@"
    ],
    "location": [
      "@opensearch-dashboards-highlighted-field@osquery@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1780586766735
  ]
}
```

**Example event 5.0:**

```json
{
  "_index": "wazuh-states-inventory-users",
  "_id": "wazuh_015_ffb2eb2fe05b15856640e45d37f8d1fb2618af9a",
  "_score": 0,
  "_source": {
    "wazuh": {
      "agent": {
        "groups": [
          "default"
        ],
        "host": {
          "architecture": "x86_64",
          "hostname": "vm-ubuntu2204-agent",
          "os": {
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "22.04.2 LTS (Jammy Jellyfish)"
          }
        },
        "id": "015",
        "name": "vm-ubuntu2204-agent",
        "version": "v5.0.0"
      },
      "cluster": {
        "name": "wazuh"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "eab62e314685e51fe3e77fe402e3655bc5fb7645"
      }
    },
    "host": {
      "ip": [
        "10.0.2.2",
        "10.0.2.2"
      ]
    },
    "login": {
      "status": true,
      "tty": "pts/1",
      "type": "user"
    },
    "process": {
      "pid": 2941
    },
    "state": {
      "document_version": 1,
      "modified_at": "2026-06-04T18:34:15.388Z"
    },
    "user": {
      "auth_failures": {
        "count": 0,
        "timestamp": null
      },
      "created": null,
      "full_name": null,
      "group": {
        "id": 1000,
        "id_signed": 1000
      },
      "groups": [
        "vagrant"
      ],
      "home": "/home/vagrant",
      "id": "1000",
      "is_hidden": false,
      "is_remote": true,
      "last_login": "2026-06-04T12:22:54.000Z",
      "name": "vagrant",
      "password": {
        "expiration_date": null,
        "hash_algorithm": "y",
        "inactive_days": -1,
        "last_change": 1680134400,
        "max_days_between_changes": 99999,
        "min_days_between_changes": 0,
        "status": "active",
        "warning_days_before_expiration": 7
      },
      "roles": [
        "sudo"
      ],
      "shell": "/bin/bash",
      "type": null,
      "uid_signed": 1000,
      "uuid": null
    }
  },
  "fields": {
    "state.modified_at": [
      "2026-06-04T18:34:15.388Z"
    ],
    "user.last_login": [
      "2026-06-04T12:22:54.000Z"
    ]
  }
}
```

### Groups

Similar to Users, Wazuh 5.0 consolidates data from two OSquery tables into each
`states-inventory-groups-*` document: `groups` (group definitions from
`/etc/group`) and `user_groups` (membership relationships).

**OSquery 4.x** — relevant source tables:

```sql
-- Group definitions (/etc/group)
SELECT gid, gid_signed, groupname FROM groups;

-- Group memberships — who belongs to each group
SELECT uid, gid FROM user_groups;
```

**Wazuh 5.0 index** (`wazuh-states-inventory-groups-*`):

| OSquery source table | OSquery field | Wazuh 5.0 field | Notes |
|---|---|---|---|
| `groups` | `gid` | `group.id` | |
| `groups` | `gid_signed` | `group.id_signed` | Signed representation of the GID |
| `groups` | `groupname` | `group.name` | |
| `user_groups` | (user names) | `group.users` | Array of usernames that belong to this group |
| — | — | `group.description` | Not available on Linux; always `null` |

**Example alert 4.x:**

```json
{
  "_index": "wazuh-alerts-4.x-2026.06.04",
  "_id": "rIOJk54BLovIbi41IxMO",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "10.0.2.15",
      "name": "vm-ubuntu2204-agent",
      "id": "009"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "osquery": {
        "calendarTime": "Thu Jun  4 16:48:09 2026 UTC",
        "hostIdentifier": "vm-ubuntu2204-agent",
        "unixTime": "1780591689",
        "columns": {
          "gid": "123",
          "groupname": "wazuh"
        },
        "name": "groups_query",
        "numerics": "false",
        "action": "added",
        "epoch": "0",
        "counter": "0"
      }
    },
    "rule": {
      "firedtimes": 595,
      "mail": false,
      "level": 3,
      "description": "osquery: groups_query query result",
      "groups": [
        "osquery"
      ],
      "id": "24010"
    },
    "location": "osquery",
    "decoder": {
      "name": "json"
    },
    "id": "1780591690.2257081",
    "timestamp": "2026-06-04T16:48:10.837+0000"
  },
  "fields": {
    "timestamp": [
      "2026-06-04T16:48:10.837Z"
    ]
  },
  "highlight": {
    "data.osquery.name": [
      "@opensearch-dashboards-highlighted-field@groups_query@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1780591690837
  ]
}
```

**Example event 5.0:**

```json
{
  "_index": "wazuh-states-inventory-groups",
  "_id": "wazuh_015_c72cf90ee6d864a8759f7b4367215224782bb49d",
  "_score": 0,
  "_source": {
    "wazuh": {
      "agent": {
        "groups": [
          "default"
        ],
        "host": {
          "architecture": "x86_64",
          "hostname": "vm-ubuntu2204-agent",
          "os": {
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "22.04.2 LTS (Jammy Jellyfish)"
          }
        },
        "id": "015",
        "name": "vm-ubuntu2204-agent",
        "version": "v5.0.0"
      },
      "cluster": {
        "name": "wazuh"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "d0fbadb1b6b7b3e87f6cbbff3dcdc66a3788718a"
      }
    },
    "group": {
      "description": null,
      "id": 997,
      "id_signed": 997,
      "is_hidden": false,
      "name": "wazuh",
      "users": [
        "wazuh"
      ],
      "uuid": null
    },
    "state": {
      "document_version": 1,
      "modified_at": "2026-06-04T18:34:15.191Z"
    }
  },
  "fields": {
    "state.modified_at": [
      "2026-06-04T18:34:15.191Z"
    ]
  }
}
```

### Services

**OSquery 4.x — Windows** (`data.osquery.columns.*` in `wazuh-alerts-*`):

```sql
SELECT name, display_name, status, start_type, pid, user_account, path FROM services;
```

**OSquery 4.x — Linux** (`data.osquery.columns.*` in `wazuh-alerts-*`):

```sql
SELECT id, description, sub_state, load_state, active_state, unit_file_state,
       fragment_path, source_path, user FROM systemd_units;
```

**Wazuh 5.0 index** (`wazuh-states-inventory-services-*`):

| OSquery field (Windows `services`) | OSquery field (Linux `systemd_units`) | Wazuh 5.0 field | Notes |
|---|---|---|---|
| `name` | `id` | `service.id` | Linux: `.service` suffix is stripped by the collector |
| `display_name` | `id` | `service.name` | Linux: same value as `service.id` |
| `description` | `description` | `service.description` | |
| `status` | `active_state` | `service.state` | `active`, `inactive`, `failed`, etc. |
| — | `sub_state` | `service.sub_state` | Linux systemd substate (`running`, `exited`, …) |
| `start_type` | — | `service.start_type` | `null` on Linux (not a systemd concept) |
| — | `unit_file_state` | `service.enabled` | `enabled`, `disabled`, `static`, etc.; no Windows equivalent |
| `path` | `fragment_path` | `process.executable` | Windows: binary path; Linux: unit file path |
| — | `source_path` | `file.path` | Drop-in or override unit file path; `null` if not present |
| `pid` | — | `process.pid` | Always `0` on Linux (not provided by systemd D-Bus API) |
| `user_account` | `user` | `process.user.name` | Service user account |
| — | `following` | `service.following` | Alias target unit, if any (Linux) |
| — | `object_path` | `service.object_path` | D-Bus object path (Linux) |
| — | `job_id` | `service.target.ephemeral_id` | Associated systemd job ID (Linux) |
| — | `job_type` | `service.target.type` | Associated systemd job type (Linux) |
| — | `job_path` | `service.target.address` | Associated systemd job path (Linux) |

> **Note:** The `load_state` column present in the OSquery `systemd_units` table is not
> captured by Wazuh 5.0. Services in a non-`loaded` load state are generally not reported.


**Example alert 4.x:**

```json
{
  "_index": "wazuh-alerts-4.x-2026.06.04",
  "_id": "eYNtk54BLovIbi41BhLD",
  "_version": 1,
  "_score": null,
  "_source": {
    "input": {
      "type": "log"
    },
    "agent": {
      "ip": "10.0.2.15",
      "name": "vm-ubuntu2204-agent",
      "id": "009"
    },
    "manager": {
      "name": "wazuh-server"
    },
    "data": {
      "osquery": {
        "calendarTime": "Thu Jun  4 16:17:30 2026 UTC",
        "hostIdentifier": "vm-ubuntu2204-agent",
        "unixTime": "1780589850",
        "columns": {
          "sub_state": "running",
          "active_state": "active",
          "load_state": "loaded",
          "description": "Wazuh agent",
          "fragment_path": "/lib/systemd/system/wazuh-agent.service",
          "id": "wazuh-agent.service"
        },
        "name": "services_query",
        "numerics": "false",
        "action": "added",
        "epoch": "0",
        "counter": "0"
      }
    },
    "rule": {
      "firedtimes": 309,
      "mail": false,
      "level": 3,
      "description": "osquery: services_query query result",
      "groups": [
        "osquery"
      ],
      "id": "24010"
    },
    "location": "osquery",
    "decoder": {
      "name": "json"
    },
    "id": "1780589854.1997582",
    "timestamp": "2026-06-04T16:17:34.772+0000"
  },
  "fields": {
    "timestamp": [
      "2026-06-04T16:17:34.772Z"
    ]
  },
  "highlight": {
    "data.osquery.name": [
      "@opensearch-dashboards-highlighted-field@services_query@/opensearch-dashboards-highlighted-field@"
    ]
  },
  "sort": [
    1780589854772
  ]
}
```

**Example event 5.0:**

```json
{
  "_index": "wazuh-states-inventory-services",
  "_id": "wazuh_015_5eec650d7ac046425786139dd84a0206bd5f4e48",
  "_score": 0,
  "_source": {
    "wazuh": {
      "agent": {
        "groups": [
          "default"
        ],
        "host": {
          "architecture": "x86_64",
          "hostname": "vm-ubuntu2204-agent",
          "os": {
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "22.04.2 LTS (Jammy Jellyfish)"
          }
        },
        "id": "015",
        "name": "vm-ubuntu2204-agent",
        "version": "v5.0.0"
      },
      "cluster": {
        "name": "wazuh"
      }
    },
    "checksum": {
      "hash": {
        "sha1": "36053478cb8c39adbe92a1db1adc8c8ead9e659b"
      }
    },
    "error": {
      "log": {
        "file": {
          "path": null
        }
      }
    },
    "file": {
      "path": null
    },
    "log": {
      "file": {
        "path": null
      }
    },
    "process": {
      "args": null,
      "executable": "/lib/systemd/system/wazuh-agent.service",
      "group": {
        "name": null
      },
      "pid": 0,
      "root_directory": null,
      "user": {
        "name": null
      },
      "working_directory": null
    },
    "service": {
      "address": null,
      "description": "Wazuh agent",
      "enabled": "enabled",
      "exit_code": 0,
      "following": null,
      "frequency": 0,
      "id": "wazuh-agent",
      "inetd_compatibility": false,
      "name": "wazuh-agent",
      "object_path": "/org/freedesktop/systemd1/unit/wazuh_2dagent_2eservice",
      "restart": null,
      "start_type": null,
      "starts": {
        "on_mount": false,
        "on_not_empty_directory": null,
        "on_path_modified": null
      },
      "state": "active",
      "sub_state": "running",
      "target": {
        "address": "/",
        "ephemeral_id": "0",
        "type": null
      },
      "type": null,
      "win32_exit_code": 0
    },
    "state": {
      "document_version": 1,
      "modified_at": "2026-06-04T18:34:15.332Z"
    }
  },
  "fields": {
    "state.modified_at": [
      "2026-06-04T18:34:15.332Z"
    ]
  }
}
```

## Migration procedure

Follow these steps to migrate from OSquery to IT Hygiene in Wazuh 5.0.

### Prerequisites

- Wazuh 4.x central components still accessible.
- Wazuh 5.0 central components (server, indexer, and dashboard) deployed and
  running as a **new installation** (in-place upgrade from 4.x is not supported).
- Wazuh 5.0 agents deployed and running.
- Access to both the 4.x and 5.0 Wazuh dashboards as an administrator.

### Step 1 – Catalog and export OSquery-based saved objects from 4.x

> **Do this step before decommissioning your 4.x installation.** Because
> Wazuh 5.0 is a fresh install, saved objects from 4.x are not carried over
> automatically.

In the **4.x** Wazuh dashboard, identify every saved search, visualization,
dashboard, index pattern, and Alerting monitor that references OSquery data.
OSquery results were stored in `wazuh-alerts-*` as regular alerts. Look for:

- Rule group `osquery`.
- Field `data.osquery.name` containing a query or pack name.
- Fields under `data.osquery.columns.*` (e.g., `data.osquery.columns.username`,
  `data.osquery.columns.name`).
- Location field `osquery`.

Export all affected saved objects as NDJSON: **Dashboard management >
Saved objects > Export**. Keep the exported file as a reference when
recreating objects in the 5.0 installation. You cannot import it directly
because the field names and index patterns no longer apply.

For Alerting monitors, note down the monitor definition (query, triggers,
and actions) from **OpenSearch Plugins > Alerting**; they are not included
in the saved objects export.

### Step 2 – Enable IT Hygiene categories in agent configuration

Identify the OSquery tables your packs query, then verify that the corresponding
Syscollector categories are enabled in each agent's `ossec.conf` (or via
centralized configuration with agent groups). All categories are enabled by
default, so in most cases no configuration change is needed:

```xml
  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>

    <!-- Database synchronization settings -->
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>75</max_eps>
      <integrity_interval>24h</integrity_interval>
    </synchronization>
  </wodle>
```

After saving, restart the agent:

```bash
# Linux
sudo systemctl restart wazuh-agent

# Windows (PowerShell)
Restart-Service -Name wazuh

# macOS
/Library/Ossec/bin/wazuh-control restart
```

### Step 3 – Wait for Syscollector to complete its first sync

Before checking the dashboard, confirm that the agent has completed its
evaluation and synchronization cycle. On **Linux**, tail the agent log:

```bash
tail -f /var/ossec/logs/ossec.log | grep "syscollector:"
```

On **Windows**, check the equivalent log at
`C:\Program Files (x86)\ossec-agent\ossec.log`.

A successful sync produces output similar to:

```
wazuh-modulesd:syscollector: INFO: Started (pid: 11156).
wazuh-modulesd:syscollector: INFO: Starting evaluation.
wazuh-modulesd:syscollector: INFO: Evaluation finished.
wazuh-modulesd:syscollector: INFO: Starting inventory synchronization.
wazuh-modulesd:syscollector: INFO: VD first sync completed, metadata marker persisted.
wazuh-modulesd:syscollector: INFO: Syscollector synchronization process finished successfully.
```

Wait until you see **"Syscollector synchronization process finished
successfully."** before proceeding to the next step. On the first run after
enabling new categories this can take up to a minute depending on the number
of items in the inventory.

### Step 4 – Verify inventory data in the dashboard

1. Open the Wazuh dashboard and navigate to **Security operations > IT Hygiene**.
2. Select the agent and confirm that all the enabled categories are populated.
3. Spot-check a few records against what you would have expected from
   the equivalent OSquery query.

### Step 5 – Recreate visualizations and dashboards in 5.0

In Wazuh 5.0 the inventory index patterns (`wazuh-states-inventory-*`) are
created automatically by the server — you do not need to create them manually.
If you had custom index patterns over `wazuh-alerts-*` scoped to OSquery data
(for example, a pattern filtered to rule group `osquery`), those need to be
recreated only if you still need to query historical OSquery alerts from the
4.x period.

Rebuild any visualizations or dashboards using the field mapping tables in
[Field mapping examples](#field-mapping-examples). The table below shows some common remappings as a quick reference:

| Old index (4.x) | Old field path | New index (5.0) | New field |
|---|---|---|---|
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.username` | `wazuh-states-inventory-users-*` | `user.name` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.uid` | `wazuh-states-inventory-users-*` | `user.id` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.name` (processes) | `wazuh-states-inventory-processes-*` | `process.name` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.pid` | `wazuh-states-inventory-processes-*` | `process.pid` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.groupname` | `wazuh-states-inventory-groups-*` | `group.name` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.gid` | `wazuh-states-inventory-groups-*` | `group.id` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.name` (chrome_extensions) | `wazuh-states-inventory-browser-extensions-*` | `package.name` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.identifier` | `wazuh-states-inventory-browser-extensions-*` | `package.id` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.id` (services) | `wazuh-states-inventory-services-*` | `service.id` |
| `wazuh-alerts-*` (rule group `osquery`) | `data.osquery.columns.active_state` | `wazuh-states-inventory-services-*` | `service.state` |

### Step 6 – Recreate alerting monitors in 5.0


Recreate each Alerting monitor noted in Step 1 in the 5.0 installation,
targeting the appropriate `wazuh-states-inventory-*` index instead of
`wazuh-alerts-*`. Translate all field references using the mapping tables
above and in [Field mapping examples](#field-mapping-examples). Because
inventory indices are stateful (one document per item, updated in place)
rather than event-based, monitor queries should use a **document-level
monitor** on the inventory index rather than a **query-level monitor** on
alerts.

### Step 7 – Remove the OSquery wodle block from agent configuration

Once you have verified that all data is flowing correctly through Syscollector,
remove the `<wodle name="osquery">` block from the agent configuration.
The OSquery wodle has been fully removed in Wazuh 5.0: a leftover block is
ignored and the agent logs `INFO: The 'osquery' module is deprecated. Use the
Syscollector module instead.` It does not prevent the agent from starting, but
it no longer provides any functionality, so delete it:

```xml
<!-- Remove this block entirely from ossec.conf -->
<wodle name="osquery">
    ...
</wodle>
```

## Limitations and known differences

| Area | OSquery 4.x behavior | Wazuh 4.14+ / 5.0 IT Hygiene behavior |
|---|---|---|
| **Installation** | External binary (`osqueryd`) required on each endpoint | Built into the Wazuh agent; no extra install |
| **Data destination** | Alerts in `wazuh-alerts-*` (rules 24000-24811, group `osquery`); fields under `data.osquery.*` | Stateful inventory indices (`states-inventory-*`) |
| **Query granularity** | Per-field SQL SELECT at query time | All fields for a category collected on each scan |
| **On-demand queries** | `osqueryi` interactive shell | Not available; use `scan_on_start` or reduce the interval |
| **Event-based tables** | Supported (e.g., `process_events`, `file_events`, `socket_events`) | Out of scope; use FIM for file events, Audit/Syscall monitoring for process and socket events |
| **Custom tables** | OSquery extensions / ATC tables | Not supported |
| **Pack scheduling** | Per-query intervals defined in pack files | Single scan interval for all enabled categories |
| **Tier 3 categories** | Full OSquery table coverage | Planned: Disks & Devices, Kernel Modules, Firmware, WiFi |

## Related resources

- [Syscollector configuration reference](../../ref/modules/syscollector/configuration.md)
- [Syscollector events reference](../../ref/modules/syscollector/events.md)
- [Syscollector architecture](../../ref/modules/syscollector/architecture.md)
