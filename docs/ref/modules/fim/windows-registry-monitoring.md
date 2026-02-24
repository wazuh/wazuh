# Windows Registry monitoring

The Windows Registry is a vital part of the Windows operating system. It is a database that stores configuration information for programs and hardware installed on Microsoft Windows operating systems. When you install a program, Windows creates a new subkey in the registry. This subkey contains information such as the program location, version, and startup instructions.

An unauthorized or unexpected change to the registry might result in system instability, application failures, and security breaches. Attackers might modify registry keys to execute malicious code or to maintain persistence on the system. In addition, legitimate software and system updates might also modify the registry. It's essential to track these changes to ensure system stability and security.

The Wazuh FIM module scans the Windows Registry periodically and triggers an alert when it detects changes in the entries.

## How it works

The FIM module runs periodic scans of monitored Windows Registry entries and stores their checksums and other attributes in a local FIM database. You can specify which registry entries to monitor in the configuration of the Wazuh agent.

Upon a scan, the Wazuh agent reports any changes the FIM module finds in the monitored registry entries to the Wazuh server. The FIM module looks for file modifications by comparing the checksums of a registry entry to its stored checksums and attribute values. It generates an alert if it finds discrepancies.

The Wazuh FIM module uses two databases to collect FIM event data, such as registry entry creation, modification, and deletion data:

- Local SQLite database on the endpoint:  
  `C:\Program Files (x86)\ossec-agent\queue\fim\db`
- Agent database on the Wazuh server:  
  `/var/ossec/queue/db`


The FIM module synchronization mechanism ensures synchronization between the Wazuh agent and the Wazuh server databases. It always updates the file inventory in the Wazuh server with the data available to the Wazuh agent. This allows servicing FIM-related API queries regarding the Wazuh agents.

## Configuration

To configure the FIM module, specify the registry keys that FIM must monitor for creation, modification, and deletion using the `<windows_registry>` label.

You can modify the default FIM configuration in  
`C:\Program Files (x86)\ossec-agent\ossec.conf`.

You can also configure this capability remotely using centralized configuration.

Wildcards `*` and `?` are supported when configuring Windows registry keys.

### Example

```xml
<syscheck>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\SOFTWARE\*</windows_registry>
  <windows_registry arch="both">HKEY_CURRENT_CONFIG\S?????</windows_registry>
  <windows_registry arch="both">HKEY_USERS\S-?-?-??\*</windows_registry>
</syscheck>
```

> **Note**  
> Registry keys created after the initial scan are monitored starting from the next scheduled scan.

The FIM module supports multiple attributes such as `check_all` and `report_changes`.

---

## Record Windows Registry attributes

The `windows_registry` option supports several attributes:

- **check_all** (default: `yes`)
  - File size
  - Last modification date
  - MD5, SHA1, and SHA256 hashes

- **check_sum**
  - Records only hashes
  - Allowed values: `yes`, `no`

- **check_mtime**
  - Records modification time
  - Allowed values: `yes`, `no`

### Example configuration

```xml
<syscheck>
  <windows_registry>HKEY_LOCAL_MACHINE\Software\Classes\batfile\TestKey1</windows_registry>
  <windows_registry check_sum="no">HKEY_LOCAL_MACHINE\Software\Classes\batfile\TestKey2</windows_registry>
  <windows_registry check_mtime="no">HKEY_LOCAL_MACHINE\Software\Classes\batfile\TestKey3</windows_registry>
</syscheck>
```

Restart the agent:

```console
Restart-Service -Name wazuh
```

---

## Recursion level

The `recursion_level` attribute defines the maximum depth to monitor.

- Allowed values: `0` to `512`
- `0` disables recursion

### Example

```xml
<syscheck>
  <windows_registry recursion_level="3">HKEY_LOCAL_MACHINE\SYSTEM\Setup</windows_registry>
</syscheck>
```

Restart the agent:

```console
Restart-Service -Name wazuh
```

Example structure with `recursion_level="3"`:

```text
HKEY_LOCAL_MACHINE\SYSTEM\Setup
├── Subkey_0
└── level_1
    ├── Subkey_1
    └── level_2
        ├── Subkey_2
        └── level_3
            ├── Subkey_3
            └── level_4
```

If not specified, the default value is defined by `syscheck.default_max_depth`.

---

## Reporting changes in registry values

The `report_changes` attribute allows reporting the exact content changed.

- Allowed values: `yes`, `no`
- Supported types:
  - `REG_SZ`
  - `REG_MULTI_SZ`
  - `REG_DWORD`
  - `REG_DWORD_BIG_ENDIAN`

> **Warning**  
> This option increases disk usage because registry data is stored under  
> `C:\Program Files (x86)\ossec-agent\queue\diff\registry`.

### Example

```xml
<syscheck>
  <frequency>300</frequency>
  <windows_registry report_changes="yes">HKEY_LOCAL_MACHINE\SYSTEM\Setup</windows_registry>
</syscheck>
```

Restart the agent:

```console
Restart-Service -Name wazuh
```

---

## Adding exclusions

You can ignore registry entries using `registry_ignore`.

### Example

```xml
<syscheck>
  <registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>
  <registry_ignore type="sregex">\Enum$</registry_ignore>
</syscheck>
```

Restart the agent:

```console
Restart-Service -Name wazuh
```

---

## Use case: Detect malware persistence in Windows Registry

Malware often persists by adding entries to `Run` and `RunOnce` registry keys.

### Configuration

By default, Wazuh monitors startup registry keys:

```xml
<syscheck>
  <frequency>300</frequency>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
</syscheck>
```

---

## Test the configuration

> **Note**  
> Perform this test in a sandbox environment.

1. Add a string value `DemoValue` with data `cmd` to the `Run` key.
2. Add the same value to the `RunOnce` key.
3. Wait 5 minutes for the scan.

---
