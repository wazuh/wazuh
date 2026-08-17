# Migration from Wazuh Agent 4.X to 5.0.0

This guide describes how to migrate Wazuh agents from 4.X to 5.0.0, including:

- Required upgrade path when the current agent is older than 4.14.X.
- Invalid and deprecated configuration elements in `ossec.conf`.
- Observed startup warnings and errors and their corresponding workarounds.
- Notes about `local_internal_options.conf` compatibility.

## Upgrade path requirements

Wazuh Agent 5.0.0 cannot be installed directly on agents running versions earlier than 4.14.0.

Required path:

1. Upgrade `4.X` -> `4.14.X`
2. Upgrade `4.14.X` -> `5.0.0`

If you attempt a direct `4.13.X` -> `5.0.0` package upgrade, installation is blocked by pre-install validation,

On the Dashboard:

![Screenshot](../../images/upgrade-4x-to-5x/direct-upgrade-dashboard.png)

On a Windows Agent:

![Screenshot](../../images/upgrade-4x-to-5x/direct-upgrade-windows.png)

On a linux terminal:

```console
UPGRADE BLOCKED: Incompatible version detected

Current version: v4.13.1
Target version:  5.0.0

Upgrade to Wazuh 5.0.0 is only supported from version 4.14.0 or later.
```

On a MacOS terminal the message is less intuitive:

```console
sh-3.2# installer -pkg /Users/vagrant/Downloads/wazuh-agent-5.0.0-beta2.arm64.pkg -target /
installer: Package name is wazuh-agent-5.0.0-beta2.arm64
installer: Upgrading at base path /
installer: The upgrade failed. (The Installer encountered an error that caused the installation to fail. Contact the software manufacturer for assistance. An error occurred while running scripts from the package “wazuh-agent-5.0.0-beta2.arm64.pkg”.)
```

## Recommended migration workflow

1. Upgrade the agent to the latest available `4.14.X` package.
2. Validate the agent starts without new errors on `4.14.X`.
3. Upgrade from `4.14.X` to `5.0.0`.
4. Review `ossec.log` and fix any invalid/deprecated configuration elements listed below.
5. Restart the agent and verify healthy connectivity and module startup.

## Configuration migration (`ossec.conf`)

The following changes were identified during agent startup validation after upgrading to 5.0.0.

| 4.X configuration element | 5.0 status | Agent log message (observed) | Required action |
|---|---|---|---|
| `<client>...</client>` | Renamed | `INFO: <agent><server><address> is not configured. Using <client><server><address> 'MANAGER_IP' with the default port 1517.` | Rename the block to `<agent>`. A 5.0 agent still starts without the rename: it reads `<server><address>` from the old block and defaults the port to `1517`. Nothing else inside `<client>` is read. |
| `<client><manager>...</manager></client>` | Invalid | `INFO: (1230): Invalid element in the configuration: 'manager'.` | Rename `<manager>` to `<server>` inside `<agent>`. The 4.14 templates already ship `<server>`. |
| `<client><server><port>1514</port></server></client>` | Changed default | — | The agent talks HTTPS to the manager on `1517`. Inside `<agent>`, remove the port to take the new default or set `1517` explicitly; inside a legacy `<client>` block the port is not read at all. |
| `<client><server><protocol>...</protocol></server></client>` | Ignored | `INFO: Ignoring the 'protocol' option. Switching to TCP.` | Remove `<protocol>`. TCP is used. |
| `<client><crypto_method>...</crypto_method></client>` | Ignored | `INFO: Ignoring the 'crypto_method' option. Switching to AES.` | Remove `<crypto_method>`. |
| `<syscheck><scan_on_start>...</scan_on_start></syscheck>` | Invalid | `INFO: (1230): Invalid element in the configuration: 'scan_on_start'.` | Remove this element from `syscheck` (Always executed on start). |
| `<rootcheck><check_files>...</check_files></rootcheck>` | Removed | `INFO: Rootcheck option 'check_files' is no longer supported. Use the FIM module instead.` | Remove from `rootcheck`; use FIM (`syscheck`) controls. |
| `<rootcheck><check_trojans>...</check_trojans></rootcheck>` | Removed | `INFO: Rootcheck option 'check_trojans' is no longer supported. Use the FIM module instead.` | Remove from `rootcheck`; use FIM (`syscheck`) controls. |
| `<rootcheck><rootkit_files>...</rootkit_files></rootcheck>` | Invalid | `INFO: (1230): Invalid element in the configuration: 'rootkit_files'.` | Remove from `rootcheck`. |
| `<wodle name="cis-cat">...</wodle>` | Removed in 5.0 | `INFO: The 'cis-cat' module is deprecated. Use the SCA module instead.` | Migrate to SCA, then remove the `cis-cat` wodle block. See [Migrating from CIS-CAT and OpenSCAP to SCA](ciscat-openscap-to-sca.md). |
| `<wodle name="osquery">...</wodle>` | Removed in 5.0 | `INFO: The 'osquery' module is deprecated. Use the Syscollector module instead.` | Migrate to IT Hygiene, then remove the `osquery` wodle block. See [Migrating from OSquery to IT Hygiene](osquery-to-it-hygiene.md). |
| `<sca><skip_nfs>...</skip_nfs></sca>` | Deprecated/Unavailable | `INFO: Detected a deprecated configuration for SCA: 'skip_nfs' is no longer available.` | Remove `<skip_nfs>` from `sca`. See [SCA policies from 4.x to 5.x](sca-policies-4x-to-5x.md). |
| `<client><enrollment><auto_method>...</auto_method></enrollment></client>` | Invalid | `ERROR: (1230): Invalid element in the configuration: 'auto_method'.` | Remove `<auto_method>` from `<enrollment>`. The option was removed entirely; see [TLS 1.3 enrollment enforcement](#tls-13-enrollment-enforcement-wazuh-authd) below. |

### Additional observed parser side-effects

When invalid rootcheck/syscheck options remain in the configuration, the agent may also report:

```console
INFO: (1202): Configuration error at 'etc/ossec.conf'.
INFO: (1207): wazuh-rootcheck remote configuration in 'etc/ossec.conf' is corrupted.
```

These messages are resolved by removing the invalid elements listed above.

## `ossec.conf` quick before/after examples

### Agent connection block

Before (4.X style):

```xml
<client>
	<server>
		<address>MANAGER_IP</address>
		<port>1514</port>
		<protocol>tcp</protocol>
	</server>
	<crypto_method>aes</crypto_method>
</client>
```

After (5.0 compatible):

```xml
<agent>
	<server>
		<address>MANAGER_IP</address>
		<port>1517</port>
	</server>
</agent>
```

`<client>` is renamed to `<agent>` in 5.0: one block under two names, never both. Options for an agent that is already on 5.0 with the old block:

- **Leave it.** The agent reads `<server><address>` from `<client>` and uses port `1517`. It connects, and logs which value it inherited. Nothing else in the block is read, so options such as `<enrollment>` or `<config-profile>` stop having an effect.
- **Rename it** to `<agent>`, which is what a fresh 5.0 install ships. Every option in the block is read again.

Recommended: rename it. The fallback exists so a remote upgrade cannot strand an agent, not as a configuration to keep.

### Removed modules

The `cis-cat` and `osquery` modules are removed in 5.0, but their capabilities are provided by other components. Migrate the functionality **before** removing the blocks:

- `cis-cat` -> SCA. See [Migrating from CIS-CAT and OpenSCAP to SCA](ciscat-openscap-to-sca.md).
- `osquery` -> IT Hygiene. See [Migrating from OSquery to IT Hygiene](osquery-to-it-hygiene.md).

Once the functionality is migrated, remove the blocks from `ossec.conf`:

```xml
<wodle name="cis-cat">...</wodle>
<wodle name="osquery">...</wodle>
```

### Rootcheck and syscheck cleanup

Remove unsupported elements:

```xml
<syscheck>
	<!-- remove scan_on_start -->
</syscheck>

<rootcheck>
	<!-- remove check_files -->
	<!-- remove check_trojans -->
	<!-- remove rootkit_files -->
</rootcheck>

<sca>
	<!-- remove skip_nfs -->
</sca>
```

## `local_internal_options.conf` migration notes

`local_internal_options.conf` overrides values defined in the default `internal_options.conf`. Comparing the agent default internal options between `4.14.X` and `5.0.0`, **no agent-side option keys were removed or renamed**. All agent component namespaces remain valid in 5.0:

`agent`, `execd`, `logcollector`, `rootcheck`, `sca`, `syscheck`, `wazuh_command`, `wazuh_modules`, `windows`.

The internal options removed in 5.0 belong exclusively to **manager-side** components (for example `analysisd.*`, `remoted.*`, `monitord.*`, `wazuh_db.*`, `vulnerability-detection.*`). These never take effect on an agent, so they do not require any migration action on agent hosts.

The agent does not validate `local_internal_options.conf` against a schema. Keys that no module reads are silently ignored: they do not block startup and do not emit warning or error messages. Consequently, there are **no `local_internal_options.conf` entries that prevent a 5.0.0 agent from starting**, and no specific log messages are expected for this file during the upgrade.

Recommended handling:

1. Keep `local_internal_options.conf` as-is during the package upgrade.
2. Optionally, remove any manager-only keys that may have been copied into the agent file (for example `analysisd.*`, `remoted.*`, `wazuh_db.*`); they have no effect on the agent and are kept only for tidiness.

## Connectivity and interoperability checks

After upgrading and cleaning configuration, verify:

1. Agent successfully connects to the manager over HTTPS on port `1517`.
2. Enrollment/service endpoint is reachable on port `1515` (if enrollment is being used).
3. Agent and manager versions are both compatible with 5.0 communication protocol.

Typical connectivity symptoms requiring action:

```console
ERROR: (1208): Unable to connect to enrollment service at '[MANAGER_IP]:1515'
WARNING: (4101): Waiting for server reply (not started). Tried: 'MANAGER_IP'. Ensure that the manager version is 'v5.0.0' or higher.
ERROR: (1216): Unable to connect to '[MANAGER_IP]:1514/tcp': 'Transport endpoint is not connected'.
```

Workaround checklist:

- Confirm manager is up and reachable from the agent host.
- Confirm manager has been migrated to a compatible 5.0 deployment.
- Confirm firewall/network rules allow `1517/tcp` (agent to manager) and `1515/tcp` (enrollment).
- Confirm the agent points to the correct manager address in `<agent><server><address>`.
- Confirm enrollment credentials: if enrollment fails with `Invalid password (from manager)`, verify that the password in `/var/ossec/etc/authd.pass` on the agent matches `/var/wazuh-manager/etc/authd.pass` on the manager.

## Remote upgrade (WPK)

A remote upgrade from 4.14.X to 5.0.0 never rewrites `ossec.conf`: the file the 4.X agent had is the file the 5.0 agent reads, which is why the `<client>` fallback above exists.

Before installing anything, the WPK installer checks that the manager accepts connections on the HTTPS port the upgraded agent will use, and aborts if it does not:

```console
2026/07/31 00:26:57 - Checking connectivity to MANAGER_IP:1517.
2026/07/31 00:26:58 - Upgrade failed. The manager is not reachable at MANAGER_IP:1517, interrupting upgrade.
```

The abort happens before the package manager runs, so the agent stays on 4.14.X, keeps running, and the upgrade can be retried once `1517` is reachable. `upgrade_result` is `2`.

The target address and port come from the same place the agent reads them: `<agent><server>` first, then `<client><server><address>`, with `1517` as the port default.

## TLS 1.3 enrollment enforcement (`wazuh-authd`)

Wazuh 5.0 raises the minimum TLS protocol version accepted by the manager's enrollment service (`wazuh-authd`) to TLS 1.3 and removes the `ssl_auto_negotiate` fallback that previously allowed negotiating down to TLS 1.0. This affects the manager's `wazuh-manager.conf` and the agent's `<enrollment>` block in `ossec.conf`.

### Manager: `<auth><ciphers>` must use a TLS 1.3 ciphersuite list

`wazuh-authd` validates `<ciphers>` against a fixed set of TLS 1.3 ciphersuite names: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`. A 4.x-style OpenSSL cipher-list string (for example the previous default, `HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH`) is rejected at config load:

```console
ERROR: Invalid TLS 1.3 cipher suite 'HIGH' in 'ciphers' option
```

If an invalid value somehow reaches the TLS setup step, the manager fails the same way at startup instead:

```console
ERROR: Invalid TLS 1.3 cipher suite list: '<value>'
ERROR: SSL context setup failed. Exiting.
```

Either way, `wazuh-authd` does not start and no agent can enroll until `<ciphers>` is updated to a colon-separated list of the values above (default: `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`) or removed to use that default.

`<auth><ssl_auto_negotiate>` was also removed entirely. Leaving it in `wazuh-manager.conf` is now an invalid element and blocks the manager from starting:

```console
ERROR: (1230): Invalid element in the configuration: 'ssl_auto_negotiate'.
```

Remove `<ssl_auto_negotiate>` from `<auth>` before upgrading the manager.

### Agent: `<enrollment><ssl_cipher>` must also use a TLS 1.3 ciphersuite list

The agent's `ssl_cipher` option has the same new format requirement, but no config-time validation: a legacy value is accepted at startup and only fails when the agent actually tries to enroll:

```console
ERROR: Invalid TLS 1.3 cipher suite list: '<value>'
ERROR: Could not set up SSL connection! Check certification configuration.
```

Update `ssl_cipher` to a colon-separated TLS 1.3 ciphersuite list (same values as the manager's `<ciphers>`) before or during the upgrade, or remove it to use the default. `<enrollment><auto_method>` was removed outright (see the configuration table above) — it has no TLS 1.3 equivalent to negotiate down to.

### Agents not yet upgraded past 4.14.x

An agent still running a pre-5.0 build predates this enforcement and applies `ssl_cipher`/`auto_method` through OpenSSL's legacy `SSL_CTX_set_cipher_list()` API, which only affects TLS 1.2-and-below negotiation. Once the manager forces TLS 1.3, that legacy cipher list has no effect on the ciphersuite actually negotiated — OpenSSL falls back to its own TLS 1.3 defaults regardless of the configured value. This follows from documented OpenSSL behavior rather than something exercised against this codebase (the pre-5.0 agent code implementing this path is not part of this repository), so treat `ssl_cipher`/`auto_method` as inert, not broken, on agents older than this change: they do not need to be removed for enrollment to keep working, but they also no longer do anything. Upgrading the agent to a 5.0-compatible build brings it under the stricter validation described above.

## Validation checklist

Migration is complete when all conditions below are met:

- Agent was upgraded using the required version path.
- No invalid `syscheck`/`rootcheck` element warnings remain.
- The connection block is `<agent>`, and no `<client>` fallback message remains in `ossec.log`.
- No deprecated `protocol` or `crypto_method` messages remain.
- Agent stays connected to the manager and sends events normally.
- No TLS 1.3 enrollment errors (`Invalid TLS 1.3 cipher suite...`, `Could not set up SSL connection...`) appear in `wazuh-authd` or agent logs, and enrollment against the 5.0 manager succeeds.
