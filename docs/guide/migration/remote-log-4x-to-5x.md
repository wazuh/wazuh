# Migrating Syslog Input to Logcollector with rsyslog

In previous Wazuh versions (4.x), the manager's `remoted` module accepted raw syslog messages from network devices (firewalls, routers, switches) on port 514, configured via `<connection>syslog</connection>` in the manager's `ossec.conf`.

Starting with Wazuh 5.0, this syslog input capability has been removed from `remoted`. The module now exclusively handles encrypted agent connections. To continue collecting syslog from network devices, you must deploy a dedicated syslog daemon (rsyslog or syslog-ng) that receives and stores the messages locally, and install a Wazuh agent on that host to forward the logs to the Wazuh server.

> **Note:** There is no automatic migration tooling for this change. You must manually configure rsyslog and install a Wazuh agent on the syslog collection host.

## What changed

| Aspect | Wazuh 4.x | Wazuh 5.x |
| ----------------------- | ---------------------------------------------- | --------------------------------------------------- |
| Syslog receiver | Manager `remoted` (port 514) | External syslog daemon (rsyslog or syslog-ng) |
| Log ingestion | Direct to `analysisd` | Via Wazuh agent logcollector |
| Configuration location | Manager `ossec.conf` `<remote>` block | Agent `ossec.conf` `<localfile>` block |
| Wazuh agent on host | Not required | Required — not installed with the manager in 5.0 |
| IP allowlist/denylist | `<allowed-ips>` / `<denied-ips>` in `ossec.conf` | rsyslog `$AllowedSender` or host firewall rules |

## Architecture

**Wazuh 4.x:**

```
Network device ──(syslog UDP/TCP port 514)──► Wazuh manager (remoted) ──► analysisd
```

**Wazuh 5.x:**

```
Network device ──(syslog UDP/TCP port 514)──► rsyslog ──► /var/log/remote/<host>.log
                                                                        │
                                                              Wazuh agent (logcollector)
                                                                        │
                                                              Wazuh manager (analysisd)
```

## Configuration mapping (4.x → 5.x)

The following table maps each `ossec.conf` element from Wazuh 4.x to its Wazuh 5.x equivalent.

| 4.x `ossec.conf` | 5.x equivalent | Guide |
| --------------------------------- | ----------------------------------------- | ----------------------------------------------- |
| `remote.connection` = `syslog` | rsyslog `imudp` or `imtcp` input module | [Step 1](#1-configure-rsyslog-to-receive-remote-syslog) |
| `remote.port` | rsyslog `input` port | [Step 1](#1-configure-rsyslog-to-receive-remote-syslog) |
| `remote.protocol` | rsyslog `imudp` (UDP) or `imtcp` (TCP) | [Step 1](#1-configure-rsyslog-to-receive-remote-syslog) |
| `remote.allowed-ips` | rsyslog `$AllowedSender` or firewall rules | [Step 1](#1-configure-rsyslog-to-receive-remote-syslog) |
| `remote.denied-ips` | Host firewall rules (`iptables`/`firewalld`) | [Step 1](#1-configure-rsyslog-to-receive-remote-syslog) |
| Syslog forwarded directly to `analysisd` | Agent `localfile` stanza monitoring log files | [Step 3](#3-configure-the-wazuh-agent-to-monitor-syslog-files) |

## Wazuh 4.x `ossec.conf` reference

The following is a typical syslog input configuration block in Wazuh 4.x `ossec.conf`. Use it as a reference when following the migration steps below.

```xml
<!-- Wazuh 4.x manager ossec.conf -->
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.1.0/24</allowed-ips>
  </remote>
</ossec_config>
```

## Migration steps

### Prerequisites

Before proceeding, make sure you have:

- Wazuh 5.0 or later fully deployed (indexer, manager, dashboard)
- A Linux host where rsyslog will run — this can be the same host as the Wazuh manager or a dedicated server
- rsyslog installed on that host (`sudo apt install rsyslog` or `sudo yum install rsyslog`)
- Network devices configured to send syslog to that host's IP address on port 514
- The Wazuh manager's IP address or hostname available for agent enrollment

> These steps must be followed **in order**, as each step depends on the previous one.

---

### 1. Configure rsyslog to receive remote syslog

On the syslog collection host, create a dedicated rsyslog configuration file to receive syslog from remote devices and write each host's messages to a separate log file.

Create `/etc/rsyslog.d/99-wazuh-remote.conf` with the following content:

**UDP (default for most network devices):**

```
# Load UDP input module
module(load="imudp")
input(type="imudp" port="514")

# Write incoming syslog to per-host files
template(name="RemoteHostLogs" type="string"
         string="/var/log/remote/%HOSTNAME%.log")

*.* ?RemoteHostLogs
```

**TCP (if your devices support it):**

```
# Load TCP input module
module(load="imtcp")
input(type="imtcp" port="514")

template(name="RemoteHostLogs" type="string"
         string="/var/log/remote/%HOSTNAME%.log")

*.* ?RemoteHostLogs
```

Create the output directory and set permissions:

```bash
sudo mkdir -p /var/log/remote
sudo chown syslog:adm /var/log/remote
sudo chmod 755 /var/log/remote
```

If you previously used `<allowed-ips>` in Wazuh 4.x to restrict which hosts could send syslog, add an equivalent restriction to the rsyslog configuration:

```
$AllowedSender UDP, 192.168.1.0/24
```

Or enforce it with a firewall rule:

```bash
# Allow syslog only from your network
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="514" protocol="udp" accept'
sudo firewall-cmd --reload
```

Restart rsyslog to apply the changes:

```bash
sudo systemctl restart rsyslog
```

Verify that rsyslog is listening on port 514:

```bash
sudo ss -ulnp | grep 514
```

---

### 2. Install the Wazuh agent on the syslog collection host

> **Important:** In Wazuh 5.0, the Wazuh agent is **not installed automatically with the manager**. Even if rsyslog runs on the same host as the Wazuh manager, you must install and enroll a separate Wazuh agent to collect and forward the syslog files.

Download the Wazuh agent package for your platform. See the [Package Download](../../ref/getting-started/packages.md#package-download) section for available repositories.

**Debian-based platforms (Ubuntu, Debian):**

```bash
sudo WAZUH_MANAGER='<MANAGER_IP>' WAZUH_AGENT_NAME='syslog-collector' dpkg -i wazuh-agent_*.deb
```

**Red Hat-based platforms (RHEL, CentOS, Amazon Linux):**

```bash
sudo WAZUH_MANAGER='<MANAGER_IP>' WAZUH_AGENT_NAME='syslog-collector' rpm -ivh wazuh-agent-*.rpm
```

Replace `<MANAGER_IP>` with the IP address or hostname of your Wazuh manager. Replace `syslog-collector` with a descriptive name for this agent (e.g., `rsyslog-host` or the hostname of the server).

> If you are installing the agent on the same host as the Wazuh manager, use `127.0.0.1` as `WAZUH_MANAGER`.

---

### 3. Configure the Wazuh agent to monitor syslog files

Edit the agent's configuration file at `/var/ossec/etc/ossec.conf` and add a `<localfile>` block to monitor the log files created by rsyslog.

**Monitor all per-host log files using a wildcard:**

```xml
<ossec_config>
  <localfile>
    <location>/var/log/remote/*.log</location>
    <log_format>syslog</log_format>
  </localfile>
</ossec_config>
```

This single stanza covers all files written by rsyslog under `/var/log/remote/`, regardless of how many source hosts are added in the future.

If you need to monitor only a specific host or a subset of devices, use a more specific pattern:

```xml
<!-- Monitor only a specific host -->
<localfile>
  <location>/var/log/remote/firewall-01.log</location>
  <log_format>syslog</log_format>
</localfile>
```

---

### 4. Start the Wazuh agent

Enable and start the agent service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Verify the agent is running and connected:

```bash
sudo systemctl status wazuh-agent
```

The agent should appear in the **Agents** section of the Wazuh dashboard within a few seconds.

---

### 5. Verify log ingestion

**5.1. Confirm rsyslog is writing remote logs**

Send a test syslog message from another machine (or use `logger` locally to simulate a remote host):

```bash
logger -n <SYSLOG_HOST_IP> -P 514 --udp "Test message from migration verification"
```

Verify the file was created and contains the message:

```bash
ls /var/log/remote/
tail -f /var/log/remote/<hostname>.log
```

**5.2. Confirm the Wazuh agent picks up the log**

Check the agent's internal log for logcollector activity:

```bash
sudo grep "logcollector" /var/ossec/logs/ossec.log | tail -20
```

You should see entries showing the agent reading from `/var/log/remote/*.log`.

**5.3. Confirm events appear in the Wazuh dashboard**

In the Wazuh dashboard, go to **Threat Intelligence** > **Events** and search for events with the `location` field matching `/var/log/remote/`. The same decoders that matched your devices in Wazuh 4.x will continue to fire, since the syslog message format is unchanged — only the ingestion path is different.

---

## Log rotation

With per-host log files accumulating under `/var/log/remote/`, configure logrotate to prevent unbounded disk growth.

Create `/etc/logrotate.d/wazuh-remote-syslog`:

```
/var/log/remote/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

---

## Decoder and rule compatibility

Existing Wazuh decoders and rules for network device syslog (for example, `cisco-ios`, `pf`, `juniper`) continue to work without modification. The syslog message body forwarded by rsyslog is identical to what `remoted` previously received on port 514. No decoder updates are required as part of this migration.

> **Note:** In Wazuh 4.x, the source IP of the remote device was available in `remoted` and could be used in rules. In Wazuh 5.x, the source IP is embedded in the syslog message itself by the device (standard syslog behavior), or can be added by rsyslog using the `%FROMHOST-IP%` template variable. If your rules relied on a remoted-injected source IP field, verify them after migration.
