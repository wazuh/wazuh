# Active Response Configuration Reference

Complete configuration reference for Active Response.

The active response module enables automatic execution of scripts in response to detected threats. The agent executes response commands sent by the manager when specific conditions are met. This module is available on both managers and agents, though execution typically occurs on agents.

For module overview and architecture, see [Active Response Module](index.html).

---

## Agent Configuration

**Configuration file:** `/var/ossec/etc/ossec.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\ossec.conf` (Windows)

**XML Section:** `<active-response>`

**Module:** Agent-only

**Internal Options:** `execd.*`

The agent configuration controls whether the agent will execute active response commands received from the manager.

### disabled

Enable or disable active response execution on this agent.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When set to `yes`, the agent will not execute any active response scripts, even if the manager sends commands

---

## Agent Configuration Examples

### Default Configuration

Allow this agent to execute active response scripts (enabled):

```xml
<active-response>
  <disabled>no</disabled>
</active-response>
```

### Disable Active Response

Prevent this agent from executing any active response scripts:

```xml
<active-response>
  <disabled>yes</disabled>
</active-response>
```

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<active-response>` (for defining response triggers)

Active response scripts and triggers are defined on the manager. The manager analyzes events and sends execution commands to agents when conditions match.

For manager-side active response configuration, see:
- [Active Response Executables](executables.md) - Available response scripts
- [Active Response Architecture](architecture.md) - How active response works
- [Manager Configuration Reference](../../configuration/manager/README.md) - Manager configuration

---

## Internal Options

Additional active response settings can be configured in `internal_options.conf` (agent) or `local_internal_options.conf`:

### Agent-Side Internal Options

Active response execution daemon (execd) runs on agents and has the following internal options:

```ini
# Active response debug level (0-2)
execd.debug=0

# Maximum restart lock attempts (default: 10)
execd.max_restart_lock=10
```


---

## Behavior

### Agent-Side Execution Flow

1. **Manager trigger:** Manager detects condition (e.g., failed login, malware detection) and sends active response command to agent
2. **Agent receives:** Agent daemon (execd) receives command via secure channel
3. **Check enabled:** Agent checks if `<active-response><disabled>` is `no`
4. **Script lookup:** Agent locates the specified script in `/var/ossec/active-response/bin/`
5. **Execute script:** If enabled, agent executes the script with provided parameters
7. **Report back:** Agent reports execution status to manager

### Command Format

Active response commands sent from manager to agent follow this format:

```
<action> <command> <timeout> <parameters>
```

**Actions:**
- `add` - Execute the response action (e.g., block IP, disable user)
- `delete` - Reverse the response action (e.g., unblock IP, re-enable user)

**Example commands:**
```
add firewall-drop 600 192.168.1.100
delete firewall-drop 0 192.168.1.100
```

### Script Execution Environment

Active response scripts run with:
- **Privileges:** Root/administrator privileges
- **Working directory:** `/var/ossec/active-response/bin/`
- **Standard input:** Command parameters passed via stdin in JSON format

---

## Active Response Scripts

### Script Location

**Agent:**
- Linux/Unix: `/var/ossec/active-response/bin/`
- Windows: `C:\Program Files (x86)\ossec-agent\active-response\bin\`

**Common scripts:**
- `firewall-drop` - Block IP address at firewall level
- `host-deny` - Add IP to `/etc/hosts.deny`
- `disable-account` - Disable user account
- `restart-wazuh` - Restart Wazuh agent
- `route-null` - Null-route IP address

### Script Requirements

Active response scripts must:
- Be executable by the wazuh user
- Accept parameters via standard input (JSON format)
- Handle both `add` and `delete` actions
- Complete within the timeout period
- Return appropriate exit codes (0=success, non-zero=failure)

---

## Security Considerations

### Agent-Side Security

- Active response scripts run with root/administrator privileges
- Only disable active response if you have a specific security policy requiring it
- Scripts are executed in a controlled environment with timeouts
- Concurrent execution is limited to prevent resource exhaustion
- Commands are authenticated and come only from the registered manager

### Script Security

- Only install trusted active response scripts from verified sources
- Validate all script inputs to prevent injection attacks
- Test scripts thoroughly in a staging environment before deployment
- Monitor active response executions for anomalies
- Regularly audit installed scripts for unauthorized modifications

### Best Practices

- Use hash verification for script integrity (check before execution)
- Implement proper error handling in custom scripts
- Log all script actions for audit trails
- Set appropriate file permissions (750, root:wazuh)
- Review and test timeout settings for your environment

---

## Performance Considerations

### Script Timeouts

Script timeout is configured per active-response in the XML configuration using the `<timeout>` option:

- **Simple scripts (firewall rules):** 30-60 seconds
- **Complex scripts (account management, API calls):** 120-300 seconds
- **Default:** 60 seconds (if not specified)

Configure timeout in the `<active-response>` XML block, not in internal options.

---

## Troubleshooting

### Active Response Not Executing on Agent

**Check if disabled:**
```bash
# On Linux/Unix agent
grep -A2 "active-response" /var/ossec/etc/ossec.conf

# On Windows agent
findstr /C:"active-response" "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

**Check agent logs:**
```bash
# On Linux/Unix
tail -f /var/ossec/logs/active-responses.log

# On Windows
type "C:\Program Files (x86)\ossec-agent\active-responses.log"
```

**Verify execd is running:**
```bash
# On Linux/Unix
/var/ossec/bin/wazuh-control status | grep execd

# On Windows
sc query WazuhSvc
```

**Check internal options:**
```bash
# Verify active response is enabled globally
```

### Script Execution Timeouts

**Increase timeout in internal options:**

```ini
# internal_options.conf or local_internal_options.conf
```

**Check script execution time:**
```bash
# Test script manually to measure runtime
time /var/ossec/active-response/bin/script.sh add - 600 192.168.1.100
```

### Permission Errors

**Verify script permissions:**
```bash
# Scripts should be executable by root/wazuh
ls -l /var/ossec/active-response/bin/

# Fix permissions if needed
chmod 750 /var/ossec/active-response/bin/*
chown root:wazuh /var/ossec/active-response/bin/*
```

**Check SELinux/AppArmor:**
```bash
# On systems with SELinux
getenforce
ausearch -m avc -ts recent | grep execd

# On systems with AppArmor
aa-status | grep wazuh
```

### Script Not Found Errors

**Verify script exists:**
```bash
ls -l /var/ossec/active-response/bin/script-name.sh
```

**Check manager configuration:**
```bash
# Verify script name matches manager configuration
grep -A5 "<command>" /var/wazuh-manager/etc/wazuh-manager.conf
```

### Too Many Concurrent Executions

**Monitor active executions:**
```bash
# Count running active response processes
ps aux | grep active-response | wc -l
```

**Note:** There is no internal option to limit concurrent executions - this is controlled by the system and active-response design.

---

## Monitoring

### View Active Response Logs

**Agent logs:**
```bash
# Linux/Unix
tail -f /var/ossec/logs/active-responses.log

# Windows
type "C:\Program Files (x86)\ossec-agent\active-responses.log"
```

**Manager logs:**
```bash
tail -f /var/wazuh-manager/logs/active-responses.log
```

### Check Recent Executions

```bash
# View recent active response executions
grep "active-response" /var/ossec/logs/ossec.log | tail -20

# View specific script executions
grep "firewall-drop" /var/ossec/logs/active-responses.log
```

### Monitor for Failures

```bash
# Search for failed executions
grep -i "error\|fail" /var/ossec/logs/active-responses.log

# Count failures by script
grep -i "error" /var/ossec/logs/active-responses.log | awk '{print $NF}' | sort | uniq -c
```

---

## Advanced Configuration

### Selective Active Response

Disable active response on specific agents while keeping it enabled on others:

**Agent A (production database server) - Disabled:**
```xml
<active-response>
  <disabled>yes</disabled>
</active-response>
```

**Agent B (web server) - Enabled:**
```xml
<active-response>
  <disabled>no</disabled>
</active-response>
```

### Debug Mode

Enable detailed logging for troubleshooting:

```ini
# local_internal_options.conf
execd.debug=2
```

View detailed logs:
```bash
tail -f /var/ossec/logs/ossec.log | grep execd
```

### Custom Timeout per Script


```bash
#!/bin/bash
# Custom script with internal timeout
timeout 30 /path/to/actual-command
```

---

## See Also

- [Active Response Module](index.html) - Module overview and architecture
- [Active Response Architecture](architecture.md) - How active response works
- [Active Response Executables](executables.md) - Available response scripts
- [Manager Configuration Reference](../../configuration/manager/README.md) - Manager active response configuration
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options
