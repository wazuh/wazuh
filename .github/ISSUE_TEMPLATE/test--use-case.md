---
name: 'Test: Use case'
about: Test suite for grouping different use cases
title: ''
labels: ''
assignees: ''

---

# Testing: Use case

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Bruteforce Attack - Linux agent

- [ ] Trigger an alert of bruteforce attack (5712) for a Linux agent.

## Bruteforce Attack - Windows agent

- [ ] Trigger an alert of bruteforce attack (18152) for a Windows agent.

# Audit user actions - Linux agent

- [ ] Trigger an alert about audit events (rules are located at 0365-auditd_rules.xml).
- [ ] Check that values at the CDB list `audit-keys` are matched correctly (rule 80792).

# Netcat- Linux agent

- [ ] Create a localfile command to collect the list of opened processes.
- [ ] Create a custom rule to catch if netcat is running in the previous processes list.

# Shellshock detection - Linux agent

- [ ] Detect a shellshock attack with Apache logs.

https://documentation.wazuh.com/current/learning-wazuh/shellshock.html

# IP reputation - Linux agent

- [ ] Create a CDB list containing a black list of IP addresses.
- [ ] Create a custom rule to look for malicious IPs in that CDB list.
- [ ] Use the `firewall-drop.sh` script to block the IP when the rule is generated.

# Changing Windows audit policy - Windows agent

- [ ] Check the rule 18113 (< 3.8.0) or 20053 (>= 3.8.0) is triaged when modifying a Windows security policy.

# FIM - Windows agent

- [ ] Create, modify, delete and change the attributes of a file monitored by FIM.

# FIM - Linux agent

- [ ] Create, modify, delete and change the permissions and owner of a monitored file.

# Rootkit detection - Linux agent

- [ ] Use the rootkit Diamorphine to hide a running process.
- [ ] Get the _hidden process_ alert by a Rootcheck scan.

https://github.com/m0nad/Diamorphine

# Detecting a trojan - Linux agent

- [ ] Detect a trojan with Rootcheck by scanning the file `rootkit_trojans.txt`.

# OpenSCAP SSG AND CVE - Linux agent (RedHat 7/CentOS 7)

- [ ] Perform an OpenScap scan with the following configuration.

```
<wodle name="open-scap">
    <disabled>no</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <content type="xccdf" path="ssg-rhel-7-ds.xml">
        <profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
        <profile>xccdf_org.ssgproject.content_profile_common</profile>
    </content>
    <content type="xccdf" path="cve-redhat-7-ds.xml"/>
</wodle>
```

- [ ] Check alerts from both scans are generated.

# Virustotal integration - Manager

- [ ] Enable the VirusTotal integration.
- [ ] Create a custom rule to detect when a file monitored by FIM is created in `/tmp`.
- [ ] In the agent side, insert a known malware into the `/tmp` folder.

# API - Manager

- [ ] Install the API in the manager.
- [ ] From a browser, do the following checks:

- Check the active agents. (http://localhost:55000/agents?status=active)
- Look for Apache rules in a range of levels. (http://localhost:55000/rules?search=apache&level=7-15)
- Read the Syscheck configuration. (http://localhost:55000/manager/configuration?section=syscheck)
- Read the Rootcheck database of an agent. (http://localhost:55000/rootcheck/001)
- Read the Syscheck database of an agent. (http://localhost:55000/syscheck/001)

# Remote upgrades

- [ ] Create a custom WPK with a future version of Wazuh.
- [ ] Upgrade an agent to that version.
- [ ] Downgrade the agent to the current stable version by the official repository.

Here you can find a guide to create a custom WPK easily:
https://documentation.wazuh.com/current/user-manual/agents/remote-upgrading/create-custom-wpk.html

# Anti flooding mechanisms - Linux agent

- [ ] Flood the agent queue and see flooding alerts.

# Analysisd performance - Manager

- [ ] Use the script `queue.py` to test the Analisys daemon performance.

https://github.com/wazuh/wazuh-tools/blob/master/utils/queue.py
