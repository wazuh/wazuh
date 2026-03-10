# YARA Integration

## Introduction

YARA is a tool for identifying and classifying malware based on pattern-matching rules. Wazuh can integrate with YARA to scan files detected by the File Integrity Monitoring (FIM) module, providing automated malware detection and response.

The integration works by combining Wazuh FIM alerts with an active response script that invokes YARA to scan files that have been created or modified. When YARA identifies a match, Wazuh generates an alert containing the matched rule name and file details.

## Prerequisites

- YARA installed on the monitored endpoint.
- YARA rules files available on the endpoint.
- Wazuh FIM configured to monitor the target directories.
- Active response enabled on the Wazuh manager and agent.

## How it works

1. The Wazuh FIM module detects a new or modified file.
2. The FIM alert triggers an active response on the agent.
3. The active response script runs `yara` against the detected file using the configured YARA rules.
4. If YARA finds a match, the script sends the results back to the Wazuh manager.
5. The Wazuh rule engine processes the YARA scan results and generates an alert.

## Setup

### Install YARA on the endpoint

**Debian/Ubuntu:**

```bash
apt-get install -y yara
```

**RHEL/CentOS:**

```bash
yum install -y yara
```

**From source:**

```bash
wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz
tar -xzf v4.3.2.tar.gz
cd yara-4.3.2
./bootstrap.sh
./configure
make
make install
ldconfig
```

### Create YARA rules

Place your YARA rules in a directory on the endpoint, for example `/var/ossec/etc/yara/rules/`:

```bash
mkdir -p /var/ossec/etc/yara/rules
```

Example YARA rule file (`/var/ossec/etc/yara/rules/malware_rules.yar`):

```yara
rule suspicious_executable {
    meta:
        description = "Detects suspicious executable patterns"
        author = "Wazuh"
    strings:
        $s1 = "malicious_string" ascii
    condition:
        $s1
}
```

### Create the active response script

Create the YARA scan script on the agent at `/var/ossec/active-response/bin/yara.sh`:

```bash
#!/bin/bash

LOCAL=$(dirname $0)
cd $LOCAL
cd ../

PWD=$(pwd)

read INPUT_JSON
YARA_PATH="/usr/bin/yara"
YARA_RULES="/var/ossec/etc/yara/rules/"
FILENAME=$(echo $INPUT_JSON | jq -r '.parameters.alert.syscheck.path')

if [ ! -f "$FILENAME" ]; then
    exit 0
fi

yara_output=$("$YARA_PATH" -w -r "$YARA_RULES" "$FILENAME")

if [ -n "$yara_output" ]; then
    while IFS= read -r line; do
        rule=$(echo "$line" | awk '{print $1}')
        file=$(echo "$line" | awk '{print $2}')
        echo "wazuh-yara: info: $rule $file" >> ${PWD}/logs/active-responses.log
    done <<< "$yara_output"
fi

exit 0
```

Make the script executable:

```bash
chmod 750 /var/ossec/active-response/bin/yara.sh
chown root:wazuh /var/ossec/active-response/bin/yara.sh
```

### Configure FIM

Configure FIM on the agent to monitor directories where you want to detect malware. In the agent's `ossec.conf`:

```xml
<syscheck>
  <directories realtime="yes">/home,/tmp,/var/www</directories>
</syscheck>
```

### Configure active response

On the Wazuh manager, configure the active response to trigger the YARA script on FIM events. Add the following to the manager's `ossec.conf`:

```xml
<ossec_config>
  <command>
    <name>yara_scan</name>
    <executable>yara.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>yara_scan</command>
    <location>local</location>
    <rules_id>550,554</rules_id>
  </active-response>
</ossec_config>
```

Rule IDs `550` and `554` correspond to FIM alerts for file integrity changes.

### Create detection rules

Add custom rules on the Wazuh manager to process YARA scan output. Create or edit `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="yara,">
  <rule id="100200" level="0">
    <decoded_as>yara_decoder</decoded_as>
    <description>YARA grouping rule.</description>
  </rule>

  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <match>wazuh-yara: info:</match>
    <description>YARA: $(yara_rule) detected in $(yara_scanned_file).</description>
    <group>malware,</group>
  </rule>
</group>
```

### Create decoder

Add a custom decoder on the Wazuh manager. Create or edit `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="yara_decoder">
  <prematch>wazuh-yara:</prematch>
</decoder>

<decoder name="yara_decoder1">
  <parent>yara_decoder</parent>
  <regex>wazuh-yara: (\S+): (\S+) (\S+)</regex>
  <order>yara_level, yara_rule, yara_scanned_file</order>
</decoder>
```

## Verify the integration

Restart the Wazuh manager and the agent:

```bash
# On the manager
systemctl restart wazuh-manager

# On the agent
systemctl restart wazuh-agent
```

Test by creating a file that matches a YARA rule in a monitored directory. Verify that:

1. FIM generates an alert for the new file.
2. The active response triggers the YARA scan.
3. A YARA alert is generated if the file matches a rule.

> **Note**: YARA is not bundled with Wazuh and must be installed separately. The active response script and detection rules shown above are examples and should be adapted to your specific environment and YARA rule set.
