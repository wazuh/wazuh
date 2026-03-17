# MITRE ATT&CK Framework

## Introduction

Wazuh integrates with the [MITRE ATT&CK](https://attack.mitre.org/) framework to map security alerts to known adversary tactics, techniques, and procedures (TTPs). This integration helps security teams understand the nature and context of detected threats by relating them to the MITRE ATT&CK knowledge base.

The MITRE ATT&CK framework organizes adversary behavior into:

- **Tactics**: The adversary's tactical goals (for example, Initial Access, Execution, Persistence).
- **Techniques**: How the adversary achieves each tactical goal (for example, Phishing, Command-Line Interface).
- **Sub-techniques**: More specific variations of techniques.

## How it works

Wazuh rules can include MITRE ATT&CK identifiers that map alerts to specific tactics and techniques. When a rule triggers, the generated alert includes the MITRE ATT&CK metadata, enabling correlation with the framework.

### MITRE ATT&CK data

Wazuh ships with the MITRE ATT&CK Enterprise matrix data in STIX 2.0 format:

```
ruleset/mitre/enterprise-attack.json
```

This file contains the complete set of tactics, techniques, and sub-techniques from the MITRE ATT&CK Enterprise matrix.

## Rule mapping

Wazuh rules use the `<mitre>` tag to map alerts to MITRE ATT&CK identifiers.

### Example rule with MITRE mapping

```xml
<rule id="5710" level="5">
  <if_sid>5700</if_sid>
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user.</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>authentication_failed,</group>
</rule>
```

In this example, `T1110` maps to the **Brute Force** technique under the **Credential Access** tactic.

### MITRE tags in rules

The `<mitre>` section in a rule supports one or more technique IDs:

```xml
<mitre>
  <id>T1078</id>
  <id>T1110.001</id>
</mitre>
```

- `T1078` maps to **Valid Accounts**.
- `T1110.001` maps to **Brute Force: Password Guessing** (a sub-technique).

## Built-in MITRE mappings

Many Wazuh built-in rules already include MITRE ATT&CK mappings. These rules cover common detection scenarios:

| Tactic | Example techniques | Rule coverage |
|--------|-------------------|---------------|
| Initial Access | T1190 (Exploit Public-Facing Application) | Web attack rules |
| Execution | T1059 (Command and Scripting Interpreter) | Script execution rules |
| Persistence | T1098 (Account Manipulation) | User management rules |
| Privilege Escalation | T1548 (Abuse Elevation Control Mechanism) | Sudo/privilege rules |
| Defense Evasion | T1070 (Indicator Removal) | Log clearing rules |
| Credential Access | T1110 (Brute Force) | Authentication failure rules |
| Lateral Movement | T1021 (Remote Services) | SSH/RDP connection rules |
| Collection | T1005 (Data from Local System) | FIM and data access rules |

## Alert output

When a rule with MITRE ATT&CK mapping triggers, the alert includes the MITRE metadata:

```json
{
  "rule": {
    "mitre": {
      "id": ["T1110"],
      "tactic": ["Credential Access"],
      "technique": ["Brute Force"]
    },
    "description": "sshd: Attempt to login using a non-existent user.",
    "id": "5710",
    "level": 5
  }
}
```

## Custom MITRE mappings

To add MITRE ATT&CK mappings to custom rules, include the `<mitre>` tag with the appropriate technique ID(s):

```xml
<group name="custom,">
  <rule id="100300" level="10">
    <decoded_as>json</decoded_as>
    <field name="action">delete</field>
    <description>Sensitive file deletion detected.</description>
    <mitre>
      <id>T1485</id>
    </mitre>
  </rule>
</group>
```

`T1485` maps to the **Data Destruction** technique under the **Impact** tactic.

## SCA compliance mapping

Wazuh Security Configuration Assessment (SCA) policies also reference MITRE ATT&CK techniques in their compliance mappings. For example, CIS benchmark checks can be mapped to relevant MITRE techniques to provide additional context about the security impact of configuration weaknesses.

## Reference

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- MITRE ATT&CK data file: `ruleset/mitre/enterprise-attack.json`
