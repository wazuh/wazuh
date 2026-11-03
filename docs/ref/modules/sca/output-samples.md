# Output Samples

This document provides examples of SCA module output in both stateful and stateless formats based on actual SCA module logs.

---

## Stateful Event

Stateful events are persisted for reliable synchronization with the manager via Agent Sync Protocol.

The sample is check 28736 from a CIS Ubuntu 22.04 scan, a `none` check that failed. Long texts and
the compliance and MITRE lists are shortened.

```json
{
    "checksum": {
        "hash": {
            "sha1": "bb4ffdb5742ece030fbde6611f9ecc88f2208c6e"
        }
    },
    "check": {
        "compliance": {
            "cmmc": ["IA.L2-3.5.7"],
            "nist_800_53": ["AC-2", "IA-2", "IA-5"],
            "pci_dss": ["2.2.2", "8.3.5", "8.3.6"]
        },
        "condition": "none",
        "description": "The nullok argument overrides the default action of pam_unix.so to not permit the user access to a service if their official password is blank.",
        "id": "28736",
        "mitre": {
            "subtechnique": {
                "id": ["T1556.003"],
                "name": ["Pluggable Authentication Modules"]
            },
            "tactic": {
                "id": ["TA0006"],
                "name": ["Credential Access"]
            },
            "technique": {
                "id": ["T1556"],
                "name": ["Modify Authentication Process"]
            }
        },
        "name": "Ensure pam_unix does not include nullok.",
        "rationale": "Using a strong password is essential to helping protect personal and sensitive information from unauthorized access.",
        "reason": "Rules satisfied (condition 'none'):\nf:/etc/pam.d/common-auth -> !r:^# && r:pam_unix\\.so && r:nullok",
        "remediation": "Run the following command: # grep -PH -- '^\\h*([^#\\n\\r]+\\h+)?pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?nullok\\b' /usr/share/pam-configs/* Edit any files returned and remove the nullok argument for the pam_unix lines Example File: Name: Unix ...",
        "result": "Failed",
        "rules": [
            "f:/etc/pam.d/common-password -> !r:^# && r:pam_unix\\.so && r:nullok",
            "f:/etc/pam.d/common-auth -> !r:^# && r:pam_unix\\.so && r:nullok",
            "f:/etc/pam.d/common-account -> !r:^# && r:pam_unix\\.so && r:nullok",
            "f:/etc/pam.d/common-session -> !r:^# && r:pam_unix\\.so && r:nullok",
            "f:/etc/pam.d/common-session-noninteractive -> !r:^# && r:pam_unix\\.so && r:nullok"
        ]
    },
    "policy": {
        "description": "This document provides prescriptive guidance for establishing a secure configuration posture for Ubuntu Linux 22.04 LTS based on CIS benchmark for Ubuntu Linux 22.04 LTS.",
        "file": "cis_ubuntu22-04.yml",
        "id": "cis_ubuntu22-04",
        "name": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.",
        "references": ["https://www.cisecurity.org/cis-benchmarks/"]
    },
    "state": {
        "document_version": 2,
        "modified_at": "2026-10-16T20:12:22.145Z"
    }
}
```

A `none` check passes only when none of its rules is satisfied. Each rule here looks for
`pam_unix.so` with `nullok` on an uncommented line of one PAM file. `/etc/pam.d/common-auth` has it,
so that rule is satisfied, and that is what fails the check. `reason` lists it under
`Rules satisfied (condition 'none')`. The other four rules were not satisfied and are not listed.
See [Reading `reason`](architecture.md#reading-reason).

---

## Stateless Event

Stateless events are sent immediately through the message queue for real-time alerting.

### Check result changed

Check 28667 from the same scan, an `all` check that went from `Passed` to `Failed` after
`PASS_WARN_AGE` in `/etc/login.defs` was lowered to 3. Long texts and lists are shortened.

```json
{
    "collector": "check",
    "module": "sca",
    "data": {
        "event": {
            "changed_fields": ["check.result", "check.version"],
            "created": "2026-10-16T20:35:47.004Z",
            "type": "modified"
        },
        "check": {
            "checksum": "046dad0c60ebaca58c9aa9fc5ee8e876caac5d6a",
            "compliance": {
                "cmmc": ["AC.L2-3.1.1", "AC.L2-3.1.2", "CM.L2-3.4.1"],
                "nist_800_53": ["CM-7", "CM-9"],
                "pci_dss": ["1.1.1", "1.2.1", "1.2.6"]
            },
            "condition": "all",
            "description": "The PASS_WARN_AGE parameter in /etc/login.defs allows an administrator to notify users that their password will expire in a defined number of days. ...",
            "id": "28667",
            "mitre": {
                "tactic": {
                    "id": ["TA0005"],
                    "name": ["Stealth"]
                },
                "technique": {
                    "id": ["T1036", "T1564"],
                    "name": ["Masquerading", "Hide Artifacts"]
                }
            },
            "name": "Ensure password expiration warning days is configured.",
            "previous": {
                "result": "Passed",
                "version": 2
            },
            "rationale": "Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password ...",
            "reason": "Rules not satisfied (condition 'all'):\nf:/etc/login.defs -> n:^\\s*\\t*PASS_WARN_AGE\\s*\\t*(\\d+) compare >= 7",
            "remediation": "Edit /etc/login.defs and set PASS_WARN_AGE to a value of 7 or more that follows local site policy: Example: PASS_WARN_AGE 7 Run the following command to modify ...",
            "result": "Failed",
            "rules": [
                "f:/etc/login.defs -> n:^\\s*\\t*PASS_WARN_AGE\\s*\\t*(\\d+) compare >= 7",
                "not f:/etc/shadow -> !r:^[\\w@-]+:[*!+-]: && n:^[\\w@-]+:\\S*:\\d*:\\d*:\\d*:(\\d+) compare < 7"
            ],
            "version": 3
        },
        "policy": {
            "description": "This document provides prescriptive guidance for establishing a secure configuration posture for Ubuntu Linux 22.04 LTS based on CIS benchmark for Ubuntu Linux 22.04 LTS.",
            "file": "cis_ubuntu22-04.yml",
            "id": "cis_ubuntu22-04",
            "name": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0.",
            "references": ["https://www.cisecurity.org/cis-benchmarks/"]
        }
    }
}
```

An `all` check passes only when every rule is satisfied. The first rule, a warning of at least 7
days, no longer is, so it is listed under `Rules not satisfied (condition 'all')`. The second rule
still holds and is not listed.

### Policy changed

```json
{
    "collector": "policy",
    "module": "sca",
    "data": {
        "event": {
            "changed_fields":
            [
                "policy.description"
            ],
            "created": "2025-04-16T12:10:01.486Z",
            "type": "modified"
        },
        "check":
        {
            "compliance":
            {
                "pci_dss": ["2.2.4"],
                "nist_800_53": ["CM.1"]
            },
            "condition": "all",
            "description": "Disabling SMBv1 mitigates known vulnerabilities.",
            "id": "CUST001",
            "mitre":
            {
                "tactic":
                {
                    "id": ["TA0008"],
                    "name": ["Lateral Movement"]
                },
                "technique":
                {
                    "id": ["T1021"],
                    "name": ["Remote Services"]
                }
            },
            "name": "Ensure SMBv1 is disabled.",
            "rationale": "SMBv1 is outdated and insecure.",
            "reason": "Rules not satisfied (condition 'all'):\nr:HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> n:SMB1 compare == 0",
            "references":
            [
                "https://internal.docs/policies/windows"
            ],
            "remediation": "Set 'SMB1' registry key to 0.",
            "result": "Failed",
            "rules":
            [
                "r:HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> n:SMB1 compare == 0"
            ]
        },
        "policy":
        {
            "description": "Custom internal hardening guidelines for Windows systems",
            "file": "custom_windows_policy.yml",
            "id": "custom_policy_win",
            "name": "Custom Windows Hardening Policy",
            "previous":
            {
                "description": "Custom internal hardening guidelines for Windows"
            },
            "references":
            [
                "https://internal.docs/policies/windows"
            ]
        }
    }
}
```
