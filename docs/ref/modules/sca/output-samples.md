# Output Samples

This document provides examples of SCA module output in both stateful and stateless formats based on actual SCA module logs.

---

## Stateful Event

Stateful events are persisted for reliable synchronization with the manager via Agent Sync Protocol.

```json
{
    "checksum": {
        "hash": {
            "sha1": "b4c17ea41d2b1af7079625095f2770d668079aad"
        }
    },
    "check":
    {
        "compliance":
        [
            "int:2.1.1"
        ],
        "condition": "all",
        "description": "Disabling SMBv1 mitigates known vulnerabilities.",
        "id": "CUST001",
        "name": "Ensure SMBv1 is disabled.",
        "rationale": "SMBv1 is outdated and insecure.",
        "reason": null,
        "references":
        [
            "https://internal.docs/policies/windows"
        ],
        "remediation": "Set 'SMB1' registry key to 0.",
        "result": "Not run",
        "rules":
        [
            "r:HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> n:SMB1 compare == 0"
        ]
    },
    "policy":
    {
        "description": "Custom internal hardening guidelines for Windows",
        "file": "custom_windows_policy.yml",
        "id": "custom_policy_win",
        "name": "Custom Windows Hardening Policy",
        "references":
        [
            "https://internal.docs/policies/windows"
        ]
    },
    "state":
    {
        "modified_at": "2025-04-16T12:10:01.486Z"
    }
}
```

---

## Stateless Event

Stateless events are sent immediately through the message queue for real-time alerting.

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
            [
                "int:2.1.1"
            ],
            "condition": "all",
            "description": "Disabling SMBv1 mitigates known vulnerabilities.",
            "id": "CUST001",
            "name": "Ensure SMBv1 is disabled.",
            "rationale": "SMBv1 is outdated and insecure.",
            "reason": null,
            "references":
            [
                "https://internal.docs/policies/windows"
            ],
            "remediation": "Set 'SMB1' registry key to 0.",
            "result": "failed",
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
