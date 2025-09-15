# Database Schema

The SCA module uses SQLite database to store policy metadata and check results. The database maintains the state of security configuration assessments and enables change detection between scans.

---

## Tables

### Policy Table

```sql
CREATE TABLE IF NOT EXISTS sca_policy (
    id TEXT PRIMARY KEY,
    name TEXT,
    file TEXT,
    description TEXT,
    refs TEXT
);
```

This table stores data for each security policy used in the SCA module, including its unique ID, name, source file, description, and external references.

| Mandatory | Column        | Data Type | Description                                           | ECS Mapping | ECS Data Type |
| :-------: | ------------- | --------- | ----------------------------------------------------- | ----------- | ------------- |
|     ✔️    | `id`          | TEXT      | Unique identifier of the policy                      | policy.id   | keyword       |
|           | `name`        | TEXT      | Human-readable name of the policy                    | policy.name | keyword       |
|           | `file`        | TEXT      | Path to the policy definition file                   | policy.file | keyword       |
|           | `description` | TEXT      | Description of the policy purpose and content        | policy.description | text    |
|           | `refs`        | TEXT      | External references related to the policy (e.g. CIS) | policy.references | keyword  |

**Indexes:**
- Primary key on `id` for fast policy lookups
- Index on `file` for policy file tracking

**Example Data:**
```sql
INSERT INTO sca_policy VALUES (
    'cis_debian10',
    'CIS Debian Linux 10 Benchmark v1.0.0',
    'etc/shared/cis_debian10.yml',
    'This document provides prescriptive guidance for establishing a secure configuration posture for Debian Linux 10',
    'https://www.cisecurity.org/cis-benchmarks/'
);
```

---

### Check Table

```sql
CREATE TABLE IF NOT EXISTS sca_check (
    id TEXT PRIMARY KEY,
    policy_id TEXT REFERENCES sca_policy(id),
    name TEXT,
    description TEXT,
    rationale TEXT,
    remediation TEXT,
    refs TEXT,
    result TEXT DEFAULT 'Not run',
    reason TEXT,
    condition TEXT,
    compliance TEXT,
    rules TEXT
);
```

This table stores individual checks associated with a policy. Each check includes metadata, logic conditions, rules to be evaluated, and tracking fields for results and compliance.

| Mandatory | Column        | Data Type | Description                                                               | ECS Mapping | ECS Data Type |
| :-------: | ------------- | --------- | ------------------------------------------------------------------------- | ----------- | ------------- |
|     ✔️    | `id`          | TEXT      | Unique identifier of the check                                           | check.id    | keyword       |
|     ✔️    | `policy_id`   | TEXT      | Reference to the associated policy ID                                    | policy.id   | keyword       |
|           | `name`        | TEXT      | Short name summarizing the check                                         | check.name  | keyword       |
|           | `description` | TEXT      | Detailed explanation of what the check evaluates                         | check.description | text    |
|           | `rationale`   | TEXT      | Justification or reason behind the check                                 | check.rationale | text      |
|           | `remediation` | TEXT      | Instructions for correcting a failed check                               | check.remediation | text    |
|           | `refs`        | TEXT      | External references related to the check                                 | check.references | keyword  |
|           | `result`      | TEXT      | Current evaluation result (Passed, Failed, Not run, Not applicable)      | check.result | keyword      |
|           | `reason`      | TEXT      | Explanation for the check's result                                       | check.reason | text         |
|           | `condition`   | TEXT      | Logical condition under which the check applies (all, any, none)        | check.condition | keyword    |
|           | `compliance`  | TEXT      | Compliance mapping (e.g., CIS ID, NIST tag)                             | check.compliance | keyword   |
|           | `rules`       | TEXT      | Serialized rule(s) logic used to perform the actual check               | check.rules | text          |

**Indexes:**
- Primary key on `id` for fast check lookups
- Foreign key on `policy_id` for policy-check relationships
- Index on `result` for filtering by check status
- Composite index on `(policy_id, result)` for policy-specific result queries

**Result Values:**
- `Not run`: Check has not been executed yet
- `Passed`: Check passed successfully
- `Failed`: Check failed
- `Not applicable`: Check is not applicable to this system

**Example Data:**
```sql
INSERT INTO sca_check VALUES (
    '5501',
    'cis_debian10',
    'Ensure permissions on /etc/ssh/sshd_config are configured',
    'The /etc/ssh/sshd_config file contains configuration specifications for sshd',
    'The /etc/ssh/sshd_config file needs to be protected from unauthorized changes',
    'Run: chmod og-rwx /etc/ssh/sshd_config',
    'https://www.cisecurity.org',
    'Passed',
    NULL,
    'all',
    'cis:5.2.1,cis_csc:14.6',
    '[{"type":"file","path":"/etc/ssh/sshd_config","permissions":"600"}]'
);
```

---

## Relationships

### Policy-Check Relationship
- **Type**: One-to-Many
- **Description**: Each policy contains multiple checks
- **Foreign Key**: `sca_check.policy_id` references `sca_policy.id`
- **Cascade**: When a policy is deleted, all associated checks are deleted

---

## State Management

### Change Detection
The database enables change detection by:
1. Storing previous check results
2. Comparing new scan results with stored state
3. Generating appropriate events (create, update, delete)
4. Tracking result transitions (e.g., Passed → Failed)

### Result Persistence
- Results persist across agent restarts
- Database acts as source of truth for check states
- Enables historical tracking of compliance status
