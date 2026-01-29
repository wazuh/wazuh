# Database Schema

The SCA module uses SQLite database to store policy metadata and check results. The database maintains the state of security configuration assessments and enables change detection between scans.

## Wazuh Common Schema (WCS)

The schema according to the Wazuh Common Schema (WCS) is available in `src/external/indexer-plugins` and is downloaded during the agent build process as part of external dependencies (`make deps`):

- `sca.json`

This schema defines the standardized format for SCA data that is sent to the Wazuh indexer.

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
    checksum TEXT NOT NULL,
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
    rules TEXT,
    regex_type TEXT DEFAULT 'pcre2',
    version INTEGER NOT NULL DEFAULT 1,
    sync INTEGER NOT NULL DEFAULT 0
);
```

This table stores individual checks associated with a policy. Each check includes metadata, logic conditions, rules to be evaluated, and tracking fields for results and compliance.

| Mandatory | Column        | Data Type | Description                                                               | ECS Mapping | ECS Data Type |
| :-------: | ------------- | --------- | ------------------------------------------------------------------------- | ----------- | ------------- |
|     ✔️    | `checksum`    | TEXT      | SHA1 checksum of the check data used for synchronization                 | checksum.hash.sha1 | keyword |
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
|           | `regex_type`  | TEXT      | Internal regex engine identifier for rule evaluation                    | N/A         | N/A          |
|     ✔️    | `version`     | INTEGER   | Monotonic version for stateful synchronization                          | state.document_version | long |
|     ✔️    | `sync`        | INTEGER   | Internal sync flag (1 = synced, 0 = local-only)                         | N/A         | N/A          |

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
INSERT INTO sca_check (checksum, id, policy_id, name, description, rationale, remediation, refs, result, reason,
                       condition, compliance, rules, regex_type, version, sync)
VALUES (
    'f1e2d3c4b5a697887766554433221100aabbccdd',
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
    '[{"type":"file","path":"/etc/ssh/sshd_config","permissions":"600"}]',
    'pcre2',
    1,
    1
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

### Metadata Table

```sql
CREATE TABLE IF NOT EXISTS sca_metadata (
    key TEXT PRIMARY KEY,
    value INTEGER
);
```

This table stores module-level metadata for tracking operational state, such as the last integrity check timestamp.

| Mandatory | Column  | Data Type | Description                                     |
| :-------: | ------- | --------- | ----------------------------------------------- |
|     ✔️    | `key`   | TEXT      | Unique identifier for the metadata entry        |
|           | `value` | INTEGER   | Numeric value associated with the key           |

**Current Keys:**
- `last_integrity_check`: Unix timestamp (seconds since epoch) of the last integrity check

**Example Data:**
```sql
INSERT INTO sca_metadata VALUES ('last_integrity_check', 1733316000);
```

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
