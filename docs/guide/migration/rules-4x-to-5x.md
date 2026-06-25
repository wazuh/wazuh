# Migrating rules from Wazuh 4.x (XML) to Wazuh 5.x (YAML)

## Overview

Wazuh 5.0 introduces a fundamentally different architecture for log analysis and threat detection. The legacy XML-based analysis daemon is replaced by a pipeline that separates **event processing** from **threat detection**:

1. **Wazuh Engine** — Receives raw logs, decodes them using the new decoder format, normalizes fields to the [Wazuh Common Schema (WCS)](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/wcs/stateless/events/main/docs/README.md), and indexes the resulting events into `wazuh-events-v5-*` indices.
2. **Security Analytics detectors** — Use a percolator to evaluate indexed events against Sigma-based (YAML) rules stored in the `wazuh-threatintel-rules` index. When an event matches a rule, the detector creates a **finding**, an enriched copy of the event, indexed into `wazuh-findings-v5-*`.

There is no automatic conversion tool. Rules must be manually rewritten following this guide.

### Terminology changes

| 4.x term | 5.x term | Description |
|---|---|---|
| **Event** | **Event** | The base log entry after decoding. In 4.x the events are the base logs before matching any rule. In 5.x, the Wazuh Engine produces normalized events. |
| **Alert** | **Finding** | In 5.x, when an event matches a detection rule, a finding is generated and the event is enriched. |
| **Rule (XML)** | **Rule (YAML)** | Detection rules are now written in the Sigma format with Wazuh extensions. |
| **Decoder (XML)** | **Decoder (Engine format)** | Decoders still exist but use a new format adapted to the Wazuh Engine. |
| **Ruleset files on disk** | **Threat intelligence indices** | Rules, KVDBs, decoders, integrations, and enrichments are stored in Wazuh indices (`wazuh-threatintel-*`). |

### Content architecture

In 5.x, detection content is organized into **integrations**, which bundle related decoders, KVDBs and rules:

```
Integration (e.g., "o365")
├── Decoders — Parse raw logs into WCS-normalized events
├── Rules — YAML detection rules
├── KVDBs — Key-Value Databases used as lookup tables during decoding
└── Category — Determines the event index (e.g., "cloud-services" → wazuh-events-v5-cloud-services-*)
```

Integrations are stored in the `wazuh-threatintel-integrations` index. Each integration has a `category` field that maps to a specific event index:

| Integration category | Event index | Findings index |
|---|---|---|
| `security` | `wazuh-events-v5-security-*` | `wazuh-findings-v5-security-*` |
| `system-activity` | `wazuh-events-v5-system-activity-*` | `wazuh-findings-v5-system-activity-*` |
| `cloud-services` | `wazuh-events-v5-cloud-services-*` | `wazuh-findings-v5-cloud-services-*` |
| `applications` | `wazuh-events-v5-applications-*` | `wazuh-findings-v5-applications-*` |
| `network-activity` | `wazuh-events-v5-network-activity-*` | `wazuh-findings-v5-network-activity-*` |
| `access-management` | `wazuh-events-v5-access-management-*` | `wazuh-findings-v5-access-management-*` |
| `other` | `wazuh-events-v5-other-*` | `wazuh-findings-v5-other-*` |
| `unclassified` | `wazuh-events-v5-unclassified-*` | `wazuh-findings-v5-unclassified-*` |

### Spaces and content lifecycle

All content (rules, decoders, integrations, KVDBs) exists within a **space** that determines its lifecycle stage:

| Space | Type | Description |
|---|---|---|
| **Standard** | Default | Out-of-the-box content provided by Wazuh. Users can disable items but cannot modify them. |
| **Draft** | User | Initial workspace for creating new content. Rules in draft are not evaluated. |
| **Test** | User | Content is loaded into the Engine so it can be validated using logtest. Rules are not yet active in production detectors. |
| **Custom** | User | Production-ready user content. Rules in this space can be assigned to detectors for active threat detection. |

The promotion path for user-created content is: **Draft → Test → Custom**.

### Key architectural differences

| Aspect | 4.x (XML) | 5.x (YAML) |
|---|---|---|
| **Format** | XML files on disk (`/var/ossec/ruleset/rules/`) | JSON documents in Wazuh indices (`wazuh-threatintel-rules`) |
| **Processing** | Single analysis daemon handles decoding + rule matching | Wazuh Engine decodes and indexes events; Security Analytics detectors match rules via percolator queries |
| **Output** | Alerts | Events (all decoded logs) + Findings (events that matched a rule) |
| **Rule identification** | Numeric ID (1–999999) | UUID, auto-assigned by the system on creation |
| **Severity** | Numeric level 0–16 | Keyword: `informational`, `low`, `medium`, `high`, `critical` |
| **Detection logic** | Decoder fields + regex matching + parent rule chaining | Sigma detection blocks with selections, conditions, and value modifiers |
| **Rule chaining** | `if_sid`, `if_group`, `if_level`, `if_matched_sid` | Not supported — each rule is self-contained |
| **Correlation** | `frequency`, `timeframe`, `same_*`, `different_*` | Not natively supported in the rule format |
| **Field schema** | Custom decoder-extracted fields — open-ended, no validation | Wazuh Common Schema (WCS) fields — validated closed set; unknown fields are rejected at creation |
| **Compliance mapping** | Embedded in `<group>` tag as CSV | Dedicated `compliance` object with structured fields |
| **MITRE mapping** | `<mitre><id>` tags inside rule | Dedicated `mitre` object with arrays of tactic, technique, and subtechnique IDs |
| **Management** | File edits + manager restart | API / index operations, no restart required |
| **Custom rules** | `/var/ossec/etc/rules/local_rules.xml` | Documents promoted through Draft → Test → Custom spaces |
| **Rule state** | Active when loaded (or `noalert`) | `enabled: true/false` field per rule |

---

## Rule structure comparison

### 4.x XML rule structure

```xml
<group name="syslog,sshd,">
  <rule id="5710" level="5">
    <if_sid>5700</if_sid>
    <match>illegal user|invalid user</match>
    <field name="alert_type">normal</field>
    <srcip>!192.168.1.0/24</srcip>
    <description>sshd: Attempt to login using a non-existent user</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>invalid_login,authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>
</group>
```

### 5.x YAML rule structure

Rules are written in Sigma format. The rule content is submitted to the Content Manager API; the system assigns a UUID on creation. The `sigma_id` field is optional and can carry a reference to the upstream Sigma rule origin.

```yaml
sigma_id: "d166d57a-86e3-49b4-b560-db423b3c156a"   # optional cross-reference
enabled: true
status: "experimental"      # experimental | test | stable
level: "high"               # informational | low | medium | high | critical

metadata:
  title: "SSH login attempt with non-existent user"
  author: "Wazuh, Inc."
  date: "2026-04-14"
  modified: "2026-04-14"
  description: "Detects SSH authentication attempts using usernames that do not exist on the system."
  references:
    - "https://documentation.wazuh.com/current/..."

logsource:
  product: "sshd"
  service: "sshd"

detection:
  condition: "selection"
  selection:
    event.action: "authentication-failed"
    user.name|exists: false   # non-existent user: field absent after normalization

mitre:
  tactic:
    - "TA0006"
  technique:
    - "T1110"
  subtechnique: []

compliance:
  pci_dss:
    - "10.2.4"
    - "10.2.5"
  nist_800_53:
    - "AU-14"
    - "AC-7"

tags:
  - "attack.credential-access"
  - "attack.t1110"

falsepositives:
  - "Legitimate users mistyping their username"
```

Rules are linked to an **integration** at creation time (see [Step 5](#step-5-assign-rules-to-an-integration)).

---

## Step-by-step migration

### Step 1: Inventory your 4.x rules

List all custom rules you need to migrate:

```bash
# On the 4.x Wazuh manager
find /var/ossec/etc/rules/ -name "*.xml" -exec grep -l '<rule ' {} \;
# Also check default rules you may have overridden
grep -r 'overwrite="yes"' /var/ossec/etc/rules/
```

For each rule, note:
- Whether it is a **leaf rule** (generates an alert) or a **grouping/parent rule** (`noalert`, level 0, or only used as a parent via `if_sid`).
- Which 4.x fields it matches on (for WCS mapping, see [Step 4](#step-4-rewrite-detection-logic)).
- Whether it relies on `if_sid`, `if_matched_sid`, `frequency`, or `timeframe` (see [Step 10](#step-10-handle-rules-that-cannot-be-directly-migrated)).

**Only leaf rules that generate alerts need to be migrated.** Grouping/parent rules exist in 4.x solely to organize chaining and share a `decoded_as` binding. In 5.x, that function is handled by the integration — the grouping rules are discarded entirely.

### Step 2: Map rule identification

| 4.x field | 5.x field | Notes |
|---|---|---|
| `<rule id="5710">` | *(auto-assigned UUID)* | The rule UUID is assigned by the system on creation and returned in the API response. You do not specify it. |
| `<rule id="5710">` | `metadata.references` | Optionally record the original 4.x rule number as a reference string, e.g. `"Migrated from 4.x rule 5710"`. |
| `<rule id="..." level="5">` | `level` | See severity mapping in [Step 3](#step-3-map-severity-levels). |
| N/A | `status` | Set to `experimental`, `test`, or `stable`. New migrations should start as `experimental`. |
| N/A | `enabled` | Set to `true` or `false`. Replaces `noalert`. |

### Step 3: Map severity levels

The 4.x numeric levels (0–16) must be translated to 5.x keyword levels:

| 4.x level | Meaning (4.x) | 5.x level |
|---|---|---|
| 0 | Ignored / no alert | Set `enabled: false` or omit the rule |
| 1 | None | `informational` |
| 2 | System low priority notification | `informational` |
| 3 | Successful/authorized event | `informational` |
| 4 | System low priority error | `low` |
| 5 | User-generated error | `low` |
| 6 | Low relevance attack | `low` |
| 7 | "Bad word" matching | `medium` |
| 8 | First-time event seen | `medium` |
| 9 | Error from invalid source | `medium` |
| 10 | Multiple user-generated errors | `high` |
| 11 | Integrity checking warning | `high` |
| 12 | High importance event | `high` |
| 13 | Unusual error (high importance) | `high` |
| 14 | High importance security event | `critical` |
| 15 | Severe attack | `critical` |
| 16 | Severe attack | `critical` |

### Step 4: Rewrite detection logic

This is the most significant change in the migration.

#### The WCS is a closed, validated schema

In 4.x, a rule's `<field name="X">` references whatever the decoder named field `X`. If `X` doesn't exist in the event, the rule never fires — there is no error, no warning, no indication that the rule is broken.

In 5.x, **every field name in a `detection` block is validated against the Wazuh Common Schema (WCS) at rule creation time**. A rule that references an unknown field is rejected with a structured error identifying the offending field names. The WCS defines a fixed, normalized set of field paths (e.g., `event.action`, `source.ip`, `user.name`) that all integrations write to.

This has two practical consequences:

1. **You cannot carry over 4.x decoder field names directly.** Fields like `office365.Operation`, `audit.key`, or `sysmon.image` do not exist in WCS and will cause rule creation to fail. You must find the WCS equivalent.
2. **A rule that passes validation is guaranteed to match on the fields you specified.** There are no silent mismatches from typos or renamed fields.

The complete WCS field list is at the [WCS field reference (CSV)](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/wcs/stateless/events/main/docs/fields.csv).

#### Finding the right WCS field

The authoritative way to find the WCS field path for a given log value is to run a sample log through logtest:

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/logtest" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "<your-integration-uuid>",
    "space": "test",
    "queue": 1,
    "location": "/var/log/auth.log",
    "event": "<the raw log line you want to match>"
  }'
```

The `normalization.output` section of the response is the fully decoded WCS document. The field paths you see there are the exact paths to use in your `detection` block.

**Example:** A 4.x rule uses `<field name="office365.Operation" type="pcre2">ComplianceDLP.*</field>`. Run a sample O365 log through logtest and find `"event": {"code": "ComplianceDLPSharePoint"}` in the output. Use `event.code|contains: "ComplianceDLPSharePoint"` in the 5.x rule.

#### 4.x detection elements → 5.x detection equivalents

| 4.x element | 5.x equivalent | Notes |
|---|---|---|
| **Log source matching** | | |
| `<decoded_as>` | `logsource.product` | Log source binding replaces decoder-based matching. The rule is linked to an integration. |
| `<category>` | `logsource.category` | The decoder type category maps to the logsource object. |
| `<location>` | `logsource` or `wazuh.integration.name` | Depends on source type. The 4.x location (e.g., `EventChannel`, `syscheck`) is now implicit in the integration. |
| `<program_name>` | `process.name: "..."` in detection | |
| **Pattern matching** | | |
| `<match>` | See [Translating `<match>` and `<regex>`](#translating-match-and-regex) below | The approach depends on whether the value was decoded into a WCS field. |
| `<regex>` | `field\|re: "pattern"` | Use the `\|re` modifier on the specific WCS field. Prefer exact/contains/startswith/endswith when possible. |
| `<field name="X">value</field>` | `X: "value"` in detection selection | `X` must be a valid WCS field path — use logtest to find the mapping. |
| `negate="yes"` on any element | `and not filter` condition | See [Negating conditions](#negating-conditions) below. |
| **Network fields** | | |
| `<srcip>` | `source.ip: "..."` | Use `\|cidr` modifier for CIDR ranges. |
| `<dstip>` | `destination.ip: "..."` | Use `\|cidr` modifier for CIDR ranges. |
| `<srcport>` | `source.port: ...` | |
| `<dstport>` | `destination.port: ...` | |
| `<protocol>` | `network.protocol: "..."` | |
| `<srcgeoip>` | `source.geo.country_iso_code: "..."` | |
| `<dstgeoip>` | `destination.geo.country_iso_code: "..."` | |
| **Identity fields** | | |
| `<user>` | `user.name: "..."` | |
| `<system_name>` | `host.name: "..."` | |
| `<hostname>` | `observer.hostname: "..."` | |
| **Event fields** | | |
| `<action>` | `event.action: "..."` | |
| `<status>` | `event.outcome: "..."` | |
| `<id>` | `event.code: "..."` | |
| `<url>` | `url.original: "..."` | |
| `<data>` | `event.original: "..."` | Context-dependent — may map to other fields depending on the decoder. |
| `<extra_data>` | No direct equivalent | Map to the appropriate WCS field based on what the decoder extracts (verify with logtest). |
| **Metadata and output** | | |
| `<description>` | `metadata.title` + `metadata.description` | Split: `title` is short (required), `description` is detailed. |
| `<info>` | `metadata.references` | Convert URLs to the references array. |
| `<group>` (categorization) | `tags` | Functional groups become Sigma-style tags (e.g., `attack.credential-access`). |
| `<group>` (compliance) | `compliance` object | Extract compliance prefixes into structured object. See [Step 8](#step-8-migrate-compliance-mappings). |
| `<mitre><id>` | `mitre` object | See [Step 7](#step-7-migrate-mitre-attck-mappings). |
| `<options>` | No direct equivalent | Options like `alert_by_email`, `no_full_log`, `no_log` must be configured externally (alert routing, index settings). |
| `<var>` | No direct equivalent | Variable definitions are not supported — inline the values. |
| **Rule attributes** | | |
| `id` (numeric) | *(auto-assigned UUID)* | A UUID is assigned by the system on creation. |
| `level` (0–16) | `level` (keyword) | See [severity mapping](#step-3-map-severity-levels). |
| `noalert` | `enabled: false` | Or simply omit the rule if it was a grouping-only rule. |
| `overwrite="yes"` | Not needed | Rules are independent documents — update the document directly via the API. |
| `maxsize` | No direct equivalent | Event size filtering not supported at the rule level. |
| `ignore` (flood control) | No direct equivalent | Throttling/suppression must be handled externally. |
| **Time-based conditions** | | |
| `<time>` | Not supported | Must be handled externally (e.g., scheduled queries). |
| `<weekday>` | Not supported | Must be handled externally. |
| **Rule chaining and correlation** | | |
| `<if_sid>` / `<if_group>` / `<if_level>` | Not supported | Rules are self-contained. See [Step 10](#step-10-handle-rules-that-cannot-be-directly-migrated). |
| `<if_matched_sid>` / `<if_matched_group>` | Not supported | Correlation handled separately. |
| `frequency` / `timeframe` | Not supported in rules | Correlation handled separately. |
| `<same_*>` / `<different_*>` | Not supported in rules | Correlation handled separately. |
| `<if_fts>` | Not supported in rules | First Time Seen logic and correlation handled separately. |
| `<global_frequency>` | Not supported in rules | Correlation handled separately. |
| **Lookups and diff** | | |
| `<list>` (CDB lookups) | Not supported in rules | KVDBs replace CDB lists, but they operate at the decoder level during normalization rather than at rule evaluation time. Migrate CDB lookups to KVDBs within the appropriate integration. |
| `<check_diff>` | Not supported | Handle via separate mechanism. |

#### Translating `<match>` and `<regex>`

In 4.x, `<match>` and `<regex>` search the **raw log string** before any field extraction. In 5.x, rules operate on the **WCS-normalized event** — there is no direct equivalent of matching raw text. Use the following decision process:

1. Run the sample log through logtest (see [Finding the right WCS field](#finding-the-right-wcs-field)).
2. **If the matched value appears in a named WCS field** — match on that field directly. This is always preferred and gives the most precise detection:
   ```yaml
   detection:
     condition: selection
     selection:
       event.action: "authentication-failed"
   ```
3. **If the raw text was not decoded into a specific field** — fall back to `event.original`, which holds the raw log line:
   ```yaml
   detection:
     condition: selection
     selection:
       event.original|contains: "illegal user"
   ```
4. **For a list of keyword alternatives across all event fields** (not targeting a specific field) — use `keywords` detection:
   ```yaml
   detection:
     keywords:
       - "illegal user"
       - "invalid user"
     condition: keywords
   ```

`keywords` is closest to a raw-log `<match>` but has no field targeting. Always prefer a specific WCS field when one exists.

**Example: translating a 4.x regex alternation**

```xml
<!-- 4.x -->
<match>illegal user|invalid user</match>
```

```yaml
# 5.x option A: specific WCS field (preferred — requires logtest to confirm field mapping)
detection:
  condition: selection
  selection:
    event.action: "authentication-failed"
    user.name|exists: false   # non-existent user maps to absent field, not specific text

# 5.x option B: keywords (fallback when no WCS field captures the value)
detection:
  keywords:
    - "illegal user"
    - "invalid user"
  condition: keywords

# 5.x option C: regex on event.original (last resort)
detection:
  condition: selection
  selection:
    event.original|re: "illegal user|invalid user"
```

#### Negating conditions

In 4.x, `negate="yes"` inverts the match for any element. In 5.x, define the excluded condition as a separate named selection and exclude it with `not` in the condition expression:

```xml
<!-- 4.x: alert on logins from outside 192.168.0.0/16, excluding root and admin -->
<rule id="17101" level="9">
  <if_group>authentication_success</if_group>
  <srcip negate="yes">192.168.0.0/16</srcip>
  <user negate="yes">root|admin</user>
  <description>Unexpected successful login.</description>
</rule>
```

```yaml
# 5.x equivalent
detection:
  condition: "selection and not filter_internal and not filter_privileged"
  selection:
    event.action: "authentication-success"
  filter_internal:
    source.ip|cidr: "192.168.0.0/16"
  filter_privileged:
    user.name:
      - "root"
      - "admin"
```

The `selection and not filter` pattern is the standard Sigma idiom for exclusions and works for any field type.

#### Detection modifiers

Modifiers are appended to field names using the pipe (`|`) character and transform how field values are compared. Multiple modifiers can be chained: `field|modifier1|modifier2: value`.

| Modifier | Meaning | Example |
|---|---|---|
| `\|contains` | Substring match (wildcard on both sides) | `event.original\|contains: "invalid user"` |
| `\|startswith` | Value begins with string (wildcard at end) | `process.name\|startswith: "cmd"` |
| `\|endswith` | Value ends with string (wildcard at start) | `file.name\|endswith: ".exe"` |
| `\|re` | Regular expression match | `event.original\|re: "illegal user\|invalid user"` |
| `\|re\|i` | Case-insensitive regex | `process.name\|re\|i: "^powershell"` |
| `\|re\|m` | Multi-line regex (`^`/`$` match line boundaries) | `event.original\|re\|m: "^error"` |
| `\|re\|s` | Single-line regex (`.` also matches newlines) | `message\|re\|s: "begin.*end"` |
| `\|exists` | Field is present (`true`) or absent (`false`) | `user.name\|exists: true` |
| `\|cidr` | IPv4 or IPv6 address falls within the CIDR range | `source.ip\|cidr: "10.0.0.0/8"` |
| `\|all` | All list values must match (default list logic is OR) | `event.category\|contains\|all: ["authentication", "failure"]` |
| `\|base64` | Value is Base64-encoded before comparison | `process.command_line\|base64: "/bin/bash"` |
| `\|base64offset\|contains` | All three Base64 offsets of the value (for substrings inside encoded streams) | `process.command_line\|base64offset\|contains: "/bin/bash"` |
| `\|wide\|base64offset\|contains` | UTF-16 encoding then Base64 offsets (Windows-style wide strings) | `process.command_line\|wide\|base64offset\|contains: "ping"` |
| `\|windash\|contains` | Expand Windows dash variants (`-`, `/`, `–`, `—`, `―`) | `process.command_line\|windash\|contains: " -enc "` |
| `\|lt` | Less than (numeric) | `event.severity\|lt: 10` |
| `\|lte` | Less than or equal (numeric) | `event.severity\|lte: 3` |
| `\|gt` | Greater than (numeric) | `event.severity\|gt: 7` |
| `\|gte` | Greater than or equal (numeric) | `event.duration\|gte: 5000` |

#### Detection condition syntax

The `condition` field uses Sigma condition expressions:

| Condition | Meaning |
|---|---|
| `selection` | The named selection must match |
| `selection1 and selection2` | Both selections must match |
| `selection1 or selection2` | Either selection must match |
| `selection and not filter` | Selection matches but filter does not |
| `(selection1 or selection2) and not filter` | Grouped logic with exclusion |
| `1 of selection_*` | At least one selection matching the wildcard must match |
| `all of selection_*` | All selections matching the wildcard must match |
| `keywords` | Keyword-based matching across all event fields |

#### Field value matching

In 5.x, detection field values can be:
- **Single string:** `event.action: "vulnerability-detected"` — exact match
- **List of strings:** `event.action: ["inserted", "added", "started"]` — OR match (any value matches)
- **Wildcard:** `observer.ingress.interface.name: "*"` — field exists with any value
- **CIDR range:** `source.ip|cidr: "10.0.0.0/8"` — use the `|cidr` modifier

### Step 5: Assign rules to an integration

In 5.x, rules do not operate in isolation — they must be linked to an **integration**. The integration determines:
- Which **decoders** process the raw logs.
- Which **event index** the decoded events are written to (via the integration's `category`).
- Which **rules** are evaluated against those events.

When migrating, you must **create a new custom integration** in user space (Draft → Test → Custom). Custom rules cannot be linked to standard integrations — the standard space is read-only.

Rules are linked to an integration at creation time via the API:

```bash
curl -sk -u admin:admin -X POST \
  "https://localhost:9200/_plugins/_content_manager/rules" \
  -H 'Content-Type: application/json' \
  -d '{
    "integration": "<integration-uuid>",
    "resource": {
      "metadata": {
        "title": "My custom rule",
        "description": "Migrated from 4.x rule 91560.",
        "author": "Security Team",
        "references": ["https://documentation.wazuh.com/"]
      },
      "enabled": true,
      "status": "experimental",
      "level": "high",
      "logsource": { "product": "o365", "service": "o365" },
      "detection": {
        "condition": "selection",
        "selection": {
          "event.code|contains": ["ComplianceDLPSharePoint", "ComplianceDLPExchange"],
          "wazuh.integration.name": "o365"
        }
      },
      "mitre": { "tactic": ["TA0010"], "technique": ["T1567"], "subtechnique": [] },
      "compliance": { "pci_dss": ["3.4", "10.2.5"] },
      "tags": ["attack.exfiltration", "attack.t1567"]
    }
  }'
```

The response returns the assigned rule UUID:

```json
{ "message": "6e1c43f1-f09b-4cec-bb59-00e3a52b7930", "status": 201 }
```

### Step 6: Migrate metadata

| 4.x | 5.x | Notes |
|---|---|---|
| `<description>` | `metadata.title` + `metadata.description` | Split: `title` is a short name (required), `description` is detailed |
| `<info>` | `metadata.references` | Convert URLs to the references array |
| N/A | `metadata.author` | Add attribution |
| N/A | `metadata.date` / `metadata.modified` | Auto-managed on creation and update |
| N/A | `metadata.documentation` | Link to extended docs |

**New in 5.x — Dynamic event field referencing:** The `title`, `tags`, `mitre.*`, and `compliance.*` fields support `{{ field.path }}` placeholders that resolve against the triggering event at enrichment time. The resulting finding reflects the specific event context rather than the static rule definition:

```yaml
metadata:
  title: "SSH failed login on agent {{ wazuh.agent.id }}"
tags:
  - "attack.credential-access"
  - "{{ wazuh.agent.host.name }}"   # expands to the agent hostname in each finding
```

Unresolved placeholders (absent or null fields) are silently dropped. See the [rules reference](../../../wazuh-indexer-plugins/docs/ref/modules/security-analytics/rules.md#dynamic-event-field-referencing) for the full specification.

### Step 7: Migrate MITRE ATT&CK mappings

**4.x:**
```xml
<mitre>
  <id>T1110</id>
  <id>T1499</id>
</mitre>
```

**5.x:**
```yaml
mitre:
  tactic:
    - "TA0006"
  technique:
    - "T1110"
  subtechnique:       # omit or use [] if not applicable
    - "T1110.001"
```

Key differences from 4.x:
- In 4.x, only technique IDs were listed. In 5.x, you must also include the parent **tactic** IDs (e.g., `TA0006`).
- Each field (`tactic`, `technique`, `subtechnique`) is a plain **array of ID strings**. There are no name fields.
- Use `subtechnique: []` when no subtechnique applies.
- A rule with techniques spanning multiple tactics lists all relevant tactic IDs:

```yaml
mitre:
  tactic:
    - "TA0004"
    - "TA0005"
  technique:
    - "T1562"
    - "T1055"
  subtechnique:
    - "T1562.001"
    - "T1055.009"
```

### Step 8: Migrate compliance mappings

**4.x** embedded compliance frameworks as CSV tags in the `<group>` element:

```xml
<group>pci_dss_10.2.4,pci_dss_10.2.5,gdpr_IV_35.7.d,nist_800_53_AU.14,tsc_CC6.1,</group>
```

**5.x** uses a dedicated structured object:

```yaml
compliance:
  pci_dss:
    - "10.2.4"
    - "10.2.5"
  gdpr:
    - "35.7.d"
  nist_800_53:
    - "AU.14"
  tsc:
    - "CC6.1"
```

**Supported compliance frameworks:**

| Key | Framework |
|---|---|
| `gdpr` | GDPR |
| `pci_dss` | PCI DSS |
| `cmmc` | CMMC |
| `nist_800_53` | NIST 800-53 |
| `nist_800_171` | NIST 800-171 |
| `hipaa` | HIPAA |
| `iso_27001` | ISO 27001 |
| `nis2` | NIS2 |
| `tsc` | TSC |
| `fedramp` | FedRAMP |

**Parsing the 4.x group tags:** Extract the prefix to determine the framework, and the suffix as the control ID:

| 4.x prefix | 5.x compliance key |
|---|---|
| `pci_dss_` | `pci_dss` |
| `gdpr_` | `gdpr` |
| `nist_800_53_` | `nist_800_53` |
| `hipaa_` | `hipaa` |
| `tsc_` | `tsc` |
| `gpg13_` | *(Not available in 5.x)* |

### Step 9: Migrate tags and groups

**4.x** uses `<group>` for both categorization and compliance:

```xml
<group name="syslog,sshd,">
  ...
  <group>invalid_login,authentication_failed,pci_dss_10.2.4,</group>
</group>
```

**5.x** uses `tags` for categorization (Sigma style, typically MITRE-prefixed):

```yaml
tags:
  - "attack.credential-access"
  - "attack.t1110"
```

Compliance tags go into the `compliance` object (see [Step 8](#step-8-migrate-compliance-mappings)). Functional groups like `authentication_failed` and `invalid_login` should be mapped to appropriate `logsource` values or Sigma-style `tags`.

### Step 10: Handle rules that cannot be directly migrated

| 4.x feature | Approach in 5.x |
|---|---|
| **Rule chaining** (`if_sid`, `if_group`, `if_level`) | Flatten into a single self-contained rule. See [example below](#flattening-if_sid-chains). |
| **Correlation rules** (`frequency`, `timeframe`, `same_*`, `different_*`) | Handle via a separate correlation engine or pipeline (outside the rule format). |
| **CDB list lookups** (`<list>`) | Migrate to KVDBs within the integration. KVDBs serve a similar purpose but operate at the decoder level during normalization, not at rule evaluation time. |
| **Time-based conditions** (`<time>`, `<weekday>`) | Implement via scheduled queries or external logic. |
| **Regex on raw log** (`<match>`, `<regex>`) | Ensure logs are properly decoded into WCS fields; match on structured fields. See [Translating `<match>` and `<regex>`](#translating-match-and-regex). |
| **`overwrite="yes"`** | Not needed — rules are independent documents; update via the API. |
| **`<check_diff>`** | Implement via external monitoring. |
| **`noalert` / level 0 grouping rules** | Not needed — rules don't chain, so grouping rules are unnecessary. |
| **`<var>` definitions** | Not supported — inline the values. |
| **`<options>` (alert_by_email, no_full_log, etc.)** | Configure alert routing externally. |

#### Flattening `if_sid` chains

The most common migration challenge is collapsing a multi-level rule chain into a single self-contained rule.

**The key insight:** In 4.x, root/grouping rules exist to share a `decoded_as` binding with children via `if_sid`. In 5.x, the integration provides that binding. Only the leaf rules that actually generated alerts need to be migrated — all parent/grouping rules are discarded.

**Example: three-level chain**

```xml
<!-- Rule 5700: grouping root — binds to sshd decoder, generates no alert -->
<rule id="5700" level="0" noalert="1">
  <decoded_as>sshd</decoded_as>
  <description>sshd grouping rule.</description>
</rule>

<!-- Rule 5710: leaf rule — inherits sshd context, generates a level-5 alert -->
<rule id="5710" level="5">
  <if_sid>5700</if_sid>
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user.</description>
  <mitre><id>T1110</id></mitre>
</rule>

<!-- Rule 5720: correlation rule — fires after 8 matches of 5710 within 120 seconds -->
<rule id="5720" level="10" frequency="8" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <description>sshd: Multiple login attempts using non-existent users (brute force).</description>
</rule>
```

**Migration plan:**
- Rule 5700: **discard** — its `decoded_as` binding is implicit in the sshd integration.
- Rule 5710: **migrate** — the integration link replaces `if_sid`; detection logic replaces `<match>`.
- Rule 5720: **cannot be migrated directly** — `frequency`/`timeframe`/`if_matched_sid` require a correlation engine. Document as a gap.

```yaml
# Migrated rule 5710 — self-contained, linked to the sshd integration
enabled: true
status: "experimental"
level: "low"

metadata:
  title: "SSH login attempt with non-existent user"
  description: "Detects SSH authentication attempts using usernames that do not exist on the system."
  references:
    - "Migrated from 4.x rule 5710"

logsource:
  product: "sshd"
  service: "sshd"

detection:
  condition: "selection"
  selection:
    wazuh.integration.name: "sshd"
    event.action: "authentication-failed"
    user.name|exists: false   # non-existent user: field absent after normalization

mitre:
  tactic:
    - "TA0006"
  technique:
    - "T1110"
  subtechnique: []

tags:
  - "attack.credential-access"
  - "attack.t1110"
```

> **Verify with logtest:** The 4.x `<match>illegal user|invalid user</match>` matched raw log text. After normalization, whether the `user.name` field is absent or set to a sentinel value depends on the decoder. Confirm with logtest which field (if any) captures this distinction in your integration.

### Step 11: Deploy and test

1. **Create an integration in Draft space** — If there is no matching standard integration, create a new custom integration in draft. Custom rules cannot be attached to standard integrations.
2. **Create the rule in Draft space** via the API (see [Step 5](#step-5-assign-rules-to-an-integration)).
3. **Promote to Test space** — the rule and its integration are loaded into the Engine's test policy.
4. **Validate with logtest** — send sample log events through `POST /_plugins/_content_manager/logtest`. Inspect:
   - `normalization.output` — verify the decoder produced the WCS fields you expect.
   - `detection.matches` — verify the rule fired on the correct conditions.
   - Iterate on the rule in Test space until it behaves as expected.
5. **Promote to Custom space** — the rule is now available for production use.
6. **Create or update a detector** to include the rule's integration, enabling active detection against incoming events.

---

## Migration examples

### Example 1: Simple field-matching rule

**4.x XML:**
```xml
<group name="vulnerability-detector,">
  <rule id="23500" level="7">
    <decoded_as>json</decoded_as>
    <field name="integration">vulnerability-detector</field>
    <field name="action">vulnerability-detected</field>
    <description>Vulnerability detected on endpoint.</description>
    <group>pci_dss_6.2,nist_800_53_SI.2,</group>
  </rule>
</group>
```

**5.x YAML:**
```yaml
enabled: true
status: "stable"
level: "medium"

metadata:
  title: "Wazuh VD - Vulnerability detected"
  author: "Wazuh, Inc."
  date: "2026-03-24"
  description: "Detects when the Wazuh vulnerability scanner identifies a new or updated vulnerability on an endpoint."
  references:
    - "https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html"

logsource:
  product: "wazuh-vd"
  service: "wazuh-vd"

detection:
  condition: "selection"
  selection:
    event.action: "vulnerability-detected"
    wazuh.integration.name: "wazuh-vd"

mitre:
  tactic:
    - "TA0001"
    - "TA0004"
  technique:
    - "T1068"
    - "T1190"
  subtechnique: []

compliance:
  pci_dss:
    - "6.2"
    - "6.3.3"
    - "11.3"
  nist_800_53:
    - "CA-7"
    - "RA-5"
    - "SI-2"
    - "SI-4"
  gdpr:
    - "32"
    - "33"
  hipaa:
    - "164.308.a.1.ii.D"
    - "164.308.a.5.ii.B"
    - "164.308.a.8"
  iso_27001:
    - "A.12.6.1"
    - "A.14.2.3"
    - "A.16.1.2"
  tsc:
    - "A1.2"
    - "CC7.1"
    - "CC7.2"
  nis2:
    - "21.2.a"
    - "21.2.e"
    - "23"
  nist_800_171:
    - "3.11.1"
    - "3.11.2"
    - "3.11.3"
    - "3.14.1"
    - "3.14.4"
  fedramp:
    - "CA-7"
    - "RA-5"
    - "SI-2"
    - "SI-4"
  cmmc:
    - "AU.L2-3.3.1"
    - "CA.L2-3.12.1"
    - "RA.L2-3.11.1"
    - "RA.L2-3.11.2"
    - "RA.L2-3.11.3"
    - "SI.L2-3.14.1"

tags:
  - "attack.initial-access"
  - "attack.privilege-escalation"
  - "attack.t1190"
  - "attack.t1068"

falsepositives:
  - "Legitimate software with known vulnerabilities that have been accepted as a risk"
```

The 4.x decoder field `integration` maps to `wazuh.integration.name` in WCS, and `action` maps to `event.action`. Both were verified via logtest. This rule belongs to the **wazuh-vd** integration (category: `security`), so events are indexed into `wazuh-events-v5-security-*` and findings into `wazuh-findings-v5-security-*`.

### Example 2: Rule with `|contains` replacing a PCRE2 alternation

**4.x XML:**
```xml
<group name="office365,">
  <rule id="91560" level="9">
    <if_sid>91500</if_sid>
    <field name="office365.Operation" type="pcre2">ComplianceDLPSharePoint|ComplianceDLPExchange</field>
    <description>Office 365 DLP policy match detected.</description>
    <group>pci_dss_3.4,pci_dss_10.2.5,</group>
  </rule>
</group>
```

**5.x YAML:**
```yaml
enabled: true
status: "experimental"
level: "high"

metadata:
  title: "Office 365 data loss prevention policy match"
  author: "Wazuh, Inc."
  date: "2026-04-14"
  description: "Detects when a DLP policy match is triggered in SharePoint or Exchange."
  references:
    - "https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp"

logsource:
  product: "o365"
  service: "o365"

detection:
  condition: "selection"
  selection:
    event.code|contains:
      - "ComplianceDLPSharePoint"
      - "ComplianceDLPExchange"
    event.kind: "alert"
    wazuh.integration.name: "o365"

mitre:
  tactic:
    - "TA0010"
  technique:
    - "T1567"
  subtechnique: []

compliance:
  pci_dss:
    - "3.4"
    - "6.2"
    - "10.2.5"
    - "11.4"
  nist_800_53:
    - "AU-6"
    - "IR-4"
    - "SC-28"
    - "SI-4"
  gdpr:
    - "25"
    - "32"
    - "33"
    - "35"
  hipaa:
    - "164.308.a.1.ii.D"
    - "164.308.a.6"
    - "164.312.a.2.iv"
    - "164.312.e.1"
  iso_27001:
    - "A.8.2.3"
    - "A.12.4.1"
    - "A.16.1.2"
    - "A.18.1.4"
  tsc:
    - "A1.2"
    - "CC6.7"
    - "CC7.2"

tags:
  - "attack.exfiltration"
  - "attack.t1567"

falsepositives:
  - "Test files or legitimate business processes involving regulated data."
```

The 4.x `if_sid` dependency is eliminated — the 5.x rule is self-contained. The 4.x decoder field `office365.Operation` maps to `event.code` in WCS (confirmed via logtest on an O365 sample log). The PCRE2 alternation becomes a list under `|contains`.

### Example 3: Multiple selections with OR condition

**4.x XML:**
```xml
<group name="audit,">
  <rule id="80700" level="10">
    <decoded_as>auditd</decoded_as>
    <field name="audit.type">SYSCALL</field>
    <description>Disabled via direct syscall - Linux</description>
  </rule>
  <rule id="80701" level="10">
    <decoded_as>auditd</decoded_as>
    <field name="audit.type">EXECVE</field>
    <match>sysctl</match>
    <description>Disabled via sysctl - Linux</description>
  </rule>
</group>
```

In 4.x, these are two separate rules with the same severity and intent. In 5.x, they consolidate into one rule with multiple selections:

**5.x YAML:**
```yaml
enabled: true
status: "experimental"
level: "high"

metadata:
  title: "Disabled Via Sysctl or Direct Syscall - Linux"
  author: "Milad Cheraghi"
  date: "2026-05-07"
  description: "Detects disabling of security features via sysctl command or direct syscall."
  references:
    - "https://man7.org/linux/man-pages/man2/personality.2.html"

logsource:
  product: "linux"
  service: "auditd"

detection:
  condition: "1 of selection_*"
  selection_syscall:
    event.action: "SYSCALL"
  selection_sysctl:
    event.action: "EXECVE"

mitre:
  tactic:
    - "TA0004"
    - "TA0005"
  technique:
    - "T1562"
    - "T1055"
  subtechnique:
    - "T1562.001"
    - "T1055.009"

tags:
  - "attack.privilege-escalation"
  - "attack.defense-evasion"
  - "attack.t1562.001"
  - "attack.t1055.009"

falsepositives:
  - "Debugging or legitimate software testing"
```

The `1 of selection_*` condition fires if either `selection_syscall` or `selection_sysctl` matches. This pattern is also the standard way to consolidate related 4.x rules that shared a parent via `if_sid` — instead of chaining, you combine them as named selections in a single rule.

### Example 4: List-based matching (multiple event actions)

**4.x XML:**
```xml
<group name="syscollector,">
  <rule id="93100" level="3">
    <decoded_as>json</decoded_as>
    <field name="integration">syscollector</field>
    <match>inserted|added|started|package-installed|service-installed</match>
    <description>IT Hygiene: New item created.</description>
  </rule>
</group>
```

**5.x YAML:**
```yaml
enabled: true
status: "stable"
level: "informational"

metadata:
  title: "Wazuh IT Hygiene - Item created"
  author: "Wazuh, Inc."
  date: "2026-03-24"
  description: "Detects creation of new system items such as packages, services, users, or groups."

logsource:
  product: "wazuh-it-hygiene"
  service: "wazuh-it-hygiene"

detection:
  condition: "selection"
  selection:
    event.action:
      - "inserted"
      - "added"
      - "started"
      - "package-installed"
      - "service-installed"
      - "user-created"
      - "group-created"
      - "os-info-collected"
    wazuh.integration.name: "wazuh-it-hygiene"

mitre:
  tactic:
    - "TA0007"
  technique:
    - "T1518"
  subtechnique: []

tags:
  - "attack.discovery"
  - "attack.t1518"

falsepositives:
  - "Normal software installation and system asset changes"
```

The 4.x `<match>` regex alternation (`inserted|added|started|...`) becomes a list of values under `event.action`. A list field matches if any value in the list is present (OR logic). The 4.x decoder field `integration` maps to `wazuh.integration.name` in WCS.

---

## WCS field mapping reference

When migrating, 4.x decoder-extracted fields must be mapped to WCS fields. Always verify the mapping with logtest — the `normalization.output` in the response shows the exact field paths produced by your integration's decoder. For the complete field list, see the [WCS field reference (CSV)](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/wcs/stateless/events/main/docs/fields.csv).

Common mappings:

| 4.x decoded field | 5.x WCS field |
|---|---|
| `srcip` | `source.ip` |
| `dstip` | `destination.ip` |
| `srcport` | `source.port` |
| `dstport` | `destination.port` |
| `srcuser` / `user` | `user.name` |
| `dstuser` | `user.target.name` |
| `protocol` | `network.protocol` |
| `action` | `event.action` |
| `status` | `event.outcome` |
| `id` | `event.code` |
| `url` | `url.original` |
| `data` | `event.original` or context-dependent |
| `system_name` | `host.name` |
| `program_name` | `process.name` |
| `hostname` | `observer.hostname` |
| `location` | `wazuh.protocol.location` |
| Integration name (from decoder) | `wazuh.integration.name` |
| Agent ID | `wazuh.agent.id` |
| Agent name | `wazuh.agent.name` |
| Agent groups | `wazuh.agent.groups` |
| Cluster name | `wazuh.cluster.name` |
| Cluster node | `wazuh.cluster.node` |
| Windows Event ID | `event.code` |
| Log severity level | `log.level` |
| Process PID | `process.pid` |
| Process command line | `process.command_line` |
| File path | `file.path` |
| File name | `file.name` |
| Registry key path | `registry.path` |

---

## Additional resources

- [Wazuh 4.x Rules Syntax Reference](https://documentation.wazuh.com/4.9/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Sigma Rule Specification](https://sigmahq.io/docs/basics/rules.html)
- [Sigma Conditions](https://sigmahq.io/docs/basics/conditions.html)
- [Sigma Modifiers](https://sigmahq.io/docs/basics/modifiers.html)
- [Wazuh Common Schema (WCS) Documentation](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/wcs/stateless/events/main/docs/README.md)
- [WCS Field Reference (CSV)](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/wcs/stateless/events/main/docs/fields.csv)
- [Wazuh 5.x Rules Reference](../wazuh-indexer-plugins/docs/ref/modules/security-analytics/rules.md)
- [Content Manager Rule Testing Guide](../wazuh-indexer-plugins/docs/ref/modules/content-manager/rule-testing.md)
