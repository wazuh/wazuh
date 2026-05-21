# Migrating rules from Wazuh 4.x (XML) to Wazuh 5.x (Sigma-based)

## Overview

Wazuh 5.0 introduces a fundamentally different architecture for log analysis and threat detection. The legacy XML-based analysis daemon is replaced by a pipeline that separates **event processing** from **threat detection**:

1. **Wazuh Engine** — Receives raw logs, decodes them using the new decoder format, normalizes fields to the [Wazuh Common Schema (WCS)](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/wcs/stateless/events/main/docs/README.md), and indexes the resulting events into `wazuh-events-v5-*` indices.
2. **Security Analytics detectors** — Use a percolator to evaluate indexed events against Sigma-based rules stored in the `wazuh-threatintel-rules` index. When an event matches a rule, the detector creates a **finding**, an enriched copy of the event indexed it into `wazuh-findings-v5-*`.

There is no automatic conversion tool. Rules must be manually rewritten following this guide.

### Terminology changes

| 4.x term | 5.x term | Description |
|---|---|---|
| **Alert** | **Event** | The base log entry after decoding. In 4.x, the analysis daemon produced alerts directly. In 5.x, the Wazuh Engine produces normalized events. |
| **Alert (matching a rule)** | **Finding** | In 5.x, when an event matches a detection rule, a finding is generated, the event enriched. |
| **Rule (XML)** | **Rule (Sigma-based)** | Detection rules are now written in the Sigma format with Wazuh extensions. |
| **Decoder (XML)** | **Decoder (Engine format)** | Decoders still exist but use a new format adapted to the Wazuh Engine. |
| **Ruleset files on disk** | **Threat intelligence indices** | Rules, KVDBs, decoders, integrations, and enrichments are stored in Wazuh indices (`wazuh-threatintel-*`). |

### Content architecture

In 5.x, detection content is organized into **integrations**, which bundle related decoders, KVDBs and rules:

```
Integration (e.g., "o365")
├── Decoders — Parse raw logs into WCS-normalized events
├── Rules — Sigma-based detection rules
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

| Aspect | 4.x (XML) | 5.x (Sigma-based) |
|---|---|---|
| **Format** | XML files on disk (`/var/ossec/ruleset/rules/`) | JSON documents in Wazuh indices (`wazuh-threatintel-*`) |
| **Processing** | Single analysis daemon handles decoding + rule matching | Wazuh Engine decodes and indexes events; Security Analytics detectors match rules via percolator |
| **Output** | Alerts | Events (all decoded logs) + Findings (events that matched a rule, enriched) |
| **Rule identification** | Numeric ID (1–999999) | UUID |
| **Severity** | Numeric level 0–16 | Keyword: `informational`, `low`, `medium`, `high`, `critical` |
| **Detection logic** | Decoder fields + regex matching + parent rule chaining | Sigma detection blocks with selections, conditions, and value modifiers |
| **Rule chaining** | `if_sid`, `if_group`, `if_level`, `if_matched_sid` | Not supported — each rule is self-contained |
| **Correlation** | `frequency`, `timeframe`, `same_*`, `different_*` | Not natively supported in the rule format |
| **Field schema** | Custom decoder-extracted fields | Wazuh Common Schema (WCS) fields |
| **Compliance mapping** | Embedded in `<group>` tag as CSV | Dedicated `compliance` object with structured fields |
| **MITRE mapping** | `<mitre><id>` tags inside rule | Dedicated `mitre` object with `tactic`, `technique`, `subtechnique` |
| **Management** | File edits + manager restart | API / index operations, no restart required |
| **Custom rules** | `/var/ossec/etc/rules/local_rules.xml` | Documents promoted through Draft → Test → Custom spaces |
| **Rule state** | Active when loaded (or `noalert`) | `enabled: true/false` field per rule |
| **Field validation** | None — rules silently fail on unknown fields | Detection fields are validated against the WCS; unknown fields are rejected |

---

## Rule structure comparison

### 4.x XML rule structure

```xml
<group name="syslog,sshd,">
  <rule id="5710" level="5" frequency="8" timeframe="120">
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

### 5.x Sigma-based rule structure

```yaml
document:
  id: "d166d57a-86e3-49b4-b560-db423b3c156a"
  enabled: true
  status: "experimental"      # experimental | test | stable
  level: "high"               # informational | low | medium | high | critical

  metadata:
    title: "SSH brute force attempt with invalid users"
    author: "Wazuh, Inc."
    date: "2026-04-14"
    modified: "2026-04-14"
    description: "Detects repeated SSH login attempts using non-existent user accounts."
    references:
      - "https://documentation.wazuh.com/current/..."
    documentation: null
    supports: []

  logsource:
    product: "sshd"
    service: "sshd"

  detection:
    condition: "selection"
    selection:
      event.action: "authentication-failed"
      user.name|exists: true

  mitre:
    tactic:
      - "TA0006"
    technique:
      - "T1110"

  compliance:
    pci_dss:
      - "10.2.4"
      - "10.2.5"
    nist_800_53:
      - "AU.14"
      - "AC.7"

  tags:
    - "attack.credential-access"
    - "attack.t1110"

  falsepositives:
    - "Legitimate users mistyping their username"

space:
  name: "standard"           # standard | draft | test | custom
hash:
  sha256: "916c6852f173..."
offset: 24
```

Rules are assigned to an **integration** via the integration's `rules` array, which links them to the detection pipeline.

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

### Step 2: Map rule identification

| 4.x field | 5.x field | Notes |
|---|---|---|
| `<rule id="5710">` | `document.id` (UUID) | The UUID is randomly generated once the rule is created. |
| `<rule id="..." level="5">` | `document.level` | See severity mapping section. |
| N/A | `document.status` | Set to `experimental`, `test`, or `stable`. |
| N/A | `document.enabled` | Set to `true` or `false`. Replaces `noalert`. |

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

This is the most significant change. The 4.x rule engine uses decoder field matching and regex patterns; 5.x uses Sigma-style detection blocks operating on **Wazuh Common Schema (WCS)** fields.

All fields referenced in detection blocks are **validated against the WCS**. Rules that reference unknown or invalid fields are rejected. Refer to the [WCS field reference](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/wcs/stateless/events/main/docs/fields.csv) for the complete list of available fields.

#### 4.x detection elements → 5.x detection equivalents

| 4.x element | 5.x equivalent | Notes |
|---|---|---|
| **Log source matching** | | |
| `<decoded_as>` | `logsource.product` | Log source binding replaces decoder-based matching. The rule is linked to an integration. |
| `<category>` | `logsource.category` | The decoder type category (e.g., `syslog`, `firewall`) maps to the logsource object. |
| `<location>` | `logsource` object or `wazuh.integration.name` | Depends on source type. The 4.x location (e.g., `EventChannel`, `syscheck`) is now implicit in the integration. |
| `<program_name>` | `detection.selection: { "process.name": "..." }` | |
| **Pattern matching** | | |
| `<match>` | `detection.selection` field values | Regex replaced by field-value matching with modifiers. Use `keywords` detection for raw string matching. |
| `<regex>` | `detection.selection` with `\|re` modifier | For complex patterns, use the `\|re` modifier. Prefer exact/contains/startswith/endswith when possible. |
| `<field name="X">value</field>` | `detection.selection: { "X": "value" }` | Fields are now WCS-normalized. |
| **Network fields** | | |
| `<srcip>` | `detection.selection: { "source.ip": "..." }` | IPv4 and IPv6 (including CIDR) supported. |
| `<dstip>` | `detection.selection: { "destination.ip": "..." }` | IPv4 and IPv6 (including CIDR) supported. |
| `<srcport>` | `detection.selection: { "source.port": ... }` | |
| `<dstport>` | `detection.selection: { "destination.port": ... }` | |
| `<protocol>` | `detection.selection: { "network.protocol": "..." }` | |
| `<srcgeoip>` | `detection.selection: { "source.geo.country_iso_code": "..." }` | GeoIP fields are now structured under `source.geo.*` / `destination.geo.*`. |
| `<dstgeoip>` | `detection.selection: { "destination.geo.country_iso_code": "..." }` | GeoIP fields are now structured under `source.geo.*` / `destination.geo.*`. |
| **Identity fields** | | |
| `<user>` | `detection.selection: { "user.name": "..." }` | |
| `<system_name>` | `detection.selection: { "host.name": "..." }` | |
| `<hostname>` | `detection.selection: { "observer.hostname": "..." }` | |
| **Event fields** | | |
| `<action>` | `detection.selection: { "event.action": "..." }` | |
| `<status>` | `detection.selection: { "event.outcome": "..." }` | |
| `<id>` | `detection.selection: { "event.code": "..." }` | |
| `<url>` | `detection.selection: { "url.original": "..." }` | |
| `<data>` | `detection.selection: { "event.original": "..." }` | Context-dependent — may map to other fields depending on the decoder. |
| `<extra_data>` | No direct equivalent | Map to the appropriate WCS field based on what the decoder extracts. |
| **Metadata and output** | | |
| `<description>` | `metadata.title` + `metadata.description` | Split: `title` is short (required), `description` is detailed. |
| `<info>` | `metadata.references` | Convert URLs to the references array. |
| `<group>` (categorization) | `tags` | Functional groups become Sigma-style tags (e.g., `attack.credential-access`). |
| `<group>` (compliance) | `compliance` object | Extract compliance prefixes into structured object. See [Step 8](#step-8-migrate-compliance-mappings). |
| `<mitre><id>` | `mitre` object | Must now include `tactic`, `technique`, and `subtechnique` arrays. See [Step 7](#step-7-migrate-mitre-attck-mappings). |
| `<options>` | No direct equivalent | Options like `alert_by_email`, `no_full_log`, `no_log` must be configured externally (alert routing, index settings). |
| `<var>` | No direct equivalent | Variable definitions are not supported — inline the values. |
| **Rule attributes** | | |
| `id` (numeric) | `id` (UUID) | A new UUID is generated for each rule once indexed. |
| `level` (0–16) | `level` (keyword) | See [severity mapping](#step-3-map-severity-levels). |
| `noalert` | `enabled: false` | Or simply omit the rule if it was a grouping-only rule. |
| `overwrite="yes"` | Not needed | Rules are independent documents — update the document directly. |
| `maxsize` | No direct equivalent | Event size filtering not supported at the rule level. |
| `ignore` (flood control) | No direct equivalent | Throttling/suppression must be handled externally. |
| **Time-based conditions** | | |
| `<time>` | Not supported | Must be handled externally (e.g., scheduled queries). |
| `<weekday>` | Not supported | Must be handled externally. |
| **Rule chaining and correlation** | | |
| `<if_sid>` / `<if_group>` / `<if_level>` | Not supported | Rules are self-contained; no chaining. Flatten the logic into a single rule with combined detection conditions. |
| `<if_matched_sid>` / `<if_matched_group>` | Not supported | Correlation handled separately. |
| `frequency` / `timeframe` | Not supported in rules | Correlation handled separately. |
| `<same_id>` / `<different_id>` | Not supported in rules | Correlation handled separately. |
| `<same_srcip>` / `<different_srcip>` | Not supported in rules | Correlation handled separately. |
| `<same_dstip>` / `<different_dstip>` | Not supported in rules | Correlation handled separately. |
| `<same_srcport>` / `<different_srcport>` | Not supported in rules | Correlation handled separately. |
| `<same_dstport>` / `<different_dstport>` | Not supported in rules | Correlation handled separately. |
| `<same_location>` / `<different_location>` | Not supported in rules | Correlation handled separately. |
| `<same_srcuser>` / `<different_srcuser>` | Not supported in rules | Correlation handled separately. |
| `<same_user>` / `<different_user>` | Not supported in rules | Correlation handled separately. |
| `<same_field>` / `<different_field>` | Not supported in rules | Correlation handled separately. |
| `<same_protocol>` / `<different_protocol>` | Not supported in rules | Correlation handled separately. |
| `<same_action>` / `<different_action>` | Not supported in rules | Correlation handled separately. |
| `<same_data>` / `<different_data>` | Not supported in rules | Correlation handled separately. |
| `<same_extra_data>` / `<different_extra_data>` | Not supported in rules | Correlation handled separately. |
| `<same_status>` / `<different_status>` | Not supported in rules | Correlation handled separately. |
| `<same_system_name>` / `<different_system_name>` | Not supported in rules | Correlation handled separately. |
| `<same_url>` / `<different_url>` | Not supported in rules | Correlation handled separately. |
| `<same_srcgeoip>` / `<different_srcgeoip>` | Not supported in rules | Correlation handled separately. |
| `<same_dstgeoip>` / `<different_dstgeoip>` | Not supported in rules | Correlation handled separately. |
| `<if_fts>` | Not supported in rules | First Time Seen logic and correlation handled separately. |
| `<global_frequency>` | Not supported in rules | Correlation handled separately. |
| **Lookups and diff** | | |
| `<list>` (CDB lookups) | Not supported in rules | KVDBs (Key-Value Databases) replace CDB lists, but they operate at the decoder level during event normalization, not at rule evaluation time. Migrate CDB lookups to KVDBs within the appropriate integration. |
| `<check_diff>` | Not supported | Handle via separate mechanism. |

#### Detection modifiers

5.x supports Sigma value modifiers using the pipe (`|`) syntax on field names:

| Modifier | Meaning | Example |
|---|---|---|
| `\|contains` | Field contains the value(s) | `event.code\|contains: ["DLPSharePoint", "DLPExchange"]` |
| `\|endswith` | Field ends with value | `file.name\|endswith: ".exe"` |
| `\|startswith` | Field starts with value | `process.name\|startswith: "cmd"` |
| `\|exists` | Field exists (boolean) | `user.name\|exists: true` |
| `\|re` | Regex match | `source.ip\|re: "^10\\..*"` |

#### Detection condition syntax

The `condition` field uses Sigma condition expressions:

| Condition | Meaning |
|---|---|
| `selection` | The named selection must match |
| `selection1 and selection2` | Both selections must match |
| `selection1 or selection2` | Either selection must match |
| `1 of selection_*` | At least one selection matching the wildcard must match |
| `all of selection_*` | All selections matching the wildcard must match |
| `selection and not filter` | Selection matches but filter does not |
| `keywords` | Keyword-based matching (list of strings to search for) |

#### Field value matching

In 5.x, detection field values can be:
- **Single string:** `event.action: "vulnerability-detected"` — exact match
- **List of strings:** `event.action: ["inserted", "added", "started"]` — OR match (any value matches)
- **Wildcard:** `observer.ingress.interface.name: "*"` — field exists with any value
- **IPv6 addresses:** `source.ip: ["2001:db8:bad::/48", "fe80::1234:5678:90ab:cdef"]` — supports standard, compressed, and CIDR formats

### Step 5: Assign rules to an integration

In 5.x, rules do not operate in isolation — they must be linked to an **integration**. The integration determines:
- Which **decoders** process the raw logs.
- Which **event index** the decoded events are written to (via the integration's `category`).
- Which **rules** are evaluated against those events.

When migrating, you must **create a new custom integration** in user space (Draft → Test → Custom). Custom rules cannot be linked to standard integrations — the standard space is read-only and cannot be modified by users. 

To create rules and integrations via the API, provide the integration UUID when submitting the rule:

```json
{
  "integration": "6b7b7645-00da-44d0-a74b-cffa7911e89c",
  "resource": {
    "metadata": { "title": "My custom rule" },
    "detection": { ... },
    ...
  }
}
```

### Step 6: Migrate metadata

| 4.x | 5.x | Notes |
|---|---|---|
| `<description>` | `metadata.title` + `metadata.description` | Split: `title` is a short name (required), `description` is detailed |
| `<info>` | `metadata.references` | Convert URLs to the references array |
| N/A | `metadata.author` | Add attribution |
| N/A | `metadata.date` / `metadata.modified` | Automatically managed |
| N/A | `metadata.documentation` | Link to extended docs |

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
    - "TA0006"      # Map technique to its parent tactic ID
  technique:
    - "T1110"
  subtechnique:     # If applicable
    - "T1110.001"
```

In 4.x, only technique IDs were listed. In 5.x, you must also provide the parent tactic IDs (e.g., `TA0006`) and, when applicable, subtechnique IDs (e.g., `T1562.001`).

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

Functional groups like `authentication_failed`, `invalid_login` should be mapped to appropriate `logsource` values or `tags`.

### Step 10: Handle rules that cannot be directly migrated

The following 4.x features have no direct equivalent in the 5.x rule format and require alternative approaches:

| 4.x feature | Workaround |
|---|---|
| **Rule chaining** (`if_sid`, `if_group`, `if_level`) | Flatten the logic into a single self-contained rule with combined detection conditions |
| **Correlation rules** (`frequency`, `timeframe`, `same_*`, `different_*`) | Handle via a separate correlation engine or pipeline (outside the rule format) |
| **CDB list lookups** (`<list>`) | Migrate to KVDBs (Key-Value Databases) within the integration. KVDBs serve a similar purpose — key-value lookups — but operate at the decoder level during event normalization rather than at rule evaluation. For example, the `windows` integration uses KVDBs to map Windows Security Event IDs to WCS `event.action`, `event.category`, and `event.type` values. |
| **Time-based conditions** (`<time>`, `<weekday>`) | Implement via scheduled queries or external logic |
| **Regex on raw log** (`<match>`, `<regex>`) | Ensure logs are properly decoded into WCS fields; match on structured fields instead. Use keyword-based detection for simple string matching. |
| **`overwrite="yes"`** | Not needed — rules are independent documents; update the document directly |
| **`<check_diff>`** | Implement via external monitoring |
| **`noalert` (level 0 grouping rules)** | Not needed — rules don't chain, so grouping rules are unnecessary |
| **`<var>` definitions** | Not supported — inline the values |
| **`<options>` (alert_by_email, no_full_log, etc.)** | Configure alert routing externally |

### Step 11: Deploy and test

1. **Create the rule in Draft space** via the API.
2. **Promote to Test space** — the rule and its integration are loaded into the Engine's test policy.
3. **Validate with logtest** — Send sample log events through logtest to verify that the decoder correctly normalizes the log into WCS fields and that the rule's detection logic matches as expected. Iterate on the rule in Test space until it produces the desired results.
4. **Promote to Custom space** — the rule is now available for production use.
5. **Create or update a detector** to include the rule's integration, enabling active detection against incoming events.


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

**5.x Sigma-based:**
```yaml
document:
  id: "aba9b03c-9dd0-4077-b99d-0002294b42a1"
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
    tactic: ["TA0001", "TA0004"]
    technique: ["T1068", "T1190"]

  compliance:
    pci_dss: ["6.2", "6.3.3", "11.3"]
    nist_800_53: ["CA-7", "RA-5", "SI-2", "SI-4"]
    gdpr: ["32", "33"]
    hipaa: ["164.308.a.1.ii.D", "164.308.a.5.ii.B", "164.308.a.8"]
    iso_27001: ["A.12.6.1", "A.14.2.3", "A.16.1.2"]
    tsc: ["A1.2", "CC7.1", "CC7.2"]
    nis2: ["21.2.a", "21.2.e", "23"]
    nist_800_171: ["3.11.1", "3.11.2", "3.11.3", "3.14.1", "3.14.4"]
    fedramp: ["CA-7", "RA-5", "SI-2", "SI-4"]
    cmmc: ["AU.L2-3.3.1", "CA.L2-3.12.1", "RA.L2-3.11.1", "RA.L2-3.11.2", "RA.L2-3.11.3", "SI.L2-3.14.1"]

  tags:
    - "attack.initial-access"
    - "attack.privilege-escalation"
    - "attack.t1190"
    - "attack.t1068"

  falsepositives:
    - "Legitimate software with known vulnerabilities that have been accepted as a risk"

space:
  name: "standard"
```

This rule belongs to the **wazuh-vd** integration (category: `security`), so events are indexed into `wazuh-events-v5-security-*` and findings into `wazuh-findings-v5-security-*`.

### Example 2: Rule with value modifiers (contains)

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

**5.x Sigma-based:**
```yaml
document:
  id: "d166d57a-86e3-49b4-b560-db423b3c156a"
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
    tactic: ["TA0010"]
    technique: ["T1567"]

  compliance:
    pci_dss: ["3.4", "6.2", "10.2.5", "11.4"]
    nist_800_53: ["AU-6", "IR-4", "SC-28", "SI-4"]
    gdpr: ["25", "32", "33", "35"]
    hipaa: ["164.308.a.1.ii.D", "164.308.a.6", "164.312.a.2.iv", "164.312.e.1"]
    iso_27001: ["A.8.2.3", "A.12.4.1", "A.16.1.2", "A.18.1.4"]
    tsc: ["A1.2", "CC6.7", "CC7.2"]

  tags:
    - "attack.exfiltration"
    - "attack.t1567"

  falsepositives:
    - "Test files or legitimate business processes involving regulated data."
```

Note how the 4.x `if_sid` dependency is eliminated — the 5.x rule is self-contained with all conditions in the detection block. The `|contains` modifier replaces the PCRE2 regex alternation.

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

In 4.x, these are two separate rules. In 5.x, they can be consolidated into a single rule using multiple selections:

**5.x Sigma-based:**
```yaml
document:
  id: "0c5d2f15-66b4-4191-aeb7-f49fe2ab13c3"
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
    tactic: ["TA0004", "TA0005"]
    technique: ["T1562", "T1055"]
    subtechnique: ["T1562.001", "T1055.009"]

  tags:
    - "attack.privilege-escalation"
    - "attack.defense-evasion"
    - "attack.t1562.001"
    - "attack.t1055.009"

  falsepositives:
    - "Debugging or legitimate software testing"
```

The `1 of selection_*` condition means the rule fires if either `selection_syscall` or `selection_sysctl` matches.

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

**5.x Sigma-based:**
```yaml
document:
  id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
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
    tactic: ["TA0007"]
    technique: ["T1518"]

  tags:
    - "attack.discovery"
    - "attack.t1518"

  falsepositives:
    - "Normal software installation and system asset changes"
```

The 4.x regex alternation (`inserted|added|started|...`) is replaced by a list of values in the detection selection. When a field has a list of values, the rule matches if any of them are present (OR logic).

---

## WCS field mapping reference

When migrating, 4.x decoder-extracted fields must be mapped to WCS fields. For the complete list of available fields, see the [WCS field reference](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/wcs/stateless/events/main/docs/fields.csv).

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

---

## Additional resources

- [Wazuh 4.x Rules Syntax Reference](https://documentation.wazuh.com/4.9/user-manual/ruleset/ruleset-xml-syntax/rules.html)
- [Sigma Rule Specification](https://sigmahq.io/docs/basics/rules.html)
- [Wazuh Common Schema (WCS) Documentation](https://github.com/wazuh/wazuh-indexer-plugins/tree/main/wcs/stateless/events/main/docs/README.md)
- [WCS Field Reference (CSV)](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/wcs/stateless/events/main/docs/fields.csv)
- [Sigma Rules in Wazuh 5.x](https://github.com/wazuh/wazuh-indexer-plugins/blob/main/docs/ref/modules/content-manager/sigma-rules.md)