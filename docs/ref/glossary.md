# Glossary

> Draft — definitions derived from the 5.0 documentation and source tree; pending team review.

**Active Response (AR)** — Automated action executed on an agent in reaction to a
detection. In 5.0, ARs are defined in the Dashboard and dispatched by the manager
through `wazuh-manager-remoted`; executions are recorded in the
`wazuh-active-responses` data stream.

**Agent** — Endpoint component that collects logs, inventory, and security data
and sends them to the manager over an encrypted TCP connection (port 1514).

**Agent group** — Named set of agents that receive a shared configuration
(`agent.conf`) from the manager. In 5.0 the group is declared by the agent during
enrollment.

**`agent.conf`** — Shared configuration file distributed per agent group from
`etc/shared/<group>/` on the manager; its values take precedence over the agent's
local `ossec.conf`.

**Cluster** — Set of manager nodes (one master, multiple workers) that share
agent keys, group configuration, and runtime state through
`wazuh-manager-clusterd` (port 1516).

**Decoder** — Engine artifact that parses and normalizes raw events into
structured fields. In 5.0 decoders are written in YAML (legacy 4.x XML decoders
must be migrated).

**Engine** — The 5.0 event processing pipeline (process name
`wazuh-manager-analysisd`): decoding, optional enrichment (GeoIP/ASN and IOC),
filtering, and output to the indexer. It replaces the legacy `analysisd`
rules pipeline.

**Enrollment** — Handshake through which an agent registers with the manager
(`wazuh-manager-authd`, port 1515), obtains its key, and declares its agent
group.

**Event** — Normalized record produced by the Engine from raw input. Events that
do not match any detection are indexed under `wazuh-events-v5-*`.

**Finding** — Detection result produced by the Engine when a rule matches; the
5.0 replacement for 4.x alerts. Indexed under `wazuh-findings-v5-*` with rule
metadata in `wazuh.rule.*`.

**FIM (File Integrity Monitoring)** — Module (`syscheck`) that detects changes
in files and Windows registry entries.

**Indexer** — OpenSearch-based component that stores events, findings, and
state indices, and hosts the Alerting and Notifications plugins.

**Indexer connector** — Manager-side component that ships data directly to the
Wazuh Indexer, replacing the 4.x Filebeat sidecar.

**Internal options** — Low-level tuning keys read from
`etc/wazuh-manager-internal-options.conf` (manager) or
`etc/local_internal_options.conf` (agent).

**IT Hygiene** — Dashboard capability built on the Syscollector inventory
(processes, packages, users, groups, services, browser extensions…), replacing
the 4.x OSquery integration.

**KVDB** — Key-value database used by Engine decoders and rules for lookups,
replacing the 4.x CDB lists.

**Rule** — Engine artifact (YAML in 5.0) that evaluates decoded events and
produces findings, carrying severity, MITRE, and compliance metadata.

**SCA (Security Configuration Assessment)** — Module that evaluates hosts
against YAML policy files (CIS benchmarks and custom policies); the 5.0
replacement for CIS-CAT and OpenSCAP integrations.

**Server API** — RESTful management API (`wazuh-manager-apid`, port 55000) with
JWT authentication and RBAC.

**Space** — Engine namespace that scopes content (decoders, rules, outputs);
events carry the space name in `wazuh.space.name`.

**Syscollector** — Agent module that collects system inventory and feeds the
`wazuh-states-inventory-*` indices and Vulnerability Detection.

**Vulnerability Detection** — Module that correlates the Syscollector inventory
against CVE content delivered by the Wazuh CTI service (the 4.x offline feed is
gone).

**WCS (Wazuh Common Schema)** — Field naming convention (aligned with ECS) used
across 5.0 indices and event payloads, e.g. `source.ip`, `user.name`,
`wazuh.rule.level`.

**`wazuh-manager.conf`** — Main manager configuration file
(`/var/wazuh-manager/etc/wazuh-manager.conf`, root tag `<wazuh_config>`); the
5.0 rename of the manager-side `ossec.conf`.

**Wodle** — Pluggable module configured as `<wodle name="...">` and executed by
`wazuh-manager-modulesd` (manager) or `wazuh-modulesd` (agent), e.g. `command`,
`syscollector`.
