# Glossary

**Active Response (AR)** — Automated action executed on an agent in reaction to a
detection. In 5.0, the Indexer's Alerting/Notifications plugins write each response
into the `wazuh-active-responses*` indices; `wazuh-manager-clusterd` polls them and
records an `active_response` task per agent in the Task Manager, which the agent
receives in its next `POST /control` response to `wazuh-manager-remoted`.

**Agent** — Endpoint component that collects logs, inventory, and security data
and sends them to the manager over HTTPS on port 1517, verifying the manager's
certificate against a trust anchor it receives at enrollment. Port 1514 is the
legacy listener, kept only for agents still on 4.x.

**Agent group** — Named set of agents that receive a shared configuration
(`agent.conf`) from the manager. An agent can declare its groups when it enrolls;
they can also be assigned afterwards from the manager.

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
pipeline; detection rules are no longer evaluated on the manager (see **Rule**).

**Enrollment** — Handshake through which an agent registers with the manager,
obtains its key, and declares its agent group. A 5.x agent enrolls over HTTPS
(`POST /enroll` on Remoted's port 1517), which bridges to `wazuh-manager-authd`;
`authd` owns the registration logic either way. Its own TLS listener on port 1515
remains only for 4.x agents, gated by `<auth><legacy_enrollment>` (which follows
`<remote><legacy><enabled>` when unset).

**Event** — Normalized record produced by the Engine from raw input. Decoded
events are indexed under `wazuh-events-v5-<category>`, the category being the
integration's `wazuh.integration.category`; events left `unclassified` go to
`wazuh-events-v5-unclassified` only when the policy enables
`index_unclassified_events`.

**Finding** — The 5.0 replacement for 4.x alerts: an enriched copy of an indexed
event that matched a detection rule. Findings are produced in the Wazuh Indexer by
its Security Analytics detectors, not by the manager, and indexed under
`wazuh-findings-v5-*`.

**FIM (File Integrity Monitoring)** — Module (`syscheck`) that detects changes
in files and Windows registry entries.

**Indexer** — OpenSearch-based component that stores events, findings, and
state indices, and hosts the Alerting and Notifications plugins.

**Indexer connector** — Manager-side component that ships data directly to the
Wazuh Indexer, replacing the 4.x Filebeat sidecar.

**Internal options** — Low-level tuning keys read from
`etc/wazuh-manager-internal-options.conf` (manager) or
`etc/internal_options.conf` overridden by `etc/local_internal_options.conf` (agent).

**IT Hygiene** — Dashboard capability built on the Syscollector inventory
(processes, packages, users, groups, services, browser extensions…), replacing
the 4.x OSquery integration.

**KVDB** — Key-value database used by Engine decoders for lookups,
replacing the 4.x CDB lists.

**Rule** — Sigma-based YAML detection rule, stored in the Indexer and evaluated
there against indexed events by the Security Analytics detectors, which produce
findings. The Engine has no rule asset: its content is decoders, filters, outputs,
integrations and KVDBs.

**SCA (Security Configuration Assessment)** — Module that evaluates hosts
against YAML policy files (CIS benchmarks and custom policies); the 5.0
replacement for CIS-CAT and OpenSCAP integrations.

**Server API** — RESTful management API (`wazuh-manager-apid`, port 55000) with
JWT authentication and RBAC.

**Space** — Engine namespace that scopes content (decoders, filters, outputs,
integrations, KVDBs); events carry the space name in `wazuh.space.name`.

**Syscollector** — Agent module that collects system inventory and feeds the
`wazuh-states-inventory-*` indices and Vulnerability Detection.

**Vulnerability Detection** — Module that correlates the Syscollector inventory
against CVE content delivered by the Wazuh CTI service (the 4.x offline feed is
gone).

**WCS (Wazuh Common Schema)** — Field naming convention (aligned with ECS) used
across 5.0 indices and event payloads, e.g. `source.ip`, `user.name`,
`wazuh.integration.category`.

**`wazuh-manager.conf`** — Main manager configuration file
(`/var/wazuh-manager/etc/wazuh-manager.conf`, root tag `<wazuh_config>`); the
5.0 rename of the manager-side `ossec.conf`.

**Wodle** — Agent module configured as `<wodle name="...">` in the agent's
`ossec.conf` or a group's `agent.conf` and run by the agent's `wazuh-modulesd`,
e.g. `command`, `syscollector`, `aws-s3`. The manager's configuration has no
`<wodle>` element.
