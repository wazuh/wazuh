# Description

The **Wazuh Manager** is the central server component of the Wazuh platform. It
receives data from deployed Wazuh Agents, processes it, and forwards the results
to the Wazuh Indexer, where they are stored and later explored through the Wazuh
Dashboard.

Its main responsibilities are:

- **Agent management**: enrollment, connection handling, agent groups, and
  centralized configuration distribution (`wazuh-manager-authd`,
  `wazuh-manager-remoted`).
- **Event processing**: decoding, enrichment, and detection through the
  **Engine** (`wazuh-manager-analysisd`), which in 5.0 replaces the legacy
  rules pipeline with YAML decoders and rules, KVDB lookups, and structured
  findings indexed as `wazuh-findings-v5-*`.
- **Security modules**: orchestration of inventory (Syscollector / IT Hygiene),
  configuration assessment (SCA), file integrity monitoring (FIM), and
  vulnerability detection fed by the Wazuh CTI service.
- **Management plane**: a RESTful Server API (`wazuh-manager-apid`) with RBAC,
  and a cluster mode (`wazuh-manager-clusterd`) for horizontal scaling and high
  availability.

The manager is a multi-daemon system installed under `/var/wazuh-manager` and
configured through `etc/wazuh-manager.conf`. See the
[Architecture](architecture.md) page for the full component breakdown and the
[Modules](modules/README.md) section for per-module documentation.
