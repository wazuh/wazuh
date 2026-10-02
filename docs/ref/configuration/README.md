# Configuration Reference

The manager and the agent are configured by different files, read by different parsers:

- [Manager Configuration](manager/README.md) — `/var/wazuh-manager/etc/wazuh-manager.conf`, a strict
  XML document validated against a JSON schema (every option in the generated
  [Manager Configuration Reference](manager/reference.md)), plus
  `wazuh-manager-internal-options.conf` and the REST API's `api.yaml`.
- [Agent Configuration](agent/README.md) — `ossec.conf` under `/var/ossec/etc/` (Linux/Unix) or
  `C:\Program Files (x86)\ossec-agent\` (Windows), plus `internal_options.conf` and its
  `local_internal_options.conf` overrides.
- [Centralized Configuration](../modules/agent-management/centralized-configuration.md) — the
  group-based `agent.conf` files the manager keeps under `/var/wazuh-manager/etc/shared/<group>/` and
  distributes to the agents.

Each page lists its files, sections and internal options, and links to the module pages that own
them. For architecture, events and database schemas, see [Modules Reference](../modules/README.md).
