# Compatibility

## Operating systems

The supported operating systems and architectures are listed once, per package:

- Server: [Requirements](getting-started/requirements.md#operating-system-requirements) and
  [Packages → Server](getting-started/packages.md#server).
- Agent: [Packages → Agent](getting-started/packages.md#agent).

## Agent and manager versions

- **5.x agents** connect over HTTPS on port 1517 and enroll there (`POST /enroll`).
- **4.x agents** connect only through the legacy listener (port 1514), which exists only while
  [`<remote><legacy><enabled>`](modules/remoted/configuration.md#legacyenabled) is on (the configuration the
  installer generates turns it on); with it off, only 5.x agents can connect. They enroll through
  `wazuh-manager-authd`'s TLS port 1515, gated by `<auth><legacy_enrollment>`, which follows
  `<remote><legacy><enabled>` when it is not set. A 4.x agent upgrades to 5.x
  only from 4.14.0 or later, by package or remotely (see [Agent upgrades](modules/task_manager/agent-upgrades.md));
  an older one has to reach 4.14 first.
- **An agent newer than the manager** (a higher major or minor; a higher patch is always accepted) is
  refused unless
  [`<remote><agents><allow_higher_versions>`](modules/remoted/configuration.md#agentsallow_higher_versions) is
  `yes`, and, for enrollment, authd's own `<auth><agents><allow_higher_versions>` as well.

## Manager versions

- **Cluster nodes** must run exactly the same Wazuh version: the master refuses any other worker with
  error `3031` (see [Cluster upgrade](upgrade.md#cluster-upgrade)).
- **A 4.x manager cannot be upgraded to 5.x**, and a 5.x manager package refuses to install on a host
  that holds a 4.x manager: a 5.x manager is always a fresh installation (see [Upgrade](upgrade.md)).
