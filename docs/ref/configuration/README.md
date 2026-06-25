# Configuration

This section is the per-section/per-option reference for `wazuh-manager.conf` (`/var/wazuh-manager/etc/wazuh-manager.conf`, root tag `<wazuh_config>`). Each page documents one top-level section with all recognized options, their defaults, and allowed values verified against the parser source.

## Contents

| Section | Description |
|---------|-------------|
| [global](global.md) | Agent disconnection timing |
| [logging](logging.md) | Internal log format |
| [remote](remote.md) | Agent listener (port, protocol, queue) |
| [auth](auth.md) | Enrollment service (authd) |
| [indexer](indexer.md) | Wazuh Indexer connection |
| [vulnerability-detection](vulnerability-detection.md) | CVE scanner |
| [socket](socket.md) | Named output sockets for Logcollector |
| [agent-upgrade / task-manager](agent-upgrade.md) | Remote agent upgrade and task lifecycle |
| [wazuh_db](wazuh-db.md) | Database backup |
| [cluster](cluster.md) | Manager cluster configuration and deployment requirements |
| [wodle-command](wodle-command.md) | `<wodle name="command">` — scheduled OS command execution |
| [wodle-docker](wodle-docker.md) | `<wodle name="docker-listener">` — Docker event monitoring |
