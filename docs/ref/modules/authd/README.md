# Authd (Enrollment Service)

`wazuh-manager-authd` handles agent enrollment. It listens for agent registration requests over TLS, validates credentials, generates cryptographic keys, and writes the resulting entries to the agent keystore.

Source: `src/os_auth/`

For configuration options see [Auth Configuration](../../configuration/auth.md).

## How it works

1. Agent connects to port 1515 over TLS.
2. If `use_password` is enabled (the default for new installations), the agent must send the enrollment password (`OSSEC PASS: <password>`). The password is auto-generated on the manager at first start and must be copied to each agent before enrollment; see [Agent-side setup](../../configuration/auth.md#use_password).
3. If mutual TLS is configured (`ssl_agent_ca`), the agent's certificate is verified.
4. The agent sends an enrollment request:
   ```
   OSSEC A:'<agent_name>' V:'<version>'
   ```
5. Authd validates the agent name, checks for existing registrations (applying `force` rules if configured), generates a random key pair, and queues the entry for persistence.
6. The agent key is written to `/var/wazuh-manager/etc/client.keys` by a background writer thread.
7. The response is sent back to the agent over the same TLS connection.

## Threads

| Thread | Role |
|--------|------|
| Remote server | Accepts TLS connections on port 1515 (when `remote_enrollment` is `yes`) |
| Local server | Handles enrollment via the local Unix socket `queue/sockets/auth` |
| Writer | Periodically flushes the in-memory key queue to `client.keys` on disk |

## Storage

| File | Contents |
|------|----------|
| `/var/wazuh-manager/etc/client.keys` | One line per agent: `<id> <name> <ip> <key>` |
| `/var/wazuh-manager/etc/agents-timestamp` | Per-agent registration timestamp |
| `/var/wazuh-manager/etc/authd.pass` | Enrollment password (auto-generated on first start; required by default) |

## Force re-enrollment

The `<force>` sub-block controls when an agent may overwrite an existing registration:

- `enabled` — allow forced overwrite at all
- `key_mismatch` — overwrite if the agent's key does not match
- `disconnected_time` — overwrite only if the agent has been disconnected for at least this long
- `after_registration_time` — overwrite only if at least this much time has passed since the last registration

## Key source files

| File | Purpose |
|------|---------|
| `src/main-server.c` | Main loop, thread management, client pool |
| `src/auth.c` | Protocol parsing, agent validation, key generation |
| `src/local-server.c` | Local socket enrollment handler |
| `src/config.c` | Configuration loading |
