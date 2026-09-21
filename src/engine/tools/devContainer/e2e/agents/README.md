# Agents E2E — real 4.x and 5.x agents against the devcontainer's manager

Four containers built from the official agent packages, pointed at the manager installed in the
devcontainer (`host.docker.internal` = the host). They exist so a change can be proven with a real
agent enrolling and connecting, not with a simulator. The scripts here are the same ones the
VS Code tasks `E2E Scripts: [Agent] …` and the Claude skill `agent-env` run.

## Layout

```
agents/
├── init.sh              downloads the four installers into pkgs/ (4.x from packages.wazuh.com, 5.x from the nightly manifests)
├── create_token.sh      mints an enrollment token on the manager → env file (token + authd password), 0600
├── docker-compose.yml   agent_{4x,5x}_{centos,ubuntu}; credentials come from `--env-file`
├── entrypoint.sh        4.x: agent-auth (1515, password) · 5.x: token → <endpoint> + etc/enrollment_token → POST /enroll
├── verify_agents.sh     PASS/FAIL per agent: client.keys, global.db, agent log, trust anchor, manager log, API
├── {ubuntu,centos}/{4.x,5.x}/Dockerfile
└── pkgs/                the .deb/.rpm files (gitignored)
```

## How enrollment works here

| | 4.x | 5.x |
|---|---|---|
| Path | `agent-auth -A <name> -m host.docker.internal -p 1515 -P <password>` | `wazuh-agentd` token bootstrap: `GET /cacerts` → pin check → `POST /enroll` with a `wazuh-enroll+jwt` bearer (kid = token id) on 1517. **Never 1515.** |
| Credential | the manager's `etc/authd.pass` (`<auth><use_password>yes</use_password>` is the default) | an enrollment token minted with `wazuh-manager-authd --create-enrollment-token --address host.docker.internal` (the token carries host, port, prefix, the CA pin and the secret) |
| Configured by | `entrypoint.sh` (`<client><server>` address/port from `MANAGER_HOST`/`MANAGER_PORT`) | `entrypoint.sh`, with the same three effects as the packaged `register_configure_agent.sh` — which the postinst removes together with `/var/ossec/packages_files`, so it is absent at container start, and is used when present: `<agent><manager><endpoint>` from the token's address (decoded with `wazuh-agentd --show-token`), `<enrollment><agent_name>`, and `etc/enrollment_token` 0600 root, unlinked by the agent once the bootstrap succeeds |
| Success (agent log) | `agent-auth: INFO: Valid key received` then `(4102): Connected to the server` | `INFO: Token bootstrap: enrollment succeeded; the manager's CA is now the agent's trust anchor.` |
| Success (manager) | `etc/client.keys` + `global.db` (authd logs the 1515 path at debug level only) | `wazuh-manager-authd: INFO: Enrollment token '<id>' consumed by agent '<name>'.` and `Recorded credentials of agent '<name>' written to the database` |

Reference: `docs/ref/modules/authd/enrollment-lifecycle.md`, `docs/ref/modules/authd/README.md#enrollment-tokens`,
`docs/ref/modules/remoted/https-events-api.md#enrollment-endpoint-post-enroll`.

## Quick start

Prerequisites: docker + compose v2, `curl`; a running manager (`sudo ../wazuh_verify_manager.sh` → 7/7) whose
listeners bind to `0.0.0.0` (`../init.sh` does that) and whose listener certificate names
`host.docker.internal` in its SAN (the devcontainer's `scripts/wazuh-certs-tool.yml` does).

```bash
./init.sh                                   # packages into pkgs/ (a stale 5.x "latest" is refreshed automatically; --check reports, --force redownloads)
sudo ./create_token.sh --env-file /tmp/wazuh-e2e-agents.env --meta /tmp/wazuh-e2e-agents.meta --max-uses 2   # 0600; never printed
docker compose --env-file /tmp/wazuh-e2e-agents.env -f docker-compose.yml up -d --build agent_5x_ubuntu agent_4x_ubuntu
sudo ./verify_agents.sh --api --expect 2 --wait 120    # PASS/FAIL lines + "# summary:" + agents-manifest.md under --out
rm -f /tmp/wazuh-e2e-agents.env                         # the containers already hold what they need
```

VS Code: `[Agent] Init setup (download pkgs)` → `[Agent] Create enrollment token` → `[Agent] Up (start containers)`
→ `[Agent] Verify enrollment`; `[Agent] Reset (down -v)` wipes the volumes (and therefore the enrolled keys);
`[Agent] Check packages (--check)` / `[Agent] Re-download packages (--force)` manage `pkgs/`.

The 5.x package must be one that carries the token bootstrap (`--show-token` in `wazuh-agentd`): the nightly
`5.0.0-latest` does; `init.sh --check` tells you whether `pkgs/` is stale. A 5.x package without it cannot enroll
here at all — the entrypoint refuses to start it unenrolled rather than falling back to a password.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| 4.x: `Invalid password provided by …` in the manager log | `AUTHD_PASSWORD` empty or wrong | run `create_token.sh` (it copies `etc/authd.pass`) and start with `--env-file` |
| 5.x: `[entrypoint] ERROR: WAZUH_ENROLLMENT_TOKEN is empty` | compose started without `--env-file` | mint + `up` with `--env-file` |
| 5.x: `[entrypoint] ERROR: wazuh-agentd --show-token refused the token` or `Deployment variables refused [ERR_BAD_TOKEN]` | the token was altered (quotes, line breaks), or the package predates the token bootstrap | re-mint; the env file must hold the raw token. For an old package: `init.sh --force`, then `down -v` and `up --build` — the volume keeps the old `/var/ossec` otherwise |
| 5.x: `Enrollment-token bootstrap failed; refusing to enroll unverified` | `GET /cacerts` unreachable/404, or the served CA does not match the token's pin (CA rotated after minting) | `curl -sk https://127.0.0.1:1517/wazuh-manager/cacerts`; re-mint after a CA rotation |
| 5.x: HTTP 401/403 on `/enroll` | 401 = bearer refused; 403 with 9022/9023/9024 = token unknown-or-revoked / expired / out of uses | `wazuh-manager-authd --list-enrollment-tokens`; mint a new one |
| 5.x: HTTP 404 | wrong port/prefix in the token's address | mint with `--port`/`--prefix` matching `wazuh-manager-conf get remote` |
| `Transport endpoint is not connected` | listeners bound to 127.0.0.1 | `../init.sh --certs-only --reuse-certs` (opens them) and restart the manager |
| agent `version` newer than the manager refused | `<remote><agents><allow_higher_versions>no` | use a manager built from a branch at least as new as the nightly, or set it to `yes` for the test |
| `Duplicate name` | a previous container enrolled with the same name | `docker compose down -v` (or remove the agent with the API) |

`docker compose down` keeps the volumes (the agents reconnect with their keys); `down -v` starts from scratch and
the next `up` enrolls again — mint a token with enough `--max-uses`, or a new one. **After refreshing `pkgs/`,
`down -v` is mandatory**: the volume holds the whole `/var/ossec` (binaries included) copied from the image that
first created it, so `up --build` with a new package keeps running the old `wazuh-agentd` until the volume is recreated.
