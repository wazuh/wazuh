# `wazuh-migrate-identity.py`

Carries a 4.x manager's agent identity into a fresh 5.0 installation.

A 4.x manager cannot be upgraded in place. The 5.0 manager is a fresh installation that starts
empty, so the agents, the groups they belong to and the configuration those groups carry have to be
moved across. This does that, and checks the result.

It implements the identity half of
[Migrating a Wazuh manager from 4.x to 5.0](../../docs/guide/migration/manager-4x-to-5x.md). It does
not touch the configuration: `ossec.conf` has no mechanical translation to `wazuh-manager.conf`, and
that guide covers it separately.

Standard library only, so it runs on either host without installing anything.

## The shape of it

The two halves are deliberately asymmetric.

The 4.x manager is being decommissioned and its files are the only thing left to read, so **`export`
reads them directly**, with the manager stopped.

The 5.0 manager is the one that has to end up correct, so **`import` never writes its files**. Every
agent, group and membership is created through the manager's own API, which means the manager
validates each one, writes `client.keys` and the registry itself, with its own ownership, and keeps
the two in step. The exceptions are files no endpoint accepts: the two opt-in credentials and the
SCA policy files a group loads. This tool holds no copy of the 5.0 schema, no table of file modes for the registry
and no idea what `client.keys` looks like. When the product changes any of that, nothing here has to
follow.

The price is that the manager has to be **running** for the import, which is the opposite of what
the manual procedure needs. That is not the inconvenience it sounds like: a migration should install
the manager with its agent listeners pointed away from the fleet anyway, so that no agent reaches an
empty registry and re-enrolls, and a manager in that state serves the API on loopback perfectly
well. The guide's step 2 covers it.

## Use

```bash
# on the 4.x manager, stopped
sudo ./wazuh-migrate-identity.py export /root/wazuh-4x-bundle

# move the bundle to the 5.0 host: it carries agent keys

# on the 5.0 manager, installed, running, and not yet reachable by the fleet
sudo ./wazuh-migrate-identity.py import /root/wazuh-4x-bundle

# open the manager to the fleet, then
sudo ./wazuh-migrate-identity.py check /root/wazuh-4x-bundle
```

`import` and `check` read the API password the manager published at install; `--api-password-file`
is for when it is somewhere else.

| Option | Commands | Default | Effect |
|---|---|---|---|
| `--source-dir DIR` | `export` | `/var/ossec` | The 4.x installation to read |
| `--target-dir DIR` | `import`, `check` | `/var/wazuh-manager` | The 5.0 installation |
| `--target-conf-dir DIR` | `import`, `check` | `/etc/wazuh-manager` | The 5.0 configuration directory (outside the installation): where `authd.pass` is installed and `certs/root-ca.pem` is read |
| `--api-url URL` | `import`, `check` | `https://localhost:55000` | The manager's Server API |
| `--api-user USER` | `import`, `check` | `wazuh` | The API user |
| `--api-password-file FILE` | `import`, `check` | — | File holding the API password, `-` for standard input |
| `--api-ca FILE` | `import`, `check` | the target's `certs/root-ca.pem` under `--target-conf-dir`, for a loopback `--api-url` only | CA bundle to verify the API certificate with; required for any other `--api-url` |
| `--with-password` | `export`, `import` | off | Carry the shared enrollment password, from the source's `etc/authd.pass` to `authd.pass` under `--target-conf-dir`. A password shorter than 16 bytes, the 5.0 minimum, is refused at `import` (and warned about at `export`) |
| `--with-rbac` | `export`, `import` | off | Carry the API users, roles and policies |
| `--dry-run` | `export`, `import` | off | Report what would happen and change nothing |
| `--force` | `export`, `import` | off | Proceed past this tool's safety checks |
| `--version` | — | — | Print the tool version |

`--dry-run` reports what `export` and `import` would do and changes nothing. Run it first: it ends
with the same **Review before going on** list as the real `export`, printed once on standard output.
The list names, per group (`default` included), every `agent.conf` setting 5.0 agents ignore
(`<labels>`, `<client_buffer>`, `<integration>`... with what to use instead), every file left
behind and every SCA policy carried. It also names the features the 4.x manager's `ossec.conf`
configures that stop at cutover (integrations, email, syslog output, agentless, active responses,
OpenSCAP and CIS-CAT, syslog input, and the monitoring of the server's own host), each with the
migration guide that rebuilds it. `import` prints the list again from the bundle.

The API password is read, in order, from `--api-password-file` (`-` for standard input), from
`WAZUH_API_PASSWORD` or `WAZUH_MANAGER_API_PASSWORD` in the environment, from the
`WAZUH_MANAGER_API_PASSWORD` the manager published in `/etc/wazuh-manager/export/credentials.env` when it generated
one at install, or prompted for on a terminal. Never from the command line, because `ps` is
world-readable. The credentials file is parsed as `KEY=VALUE` and never sourced, the way the manager
itself reads it.

The connection to the API is always verified, chain and host name, because it carries that password
and every agent key. Against a loopback `--api-url` the tool trusts the CA the manager issued
`apid.pem` from at install, `certs/root-ca.pem` under `--target-conf-dir`; any other address needs
`--api-ca`, and plain `http://` is accepted only on loopback.

One consequence of `--with-rbac` is worth knowing before you use it: the manager never reseeds the
passwords of an existing `rbac.db` (its version upgrade copies every user with its hash,
`check_database_integrity()` in `framework/wazuh/rbac/orm.py`), so from the next start the `wazuh` and `wazuh-internal-client` passwords are the 4.x ones
the database carries, and the two values in `credentials.env` are stale. The import says so. Either
set both users back to the published values with `rbac_control change-password` after the restart,
or keep the 4.x passwords and give `check` the 4.x one explicitly.

## What moves

| Data | How |
|---|---|
| Agents: id, name, address and key | `POST /agents/insert` per agent. The manager writes `client.keys` and the registry row itself |
| Groups | `POST /groups` per custom group. `default` is the target's own and is never recreated |
| Each group's `agent.conf` | `PUT /groups/{group}/configuration` |
| The `default` group's `agent.conf`, when the 4.x one sets anything | Appended after the 5.0 one with `PUT /groups/default/configuration`, so both apply. A second import finds it there and leaves the file alone |
| SCA policy files a group's `agent.conf` loads | File copy into the group folder, `wazuh-manager:wazuh-manager 0660`, before the `agent.conf` that loads them |
| Group membership | Exactly the 4.x groups, in the 4.x priority order. The manager inserts every agent in `default`: the first group replaces it (`PUT /agents/{id}/group/{group}?force_single_group=true`) and the rest are appended, `default` included where 4.x had it |
| Enrollment password | file copy, `--with-password` at both ends |
| API users, roles and policies | file copy, `--with-rbac` at both ends |

**What it does not carry.** The registration date: `POST /agents/insert` does not accept one, so a
migrated agent's `dateAdd` is the moment it was inserted. The agent's recorded version and operating
system are not carried either, but those the manager refreshes from the agent's first keepalive.
Agent labels and the 4.x `info` table were removed in 5.0. Rules, decoders and CDB lists are their
own migration; see the guides for each.

**SCA policy files** are carried when the group's `agent.conf` loads them: a `<policy>` under
`<sca>` whose path is the agent's shared directory and the file name (`etc/shared/<file>` on Linux
and macOS, `shared\<file>` on Windows). 5.0 agents still run them.

**Other files in a group folder** are reported and left behind. No endpoint uploads them, and 5.0
compiles everything in a group folder into what it pushes to that group's agents, so a 4.x CDB list
or rootcheck file would be distributed to the fleet with no meaning attached. `export` names each
one so the decision is yours rather than silent. The rootcheck lists every 4.x installation ships
in `default` are not named.

**Agent labels** (`<labels>` in an `agent.conf`) are carried with the file, but 5.0 agents ignore
them and `agent.labels.*` no longer reaches events. The review names every group that sets them;
group membership (`wazuh.agent.groups`) is the closest replacement.

### The RBAC database

4.x and 5.0 both stamp RBAC schema version `1`, so a copied database is taken for a current one and
keeps the 4.x **default** policies: the ones 5.0 added, enrollment-token minting among them, are
never created, and no role can use them. `import --with-rbac` therefore sets the version to `0`,
which is what asks the API for its supported upgrade. On the next start it rebuilds the defaults
from 5.0 and migrates across the users, roles, policies and rules an operator created, with their
passwords.

## Refusals

Everything that can refuse runs before the first write.

- The source is not a 4.x installation, or the target is not a 5.0 one.
- The 4.x manager is still running. Its files would be read underneath live daemons.
- The source registry reports a `db_version` this tool has not been checked against.
- The target already holds agents, which an import would collide with by id.
- The bundle is truncated, or comes from a bundle version this tool does not read. Version 2
  bundles (tool 2.x) are imported with a notice: they carry neither the default group nor the SCA
  policy files.

Anything the manager itself refuses is reported in the manager's own words, per item, and the run
ends with exit `1` rather than pretending it succeeded. A `default` group configuration the manager
refuses is reported the same way and does not stop the agents from going in. `--force` overrides this tool's own checks;
it cannot override the manager's.

The two file copies keep a `.pre-migration` copy of whatever they overwrite, and never overwrite an
earlier one: a second import writes `.pre-migration.<timestamp>` instead of skipping the backup.

## What `check` compares

Every agent of the bundle is present with its name and exactly its 4.x groups in the 4.x order (a
group missing, a group it was not in, `default` included, and a different order are each a
problem); no agent is present that the bundle did not carry; every group exists; the `default`
group holds the 4.x settings the bundle carried; every carried SCA policy is in its group folder.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Done, or `check` found no problems |
| `1` | Something was refused by the manager, or `check` found problems |
| `2` | Refused before doing anything, with the reason on standard error |

## Tests

```bash
python3 tools/migration/test_wazuh_migrate_identity.py
```

`export` runs against a 4.x installation tree built in a temporary directory. `import` and `check`
run against a stub of the manager's API that implements the endpoints the tool uses and records what
it was asked to do, so the assertions are about the calls the tool makes rather than about files it
no longer writes. The stub enforces the same content types the real endpoints do.

The TLS case mints a certificate with `openssl` and is skipped without it; CI
([5_testunit_migration.yml](../../.github/workflows/5_testunit_migration.yml)) fails the job when
`openssl` is missing rather than let it skip.
