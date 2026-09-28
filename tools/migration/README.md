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
the two in step. This tool holds no copy of the 5.0 schema, no table of file modes for the registry
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

Both read the API password the manager published at install; `--api-password-file` is for when it
is somewhere else.

`--dry-run` reports what `export` and `import` would do and changes nothing. Run it first.

The API password is read, in order, from `--api-password-file` (`-` for standard input), from
`WAZUH_API_PASSWORD` or `WAZUH_MANAGER_API_PASSWORD` in the environment, from the
`WAZUH_MANAGER_API_PASSWORD` the manager published in `/etc/wazuh/credentials.env` when it generated
one at install, or prompted for on a terminal. Never from the command line, because `ps` is
world-readable. The credentials file is parsed as `KEY=VALUE` and never sourced, the way the manager
itself reads it.

One consequence of `--with-rbac` is worth knowing before you use it: the manager never reseeds an
existing `rbac.db`, so from the next start the `wazuh` and `wazuh-wui` passwords are the 4.x ones
the database carries, and the two values in `credentials.env` are stale. The import says so. Either
set both users back to the published values with `rbac_control change-password` after the restart,
or keep the 4.x passwords and give `check` the 4.x one explicitly.

## What moves

| Data | How |
|---|---|
| Agents: id, name, address and key | `POST /agents/insert` per agent. The manager writes `client.keys` and the registry row itself |
| Groups | `POST /groups` per custom group. `default` is the target's own and is never recreated |
| Each group's `agent.conf` | `PUT /groups/{group}/configuration` |
| Group membership | `PUT /agents/{id}/group/{group}` in the 4.x priority order |
| Enrollment password | file copy, `--with-password` at both ends |
| API users, roles and policies | file copy, `--with-rbac` at both ends |

**What it does not carry.** The registration date: `POST /agents/insert` does not accept one, so a
migrated agent's `dateAdd` is the moment it was inserted. The agent's recorded version and operating
system are not carried either, but those the manager refreshes from the agent's first keepalive.
Agent labels and the 4.x `info` table were removed in 5.0. Rules, decoders and CDB lists are their
own migration; see the guides for each.

**Files in a group folder other than `agent.conf`** are reported and left behind. No endpoint
uploads them, and 5.0 compiles everything in a group folder into what it pushes to that group's
agents, so a 4.x CDB list or rootcheck file would be distributed to the fleet with no meaning
attached. `export` names each one so the decision is yours rather than silent.

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
- The bundle is truncated, or comes from a different bundle version.

Anything the manager itself refuses is reported in the manager's own words, per item, and the run
ends with exit `1` rather than pretending it succeeded. `--force` overrides this tool's own checks;
it cannot override the manager's.

The two file copies keep a `.pre-migration` copy of whatever they overwrite, and never overwrite an
earlier one: a second import writes `.pre-migration.<timestamp>` instead of skipping the backup.

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
