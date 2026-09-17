# `wazuh-migrate-identity.py`

Carries a 4.x manager's agent identity data into a fresh 5.0 installation.

A 4.x manager cannot be upgraded in place. The 5.0 manager is a fresh installation in a new path,
run by a new system user, and it starts empty. Everything that identifies the fleet has to be moved
by hand: agent keys, the agent registry, group membership, the enrollment password and the API
users, each with its own ownership rules, plus a schema transform for the registry that a plain copy
cannot do. This performs that move and checks the result.

It implements the identity half of
[Migrating a Wazuh manager from 4.x to 5.0](../../docs/guide/migration/manager-4x-to-5x.md). It does
not touch the configuration: `ossec.conf` has no mechanical translation to `wazuh-manager.conf`, and
that guide covers it separately.

Standard library only, so it runs on the 4.x host without installing anything. On a manager with no
`sqlite3` package the bundled interpreter works too:
`/var/wazuh-manager/framework/python/bin/python3`.

## Use

```bash
# on the 4.x manager, stopped
sudo ./wazuh-migrate-identity.py export /root/wazuh-4x-bundle --with-password

# move the bundle to the 5.0 host: it carries agent keys and API password hashes

# on the 5.0 manager, installed and stopped
sudo ./wazuh-migrate-identity.py import /root/wazuh-4x-bundle --with-password --with-rbac

# start the manager, then
sudo ./wazuh-migrate-identity.py check /root/wazuh-4x-bundle
```

`--dry-run` reports what `export` and `import` would do and changes nothing. Run it first.

## What moves

| Data | 4.x | 5.0 | Notes |
|---|---|---|---|
| Agent keys | `etc/client.keys` | `etc/client.keys` | `wazuh-manager:wazuh-manager 0640`. `wazuh-manager-authd` rewrites this file after dropping privileges, so the 4.x `root:wazuh` ownership stops enrollment. |
| Agent registry | `queue/db/global.db` | rows copied into the target's `queue/db/global.db` | The 4.x file cannot replace the target's: 5.0 stamps `PRAGMA user_version` and refuses anything else. |
| Group folders | `etc/shared/<group>/` | same | `default` is excluded: 5.0 ships its own. `merged.mg` is regenerated. |
| Enrollment password | `etc/authd.pass` | `etc/authd.pass` | `--with-password`. Optional by default: only 4.x agents use it. See the guide before deciding. |
| API users, roles, policies | `api/configuration/security/rbac.db` | same | `--with-rbac`. |

Not carried: agent labels and the `info` table, both removed in 5.0; the manager configuration; rules,
decoders and CDB lists. The 4.x `ossec.conf`, `local_internal_options.conf` and `api.yaml` are copied
into the bundle's `reference/` directory for you to translate by hand, and are never installed.

### The registry transform

Only the columns both schemas define are carried. `os_type` is derived from the 4.x `os_platform`,
which 5.0 splits into a family plus the platform. `connection_status` is set to `disconnected` and
`disconnection_time` to `0` for every agent rather than carried: an agent is disconnected until it
actually reaches the new manager, and a stale `active` misreports the fleet until each one
reconnects. Row `0` is the manager itself and is skipped. Columns 5.0 added and 4.x never had keep
their defaults, which is the correct state for a migrated agent.

The columns dropped and filled in are printed on every run, so a schema that moves under the tool is
visible rather than silent.

### The RBAC database

4.x and 5.0 both stamp RBAC schema version `1`, so a copied database is taken for a current one and
keeps the 4.x **default** policies: the ones 5.0 added, enrollment-token minting among them, are
never created, and no role can use them. `import --with-rbac` therefore sets the version to `0`,
which is what asks the API for its supported upgrade. On the next start it rebuilds the defaults from
5.0 and migrates across the users, roles, policies and rules an operator created, with their
passwords. `check` reports whether that has happened yet.

## Refusals

Everything that can refuse runs before anything is written, so a refused run never leaves half a
migration behind. `--force` overrides each one; none of them is a guess.

- The source is not a 4.x installation, or the target is not a 5.0 one.
- Either manager is running. Both are read and written underneath live daemons otherwise.
- The target is a cluster worker. Its registry and keys come from the master.
- The source registry reports a `db_version` this tool has not been checked against.
- The target registry is at a schema version this tool was not written against.
- The target registry already holds agents, which an import would overwrite by id.
- A bundle file does not match its manifest checksum, or the group archive contains a path outside
  the group tree.

`import` keeps a `.pre-migration` copy of every file it overwrites.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Done, or `check` found no problems |
| `1` | `check` found problems, listed on standard output |
| `2` | Refused, with the reason on standard error |

## Tests

```bash
python3 tools/migration/test_wazuh_migrate_identity.py
```

They build a 4.x and a 5.0 tree in a temporary directory, using the repository's own
`src/wazuh_db/schemas/schema_global.sql` as the target schema, and exercise the round trip along
with each refusal.
