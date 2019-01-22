---
name: 'Test: Upgrade'
about: Test suite for upgrade.

---

# Upgrade test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## RPM (Linux)

- [ ] Install new version.
- [ ] Check_files.
- [ ] Check that the databases are purged.
- [ ] Check that the service are restarted.

## DEB (Linux)

- [ ] Install new version.
- [ ] Check_files.
- [ ] Check that the databases are purged.
- [ ] Check that the service are restarted.

## macOS

- [ ] Install new version.
- [ ] Check_files.
- [ ] Check that the service are restarted.

## Solaris (Intel)

- [ ] Install new version.
- [ ] Check_files.
- [ ] Check that the service are restarted.

## Solaris (SPARC)

- [ ] Install new version.
- [ ] Check_files.
- [ ] Check that the service are restarted.

## HP-UX

- [ ] Install new version.
- [ ] Check_files.
- [ ] Check that the service are restarted.

## AIX

- [ ] Install new version.
- [ ] Check_files.
- [ ] Check that the service are restarted.

## Sources

- [ ] Check the upgrade building the source code.
- [ ] Check that the databases located at _var/db_ are purged.
- [ ] Check that the databases located at _queue/db_ are upgraded.

## Remote upgrades (WPK)

- [ ] Upgrade an agent remotely (Linux and Windows) and check the _upgrade.log_  (Use UDP and TCP).
- [ ] Upgrade an agent with a custom WPK.
- [ ] Upgrade an agent without CA verification.
- [ ] Downgrade an agent (option `-F`).
