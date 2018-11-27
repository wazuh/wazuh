---
name: 'Test: Command'
about: Test suite for the wodle command.

---

# Command test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Linux

- [ ] Run a command in Linux.
- [ ] Check all options (`interval`, `ignore_output`, ...)
- [ ] Run a command that not finish (set a timeout of 0 letting the process to run indefinitely)
- [ ] Run a command that not finish.
Set a timeout other than 0 killing the process when it is reached.
- [ ] Try to run an alias (e.g. `openssl` instead of */usr/bin/openssl*).
- [ ] Verify checksums of the defined command.
- [ ] Check interval runs as expected more than the very first time.
- [ ] Try to run wodle command with `remote_commands=0`.

## Windows

- [ ] Run a command in Windows.
- [ ] Check all options (`interval`, `ignore_output`, ...)
- [ ] Run a command that not finish (set a timeout of 0 letting the process to run indefinitely).
- [ ] Run a command that not finish (set a timeout other than 0 killing the process when it is reached).
- [ ] Try to run an alias (e.g. `ipconfig`).
- [ ] Verify checksums of the defined command.
- [ ] Check interval runs as expected more than the very first time.
- [ ] Try to run wodle command with `remote_commands=0`.
