---
name: 'Test: Logcollector'
about: Test suite for Logcollector.

---

# Logcollector test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Configuration

- [ ] Add log.
- [ ] Delete all localfile entries and start Logcollector.
- [ ] Test Logcollector internal options.

## Logs

- [ ] Solve the reading of a file when changing its inode.
- [ ] Check that Eventlog logs are read in all supported versions of Windows.
- [ ] Rotate file.
- [ ] Check for new paths that match a wildcards after starting Logcollector.
- [ ] Check **all the tests** changing the order of the parameters in combination with normal and daily wildcards.
- [ ] Check that labels are added to JSON files.
- [ ] Check that the multi-line logs are taken correctly.
- [ ] Check that no duplicate files are scanned (entered multiple times).

## Performance

- [ ] Monitor the memory wasted by Logcollector in the previous operations.

## Sockets

- [ ] Configure one and multiple sockets output as target. (https://github.com/wazuh/wazuh/pull/395)
- [ ] Test the `out_format` option for different socket targets. (https://github.com/wazuh/wazuh/pull/863)

## COmmands

- [ ] Prevent remote commands, with `command` or `full_command`, if `logcollector.remote_commands` is enabled.
- [ ] Check that the output of a command is captured line by line (with `command`) and completely (with `full_command`)
- [ ] Check the correct output of *netstat* commands.
