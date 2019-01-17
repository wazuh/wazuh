---
name: 'Test: Syscheck'
about: Test suite for Syscheck

---

# Testing: Syscheck

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Any

- [ ] Check if ignore files and folders using tag <ignore> and restrict option (string or sregex) in both options.
- [ ] Check if delete content in _/var/ossec/queue/diff_ when deleting any tag <directories report_changes="yes">
- [ ] Check if delete content in _/var/ossec/queue/diff_ when report_changes option passed yes to no.


## Frequency

### Linux

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values different values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check the option `follow_symbolic_link` (Since v3.8.0)

### Windows

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert with report_changes option and `last-entry` files are stored compressed.
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)

## Realtime

### Linux

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)
- [ ] Check the option `follow_symbolic_link` (Since v3.8.0)

### Windows

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check the "nodiff" option to don't show the changes of a file
- [ ] Check syscheck flag auto_ignore with attributes "frequency" and "timeframe" (1)
- [ ] Check syscheck alert for changing attributes of a file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)

(1) https://github.com/wazuh/wazuh/pull/605

## Who-data

### Linux

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for deleting a file
- [ ] Check syscheck alert for deleting a folder
- [ ] Check syscheck alert for changing file permissions
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check recursive commands.
- [ ] Check audit rules added (auditctl -l)
- [ ] Check audit rules removed (auditctl -l)
- [ ] Remove audit rule manually and check if the rule is reloaded. (Auto-reload each 30 seconds)
- [ ] Remove rules 5 times and check if whodata stops and realtime is started. (Check alert)
- [ ] Remove monitored folder and check if the rule is removed and re-add the folder. The rule must be re-added.
- [ ] Add blocking rule in audit and check whodata logs and alert. (auditctl -a never,task)
- [ ] Restart auditd. Check whodata connection retries.
- [ ] Stop auditd. Move to realtime.
- [ ] Check modifications in a file changed from whodata to realtime.
- [ ] Check whodata in Amazon Linux.
- [ ] Check the option `follow_symbolic_link` only for directories, not files. (Since v3.8.0)


### Windows

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for deleting a file
