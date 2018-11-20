---
name: 'Test: Syscheck'
about: Test suite for Syscheck

---

# Testing: Syscheck

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Any

- [ ] Check if ignore files and folders using tag <ignore> and restrict option (string or sregex) in both options
- [ ] Check if delete content in /var/ossec/queue/diff when deleting any tag <directories report_changes="yes">
- [ ] Check if delete content in /var/ossec/queue/diff when report_changes option passed yes to no


## Frequency

### Linux

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] After delete, readd file with de same name to view re-added file alert
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)

### Windows

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for adding text to a file
- [ ] Check syscheck alert for deleting text from a file
- [ ] Check syscheck alert with report_changes option
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check values diferent values for options 'check_sum', 'check_md5sum', 'check_sha1sum','check_sha256sum'
- [ ] Check syscheck alert for deleting a file
- [ ] After delete, readd file with de same name to view re-added file alert
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
- [ ] After delete, readd file with de same name to view re-added file alert
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)

### Windows

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
- [ ] After delete, readd file with de same name to view re-added file alert
- [ ] Check recursion level option (recursion_level=0, recursion_level=2 check folder level 0, 1, 2 and 3)

(1) https://github.com/wazuh/wazuh/pull/605

## Who-data

### Linux

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for deleting a file
- [ ] Check syscheck alert for changing file permissions
- [ ] Check syscheck alert for changing owner of file
- [ ] Check syscheck alert for changing group of file
- [ ] Check audit rules added (auditctl -l)
- [ ] Check audit rules removed (auditctl -l)
- [ ] Remove audit rule manually and check if Syscheck changes to realtime
- [ ] Remove monitored folder and check if an alert is received
- [ ] Check modifications in a file changed from whodata to realtime
- [ ] After delete, readd file with de same name to view re-added file alert

### Windows

- [ ] Check syscheck alert for adding a file
- [ ] Check syscheck alert for moving a file
- [ ] Check syscheck alert for modifying a file
- [ ] Check syscheck alert for deleting a file
- [ ] After delete, readd file with de same name to view re-added file alert
