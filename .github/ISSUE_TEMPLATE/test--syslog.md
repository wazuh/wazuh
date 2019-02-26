---
name: 'Test: Syslog'
about: Test suite for Syslog.
title: ''
labels: ''
assignees: ''

---

# Syslog test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Output

- [ ] Send alerts using ports other than 514.
- [ ] Send alerts from the minimum level.
- [ ] Send alerts for a specific group.
- [ ] Send alerts for a specific rule.
- [ ] Send alert in `json` format.
- [ ] Send alert in `splunk` format.
- [ ] Send alert in `cef` format.
- [ ] Send alerts for a specific log location.

**Side note**
If two identical alerts are sent to the syslog server **it won't log them** in `/var/log/syslog`. We must change some fields values between alerts in order to get the information properly.
