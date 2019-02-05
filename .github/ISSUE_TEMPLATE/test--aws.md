---
name: 'Test: AWS'
about: Test suite for Amazon Web Services.
title: ''
labels: ''
assignees: ''

---

# Amazon Web Services test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

### RPM (Linux)

- [ ] Configure *ossec.conf* to use cloud-trail wodle and check manager logs.
- [ ] Check wodle related alerts are being stored in *alerts.json*.
- [ ] Configure AWS in Wazuh v3.5 and check it correctly upgrades to the latest version.
- [ ] Configure multiple buckets with multiple types (*custom* and *cloudtrail*).
- [ ] Wazuh app tab shows the alerts.
