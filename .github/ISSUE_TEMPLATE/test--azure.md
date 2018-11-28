---
name: 'Test: Azure-logs'
about: Test module for Azure log collector.

---

# Azure module

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

This module collects logs from three Azure APIs (log analytics, graphs and storage).

### Manager (Linux)

- [ ] Configure **ossec.conf** to request logs from the three available APIs.
- [ ] Check wodle related alerts are being stored in *alerts.json*.
- [ ] Try to configure the module in agents. **It should show a descriptive error message.**
- [ ] Configure multiple log analytics and graph APIs with multiple requests.
- [ ] Configure multiple Storage APIs with multiple containers.
