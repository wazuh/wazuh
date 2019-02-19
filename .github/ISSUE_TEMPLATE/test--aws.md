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

- [ ] Configure *ossec.conf* to use different services and check manager logs:
    - [ ] *CloudTrail*.
    - [ ] *Config*.
    - [ ] *VPC*.
    - [ ] *GuardDuty*.
    - [ ] *Inspector*.
    - [ ] *Macie* (custom).
    - [ ] *KMS* (custom).
    - [ ] *TrustedAdvisor* (custom).
- [ ] Check wodle related alerts are being stored in *alerts.json*.
- [ ] Configure AWS in Wazuh v3.5 and check it correctly upgrades to the latest version.
- [ ] Check configurations of multiple regions.
- [ ] Check pull of logs from *CloudTrail*.
- [ ] Check pull of logs from *Config* (*AWS* doesn't store *Config* logs by lexicographical order).
- [ ] Check pull of logs from *VPC* (*flow log id* makes that logs don't follow lexicographical order).
- [ ] Check pull of logs from *KMS* (custom).
- [ ] Check databases:
    - [ ] *s3_cloudtrail.db*.
    - [ ] *aws_services*.
- [ ] Wazuh apps tab show the alerts:
    - [ ] Kibana.
    - [ ] Splunk.
- [ ] Check alerts on Wazuh apps:
    - [ ] Kibana.
    - [ ] Splunk.
