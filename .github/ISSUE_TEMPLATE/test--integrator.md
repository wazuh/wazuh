---
name: 'Test: Integrator'
about: Test suite for integrations.
title: ''
labels: ''
assignees: ''

---

# Integrator test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## VirusTotal

### Configuration

- [ ] Configure the VirusTotal integration. (1) 
- [ ] Get an alert: "Incorrect API credentials". (1) 
- [ ] Get the alert: "Rate limit reached". (1) 

### Scan

- [ ] Monitor a folder in real-time, getting "not found" alerts by VT. (1) 
- [ ] Monitor a file  and scanning it. (1) 
- [ ] Monitor a malicious file getting a "positive" alert found by VT. (1) 

(1) https://documentation.wazuh.com/3.x/user-manual/capabilities/virustotal-scan/integration.html?highlight=integrator

## Slack

- [ ] Configure the Slack integration and get alerts on Slack.

## PagerDuty

- [ ] Configure the PagerDuty integration. (2)
- [ ] Get alerts on the PagerDuty Dashboard. (2)

(2) https://documentation.wazuh.com/3.x/user-manual/manager/manual-integration.html?highlight=integrator
