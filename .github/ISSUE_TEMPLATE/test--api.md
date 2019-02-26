---
name: 'Test: API'
about: Test suite for the API.
title: ''
labels: ''
assignees: ''

---

# Ruleset test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Installation

- [ ] Install API in a cluster of two nodes. One of the nodes must be a custom directory install. All agents must report to the worker node.
- [ ] Check API status is running in both nodes.

## Configuration

- [ ] Custom user, password and https working.

## Calls

### Certificates and HTTPS

- [ ] Install certificates.
- [ ] Run query using HTTPS.

### Test mocha

Required tests:

- Agents.
- Decoders.
- Manager.
- Rootcheck.
- Rules.
- Syscheck.
- Syscollector.

Checks:

- [ ] Master node:
    - [ ] Ubuntu 18 / Python 2.
    - [ ] Ubuntu 18 / Python 3.
    - [ ] CentOS 7 / Python 2.
    - [ ] CentOS 7 / Python 3.
    - [ ] CentOS 6 / Python27.
