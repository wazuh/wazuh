---
name: 'Test: API'
about: Test suite for the API.

---

# Ruleset test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Installation

- [ ] Install API.
- [ ] Install in custom directory.
- [ ] Check API status is running.

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

- [ ] Ubuntu 18 / Python 2.
- [ ] Ubuntu 18 / Python 3.
- [ ] CentOS 7 / Python 2.
- [ ] CentOS 7 / Python 3.
- [ ] CentOS 6 / Python27.

### Cluster calls (Ubuntu 18)

- [ ] *GET /cluster/nodes*.
- [ ] *GET /cluster/node*.
- [ ] *GET /cluster/files*.
- [ ] *GET /cluster/agents*.
- [ ] *GET /cluster/status*.
- [ ] *GET /cluster/config*.

### Cluster calls (CentOS 7)

- [ ] *GET /cluster/nodes*.
- [ ] *GET /cluster/node*.
- [ ] *GET /cluster/files*.
- [ ] *GET /cluster/agents*.
- [ ] *GET /cluster/status*.
- [ ] *GET /cluster/config*.

### Cluster calls (CentOS 6)

- [ ] *GET /cluster/nodes*.
- [ ] *GET /cluster/node*.
- [ ] *GET /cluster/files*.
- [ ] *GET /cluster/agents*.
- [ ] *GET /cluster/status*.
- [ ] *GET /cluster/config*.

### Agent calls

- [ ] Test agents config queries (https://github.com/wazuh/wazuh/issues/1248).
