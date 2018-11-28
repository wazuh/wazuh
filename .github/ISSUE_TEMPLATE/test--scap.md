---
name: 'Test: SCAP'
about: Test suite for OpenSCAP and CIS-CAT.

---

# SCAP test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## OpenSCAP

- [ ] Launch a scan on Ubuntu 16.
XCCDF and OVAL. Check the generated alerts. (1)
- [ ] Launch a scan on Fedora 24.
XCCDF and OVAL. Check the generated alerts. (1)
- [ ] Launch a scan on CentOS 7.
XCCDF and OVAL. Check the generated alerts. (1)
- [ ] Launch a scan on Debian.
XCCDF and oval. Check the generated alerts. (1)
- [ ] Set several content sections and launch a scan. (1)
- [ ] Set an non-existent benchmark, incorrect path and wrong type. **Must fail** (1)

(1) https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/wodle-openscap.html#content

## CIS-CAT

- [ ] Launch a scan (XCCDF) and check the generated alerts. (2)
- [ ] Set CIS-CAT path, Java path and benchmark path with absolute and relative paths. (2)
- [ ] Launch a scan with incorrect parameters (incorrect benchmarks). **Must fail** (2)
- [ ] Launch a scan with incorrect parameters (incorrect CIS-CAT path and JAVA path). **Must fail** (2)
- [ ] Launch a scan with incorrect parameters (incorrect profile). **Must fail** (2)
- [ ] Set several content sections and launch a scan. (2)
- [ ] Launch a scan (XCCDF) and check the generated alerts. (2)
- [ ] Set CIS-CAT path, Java path and benchmark path with absolute and relative paths. (2)
- [ ] Launch a scan with incorrect parameters (incorrect benchmarks). **Must fail** (2)
- [ ] Launch a scan with incorrect parameters (incorrect CIS-CAT path and JAVA path). **Must fail** (2)
- [ ] Launch a scan with incorrect parameters (incorrect profile). **Must fail** (2)
- [ ] Set several content sections and launch a scan. (2)
- [ ] Check that main results of the scans are saved into the table `ciscat_results` of the DB of each agent.

(2) https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/wodle-ciscat.html
