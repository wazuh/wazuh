---
name: 'Test: Vulnerability Detector'
about: Test suite for Vulnerability Detector.

---

# Vulnerability Detector test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Database update

- [ ] Check that all OVALs of all operating systems are updated correctly. Debug code: 5451
- [ ] Check that an OVAL is not re-downloaded if it is up to date. Debug code: 5457
- [ ] Check that each OVAL is updated according to its update interval.
- [ ] Download Ubuntu 12 and CentOS 5 OVALs.
- [ ] Check the option `update_from_year` for the Red Hat feed.

## Detection

- [ ] Check that version comparisons make sense. To do this, run a vulnerability detection for one agent in each family in debug mode (level 2), and check debug messages 5467, 5468 and 5456.
Spend at least 5-10 minutes checking logs of vulnerable and non-vulnerable packages.
- [ ] Check that all supported agents are taken into account.
- [ ] Do not see repeated alerts.
- [ ] Check that there are no false positives in Ubuntu.
- [ ] Check that there are no false positives in CentOS.
- [ ] Check that there are no false positives in Red Hat.
- [ ] Check that there are no false positives in Amazon Linux.
- [ ] Check that there are no false positives in Debian.
- [ ] Test that all vulnerabilities are reported according to the period indicated in ignore_time.
- [ ] Test RHSA decompression in CVEs for Red Hat vulnerabilities.
- [ ] Verify that no vulnerabilities of wrong architectures are triggered in RedHat/CentOS agents.
- [ ] Verify that the vulnerability databases are deleted when updating.
- [ ] Verify that a 3.2.X configuration is accepted.
- [ ] Verify that OVAL files can be downloaded from alternate addresses.
- [ ] Verify that OVAL files can be used from local paths.
- [ ] Checks that it does not break when checking the version of unsupported systems such as Debian Sid (1).

(1) https://hub.docker.com/r/cantara/debian-sid-zulu-jdk9/
