---
name: 'Test: Windows MSI'
about: Test suite for MSI Windows installation.
title: ''
labels: ''
assignees: ''

---

# Windows MSI

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Installation

To check in every test:

- Correct version.
- WUI doesn't show any strange information.
- Service is running correctly.
- No errors in ossec.log.

- [ ] Successful installation by UI
- [ ] Unattended installation
- [ ] Unattended installation with registration parameters
- [ ] Check the options "PEM" and "KEY" with absolute paths. (1)
- [ ] Check the options "PEM" and "KEY" with relative paths.
- [ ] Check the option "CERTIFICATE" with absolute paths. (1)
- [ ] Check the option "CERTIFICATE" with relative paths.

### Versions

- [ ] Windows XP
- [ ] Windows Server 2003
- [ ] Windows Vista
- [ ] Windows Server 2008
- [ ] Windows 7
- [ ] Windows Server 2012
- [ ] Windows 8/8.1
- [ ] Windows Server 2016
- [ ] Windows 10
- [ ] Windows Server 2019

## Uninstall

To check in every test:

- It only remains the `client.keys`, `ossec.conf` and `local_internal_options.conf` files.
- The package and service are removed.

- [ ] Successful uninstallation by running the MSI
- [ ] Successful uninstallation by the Windows control panel

### Versions

- [ ] Windows XP
- [ ] Windows Server 2003
- [ ] Windows Vista
- [ ] Windows Server 2008
- [ ] Windows 7
- [ ] Windows Server 2012
- [ ] Windows 8/8.1
- [ ] Windows Server 2016
- [ ] Windows 10
- [ ] Windows Server 2019

## Upgrade

To check in every test:

- It does not overwrite the `client.keys`, `ossec.conf` and `local_internal_options.conf`.
- WUI doesn't show any strange information.
- Service is restarted correctly.
- No errors in ossec.log.
- No duplicated package when upgrading from the EXE.

- [ ] Upgrade MSI from 3.X.X
- [ ] Upgrade from the current MSI
- [ ] Upgrade MSI from EXE installation 2.X.X
- [ ] Upgrade MSI from EXE installation 3.X.X
- [ ] Check an unattended installation with PEM and KEY from a previous version.
- [ ] Check an unattended installation with CERTIFICATE from a previous version.

### Versions

- [ ] Windows XP
- [ ] Windows Server 2003
- [ ] Windows Vista
- [ ] Windows Server 2008
- [ ] Windows 7
- [ ] Windows Server 2012
- [ ] Windows 8/8.1
- [ ] Windows Server 2016
- [ ] Windows 10
- [ ] Windows Server 2019

(1) Use MS-DOS scaping form for paths with spaces. ( "C:\Program Files\sslagent.cert" would be "C:\Progra\~1\sslagent.cert" and "C:\Program Files x86\sslagent.cert" would be "C:\Progra\~2\sslagent.cert")
