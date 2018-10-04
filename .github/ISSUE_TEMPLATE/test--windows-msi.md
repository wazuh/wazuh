---
name: 'Test: Windows MSI'
about: Test suite for MSI Windows installation.

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

### Versions

- [ ] Windows XP
- [ ] Windows Server 2003
- [ ] Windows Vista
- [ ] Windows Server 2008
- [ ] Windows 7
- [ ] Windows 8/8.1
- [ ] Windows Server 2016
- [ ] Windows 10

## Uninstall

To check in every test:

- It only remains the `local_internal_options.conf` and `ossec.log` files.
- The package and service are removed.

- [ ] Successful uninstallation by running the MSI
- [ ] Successful uninstallation by the Windows control panel

### Versions

- [ ] Windows XP
- [ ] Windows Server 2003
- [ ] Windows Vista
- [ ] Windows Server 2008
- [ ] Windows 7
- [ ] Windows 8/8.1
- [ ] Windows Server 2016
- [ ] Windows 10

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

### Versions

- [ ] Windows XP
- [ ] Windows Server 2003
- [ ] Windows Vista
- [ ] Windows Server 2008
- [ ] Windows 7
- [ ] Windows 8/8.1
- [ ] Windows Server 2016
- [ ] Windows 10
