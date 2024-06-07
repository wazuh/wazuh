# Description

Vulnerability detection validation for package `systemd` insertion and deletion.
The test verifies the vulnerabilities for this specific package are found and that after the removal of the package, the entry is deleted from the inventory.

# Platforms

## Linux

- Input events
    - [001](input_001.json)
    - [002](input_002.json)
    - [003](input_003.json)

| Name    | Version         | Feed   | CVE IDs         | Expected    |
|---------|-----------------|--------|-----------------|-------------|
| systemd | 247.3-7+deb11u4 | Debian | CVE-2013-4392   | Vulnerable  |
| systemd | 247.3-7+deb11u4 | Debian | CVE-2020-13529  | Vulnerable  |
| systemd | 247.3-7+deb11u4 | Debian | CVE-2023-31437  | Vulnerable  |
| systemd | 247.3-7+deb11u4 | Debian | CVE-2023-31438  | Vulnerable  |
| systemd | 247.3-7+deb11u4 | Debian | CVE-2023-31439  | Vulnerable  |
