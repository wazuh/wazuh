# Description

Vulnerability detection validation for **_openssh_** package.

# Platforms

## Ubuntu Jammy

- Input events
  - [001](input_001.json)
  - [002](input_002.json)

| Name           | Version             | Feed      | CVE IDs       | Expected       |
|----------------|---------------------|-----------|---------------|----------------|
| openssh-server | 1:8.9p1-3ubuntu0.10 | Canonical | CVE-2024-6387 | Not vulnerable |

## Centos 9

- Input events
  - [003](input_003.json)
  - [004](input_004.json)

| Name    | Version      | Feed     | CVE IDs       | Expected   |
|---------|--------------|----------|---------------|------------|
| openssh | 8.7p1-34.el9 | redhat_9 | CVE-2024-6387 | Vulnerable |

## Arch Linux

- Input files
  - [005](input_005.json)
  - [006](input_006.json)
  - [007](input_007.json)

| Name    | Version | Feed | CVE IDs       | Expected       |
|---------|---------|------|---------------|----------------|
| openssh | 9.7p1-2 | Arch | CVE-2024-6387 | Vulnerable     |
| openssh | 9.8p1-1 | Arch | CVE-2024-6387 | Not vulnerable |
