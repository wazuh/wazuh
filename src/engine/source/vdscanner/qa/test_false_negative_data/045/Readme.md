# Description

Vulnerability detection validation for `perl-modules` and `linux-hwe-6.8` on Ubuntu.

# Platforms

## Ubuntu Hardy

- Input events
  - [001](input_001.json)

| Name           | Version             | Feed      | CVE IDs        | Expected       |
| ---------------| ------------------- | --------- | -------------- | -------------- |
| perl-modules   | 5.7.8-12ubuntu0.3   | Canonical | CVE-2007-4829  | Not Vulnerable |

## Ubuntu Jammy

- Input events
  - [002](input_002.json)

| Name           | Version             | Feed      | CVE IDs        | Expected       |
| ---------------| ------------------- | --------- | -------------- | -------------- |
| linux-hwe-6.8  | 6.7.0-40.40~22.04.3 | Canonical | CVE-2024-36001 | Vulnerable     |
