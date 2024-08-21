# Description

Vulnerability detection validation for **_XZ_** package.

# Platforms

## Ubuntu Jammy

- Input events
  - [001](input_001.json)

| Name       | Version       | Feed      | CVE IDs       | Expected       |
|------------|---------------|-----------|---------------|----------------|
| xz-utils   | 5.2.5-2ubuntu1| Canonical | CVE-2024-3094 | Not vulnerable |
| xz-utils   | 5.6.0         | NVD       | CVE-2024-3094 | Vulnerable     |

## Arch Linux

- Input files
  - [002](input_002.json)

| Name       | Version | Feed | CVE IDs       | Expected       |
|------------|---------|------|---------------|----------------|
| xz         | 5.4.6-1 | Arch | CVE-2024-3094 | Not vulnerable |
| xz         | 5.6.0-1 | Arch | CVE-2024-3094 | Vulnerable     |
