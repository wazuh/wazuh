# Description

Vulnerability detection validation for **Wazuh agent** package.

# Platforms


## Ubuntu Jammy

- Input events
  - [001](input_001.json)

| Name           | Version             | Feed      | CVE IDs       | Expected       |
|----------------|---------------------|-----------|---------------|----------------|
| wazuh-agent    | 4.2.0-1             | NVD       |CVE-2023-50260 | Vulnerable     |
| wazuh-agent    | 4.2.0-1             | NVD       |CVE-2023-42463 | Vulnerable     |
| wazuh-agent    | 4.2.0-1             | NVD       |CVE-2022-40497 | Vulnerable     |
| wazuh-agent    | 4.2.0-1             | NVD       |CVE-2021-44079 | Vulnerable     |
| wazuh-agent    | 4.2.0-1             | NVD       |CVE-2018-19666 | Not vulnerable |

## Windows

- Input files
  - [002](input_002.json)


| Name           | Version             | Feed      | CVE IDs       | Expected       |
|----------------|---------------------|-----------|---------------|----------------|
| wazuh-agent    | 2.2.1               | NVD       |CVE-2018-19666 | Vulnerable     |
| wazuh-agent    | 2.2.1               | NVD       |CVE-2021-44079 | Not vulnerable |
