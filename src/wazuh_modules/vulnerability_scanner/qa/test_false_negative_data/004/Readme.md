# Description

Vulnerability detection validation for package `containerd` in different Ubuntu versions.

# Platforms

## Linux

- Input events
    - [001](input_001.json)
    - [002](input_002.json)
    - [003](input_003.json)
    - [004](input_004.json)
    - [005](input_005.json)
    - [006](input_006.json)
    - [007](input_007.json)
    - [008](input_008.json)


| Name        | Version                           | Feed      | CVE IDs         | Expected    |
|-------------|-----------------------------------|-----------|-----------------|-------------|
| containerd  | 1.6.11-0ubuntu1~18.04.1+esm1      | Canonical | CVE-2023-25153  | Vulnerable  |
| containerd  | 1.6.11-0ubuntu1~18.04.1+esm1      | Canonical | CVE-2023-25173  | Vulnerable  |
| containerd  | 1.6.11-0ubuntu1~20.04.3           | Canonical | CVE-2023-25153  | Vulnerable  |
| containerd  | 1.6.11-0ubuntu1~20.04.3           | Canonical | CVE-2023-25173  | Vulnerable  |
| containerd  | 1.2.5-0ubuntu1~16.04.6+esm4       | Canonical | CVE-2023-25153  | Vulnerable  |
| containerd  | 1.2.5-0ubuntu1~16.04.6+esm4       | Canonical | CVE-2023-25173  | Vulnerable  |
| containerd  | 1.6.11-0ubuntu1~22.04.3           | Canonical | CVE-2023-25153  | Vulnerable  |
| containerd  | 1.6.11-0ubuntu1~22.04.3           | Canonical | CVE-2023-25173  | Vulnerable  |
