# Description

Vulnerability detection validation for **Python3.10** packages in **Ubuntu 22.04**. These tests validate the fix in binaries expansion made in https://github.com/wazuh/intelligence-platform/issues/1669.


## CVE

- CVE-2022-42919
- CVE-2022-45061
- CVE-2023-24329
- CVE-2023-41105

# Platforms

## Ubuntu 22.04 (Jammy Jellyfish)

- Input events
  - [001](input_001.json)
  - [002](input_002.json)
  - [003](input_003.json)
  - [004](input_004.json)
  - [005](input_005.json)
  - [006](input_006.json)
  - [007](input_007.json)
  - [008](input_008.json)
  - [009](input_009.json)
  - [010](input_010.json)
  - [011](input_011.json)

|Name|Version|Feed|Expected|
|---|---|---|---|
|libpython3.10|3.10.12-1~22.04.4|Canonical|Not vulnerable|
|libpython3.10-dev|3.10.12-1~22.04.4|Canonical|Not vulnerable|
|libpython3.10-minimal|3.10.12-1~22.04.4|Canonical|Not vulnerable|
|libpython3.10-stdlib|3.10.12-1~22.04.4|Canonical|Not vulnerable|
|python3.10|3.10.12-1~22.04.4|Canonical|Not vulnerable|
|python3.10-dev|3.10.12-1~22.04.4|Canonical|Not vulnerable|
|python3.10-minimal|3.10.12-1~22.04.4|Canonical|Not vulnerable|

|Name|Version|Feed|Expected Vulnerable|Expected Not Vulnerable|
|---|---|---|---|---|
|libpython3.10|3.10.4-3|Canonical|CVE-2022-42919, CVE-2022-45061, CVE-2023-24329|CVE-2023-41105|
|libpython3.10-dev|3.10.4-3|Canonical|CVE-2022-42919, CVE-2022-45061, CVE-2023-24329|CVE-2023-41105|
|libpython3.10-minimal|3.10.4-3|Canonical|CVE-2022-42919, CVE-2022-45061, CVE-2023-24329|CVE-2023-41105|
|libpython3.10-stdlib|3.10.4-3|Canonical|CVE-2022-42919, CVE-2022-45061, CVE-2023-24329|CVE-2023-41105|
