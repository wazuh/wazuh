| System version | Policy name | Policy ID | Policy file |
| --- | --- | --- | --- |
| Windows 11 Enterprise | CIS Microsoft Windows 11 Enterprise Benchmark | `cis_win11_enterprise` | `cis_win11_enterprise.yml` |
| Windows Server 2025 | CIS Microsoft Windows Server 2025 Benchmark | `cis_win2025` | `cis_win2025.yml` |
| macOS 26 (Tahoe) | CIS_Apple_macOS_26.0_Tahoe_Benchmark_v1.0.0 | `cis_macOS_26.x.yml` | `cis_apple_macOS_26.x.yml` |
| macOS 15 (Sequoia) | CIS_Apple_macOS_15.0_Sequoia_Benchmark_v1.0.0 | `cis_macOS_15.Sequoia.yml` | `cis_apple_macOS_15.x.yml` |
| Debian 13 (Trixie)| Center for Internet Security Debian Linux 13 Benchmark | `cis_debian13` | `cis_debian13.yml` |
| Debian 12 (Bookworm) | Center for Internet Security Debian Linux 12 Benchmark v1.1.0 | `cis_debian12` | `cis_debian12.yml` |

- Windows and Linux use the same policy naming style (` `), whereas macOS uses `_`.
- macOS includes the policy version (for example, `v1.0.0`) in the policy name, whereas Windows and some Linux distributions do not.
- Debian 13 does not specify the policy version, whereas Debian 12 does.
- Windows and Linux systems do not use the file extension in the Policy ID, whereas macOS includes the `.yml` extension.
- Linux distributions use different nomenclature in the policy name (`CIS` vs. `Center for Internet Security`).
- macOS policy files and policy ID separate the operating system name from the version number, whereas Windows and Linux combine them (for example, `macOS_15.something` vs. `win11` or `debian13`).

We should review this nomenclature and standardize these policy fields.

The above is the shortcomings found in the SCA documents, review all the SCAs in the SCA folder "ruleset/sca" come up with the best standardized template for the policy naming in the policy block of the YMLs, show me so i can review before applying.

example poliicy block

```yaml
policy:
  id: "cis_macOS_15.Sequoia.yml"
  file: "cis_macOS_15.Sequoia.yml"
  name: "CIS_Apple_macOS_15.0_Sequoia_Benchmark_v1.0.0"
  description: "This document provides prescriptive guidance for establishing a secure configuration posture for MacOS 15 Sequoia systems."
  references:
    - https://www.cisecurity.org/cis-benchmarks/

```