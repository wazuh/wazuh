# Description

Vulnerability detection validation for Windows OS. It verifies the vulnerabilities found for one version; then it upgrades the OS to a newer version and makes sure the corresponding CVEs are solved. Finally, it clears the OS table and looks for the messages and alerts for this type of event.

# Platforms

## Windows

- Input events
    - [001](input_001.json)
    - [002](input_002.json)
    - [003](input_003.json)

| Name                           | Version          | Feed | CVE IDs          | Expected         |
|--------------------------------|------------------|------|------------------|------------------|
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4043  | NVD  | CVE-2024-21405   | Vulnerable       |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4043  | NVD  | CVE-2024-21372   | Vulnerable       |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4043  | NVD  | CVE-2024-21371   | Vulnerable       |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4043  | NVD  | CVE-2024-21340   | Vulnerable       |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4043  | NVD  | CVE-2024-21338   | Vulnerable       |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4043  | NVD  | CVE-2024-21341   | Vulnerable       |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4043  | NVD  | CVE-2023-32040   | Vulnerable       |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4046  | NVD  | CVE-2024-21338   | Not vulnerable   |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4046  | NVD  | CVE-2024-21340   | Not vulnerable   |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4046  | NVD  | CVE-2024-21341   | Not vulnerable   |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4046  | NVD  | CVE-2024-21371   | Not vulnerable   |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4046  | NVD  | CVE-2024-21372   | Not vulnerable   |
| Microsoft Windows 10 Pro 22H2  | 10.0.19045.4046  | NVD  | CVE-2024-21405   | Not vulnerable   |
