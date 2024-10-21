# Description

Vulnerability detection validation for `Docker Desktop` on macOS Darwin and Windows.

# Platforms

## Darwin

- Input events
  - [001](input_001.json)

| Name           | Version  | Feed  | CVE IDs        | Expected   |
| ---------------| -------- | ----- | -------------- | ---------- |
| docker         | 4.19.0   | NVD   | CVE-2024-8695  | Vulnerable |
| docker         | 4.19.0   | NVD   | CVE-2024-8696  | Vulnerable |

## Windows

- Input events
  - [002](input_002.json)

| Name           | Version  | Feed  | CVE IDs        | Expected   |
| ---------------| -------- | ----- | -------------- | ---------- |
| Docker Desktop | 2.1.0    | NVD   | CVE-2020-10665 | Vulnerable |
| Docker Desktop | 2.1.0    | NVD   | CVE-2023-0625  | Vulnerable |
