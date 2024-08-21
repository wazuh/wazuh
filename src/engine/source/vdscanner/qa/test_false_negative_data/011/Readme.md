# Description

Vulnerability detection validation for Windows package `Opera`.
Vulnerability detection validation for macOS packages `Mail` and homebrew `brotli` (only verifies the scan begins).

# Platforms

## Windows

- Input events
    - [001](input_001.json)
    - [002](input_002.json)

| Name                       | Version           | Feed | CVE IDs        | Expected    |
|----------------------------|-------------------|------|----------------|-------------|
| Opera Stable 108.0.5067.29 | 108.0.5067.29     | NVD  | CVE-2008-7297  | Vulnerable  |

## macOS

- Input events
    - [003](input_003.json)
    - [004](input_004.json)
    - [005](input_005.json)

| Name                | Version | Feed | CVE IDs        | Expected    |
|---------------------|---------|------|----------------|-------------|
| Mail                | 16.0    | NVD  | CVE-2005-2512  | Vulnerable  |
