# Description

Vulnerability detection validation for Windows package `Microsoft Office Professional Plus 2016`.
It's verified that the installation of a hotfix before the insertion of a vulnerable package prevents the vulnerability from being detected.

# Platforms

## Windows

- Input events
    - [001](input_001.json)
    - [002](input_002.json)
    - [003](input_003.json)

| Name                                    | Version | Feed | CVE IDs         | Expected        |
|-----------------------------------------|---------|------|-----------------|-----------------|
| Microsoft Office Professional Plus 2016 | 2016    | NVD  | CVE-2024-20673  | Not vulnerable  |
