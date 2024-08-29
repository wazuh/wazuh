# Description
This test is intended to make sure that there are no false positives related to the `bsdutils` package in Ubuntu.
The candidates are discarded because the OS isn't found in the platforms' array.

# Platforms

## Windows

- Input events
    - [001](input_001.json)

| Name     | Version              | Feed       | CVE IDs        | Expected    |
|----------|----------------------|------------|----------------|-------------|
| bsdutils | 1:2.37.2-4ubuntu3.4  | CANONICAL  | CVE-2016-5011  | Vulnerable  |
| bsdutils | 1:2.37.2-4ubuntu3.4  | CANONICAL  | CVE-2018-7738  | Vulnerable  |
| bsdutils | 1:2.37.2-4ubuntu3.4  | CANONICAL  | CVE-2021-3995  | Vulnerable  |
| bsdutils | 1:2.37.2-4ubuntu3.4  | CANONICAL  | CVE-2021-3996  | Vulnerable  |
