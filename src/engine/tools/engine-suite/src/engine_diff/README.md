# Engine diff tool
It's  a command line tool to compare two event files in YAML or JSON format. The script loads the events, sorts them (if necessary), and performs a comparison using delta, a difference visualization tool.
The tool provides a report of the differences between the two files, including keys that are present in one but not the other and keys that have different values ​​in both files.


1. [Directory structure](#directory-structure)
2. [Install](#install)
3. [Usage](#usage)

# Directory structure

```bash
├── engine_diff/
|   └── __init__.py
|   └── __main__.py
```

## Install
The script is packaged along the engine-suite python packaged, to install simply run:
```bash
￼pip install tools/engine-suite
```
￼To verify it's working:
```bash
￼engine-diff --version
```

## Usage
```bash
usage: engine-diff [-h] [--version] [-in {yaml,json}] [-q, --quiet] [--no-order] fileA fileB

Compare two events in yaml format, returns SAME if no differences found, DIFFERENT otherwise. The script loads the events, orders them and
makes a diff using delta, credits to dandavison for his awesome tool (https://github.com/dandavison/delta)

positional arguments:
  fileA                 First file to compare
  fileB                 Second file to compare

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -in {yaml,json}, --input {yaml,json}
                        Input format (default: json)
  -q, --quiet           Print only the result
  --no-order            Do not order the events when comparing
```
