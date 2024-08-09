# Engine decoder tool
It's a command line tool for managing and analyzing decoders in the system. Allows you to list the fields extracted from a decoder and update the name of auxiliary functions in the decoders.

1. [Directory structure](#directory-structure)
2. [Install](#install)
3. [Usage](#usage)
4. [Subcommands Usage](#subcommands-usage)
   1. [list-extracted](#list-extracted)
   2. [helper-function](#helper-function)

# Directory structure

```bash
├── engine_decoder/
|   └── cmds
|       └── __init__.py
|       └── list_extracted.py
|       └── syntax_update.py
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
￼engine-decoder --version
```

## Usage
```bash
usage: engine-decoder [-h] [--version] {list-extracted,helper-function} ...

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

subcommands:
  {list-extracted,helper-function}
    list-extracted      List all extracted fields from a decoder
    helper-function     Change the helper function name on all the decoders
```

## Subcommands Usage

### list-extracted

```bash
usage: engine-decoder list-extracted [-h] decoder

positional arguments:
  decoder     Decoder to analyze

options:
  -h, --help  show this help message and exit
```

### helper-function

```bash
usage: engine-decoder helper-function [-h] [-o OLD-NAME] [-n NEW-NAME] [-l LIST-FILE] [-d DIRECTORY]

options:
  -h, --help            show this help message and exit
  -o OLD-NAME, --old-name OLD-NAME
                        Helper Function Name to be changed
  -n NEW-NAME, --new-name NEW-NAME
                        New Helper Function Name
  -l LIST-FILE, --list-file LIST-FILE
                        Path to list of {"old":"new"} helper functions names
  -d DIRECTORY, --directory DIRECTORY
                        Directory where to look for decoders
```
