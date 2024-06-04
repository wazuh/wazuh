# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from os import listdir, chmod, remove, path
from pathlib import Path
from typing import Union

from wazuh.core import common
from wazuh.core.exception import WazuhError
from wazuh.core.utils import find_nth, delete_wazuh_file, to_relative_path

REQUIRED_FIELDS = ['relative_dirname', 'filename']
SORT_FIELDS = ['relative_dirname', 'filename']
LIST_FIELDS = ['items', 'filename', 'relative_dirname']

_regex_path = r'^(etc/lists/)[\w\.\-/]+$'
_pattern_path = re.compile(_regex_path)


def check_path(path: str):
    """Check if path is well-formed (without './' or '../').

    Parameters
    ----------
    path : str
        Path to check.

    Raises
    ------
    WazuhError(1801)
        If the path is not valid.
    """
    if './' in path or '../' in path or not _pattern_path.match(path):
        raise WazuhError(1801)


def iterate_lists(absolute_path: str = common.USER_LISTS_PATH, only_names: bool = False) -> list:
    """Get the content of all CDB lists.

    Parameters
    ----------
    absolute_path : str
        Full path of directory to get CDB lists.
    only_names : bool
        If this parameter is True, only the name of all lists will be showed.

    Returns
    -------
    list
        List with all CDB lists.
    """
    dir_content = listdir(absolute_path)
    output = list()

    # For skipping .swp files
    regex_swp = r'^\.{1}[\w\-/]+(.swp){1}$'
    pattern = re.compile(regex_swp)

    for name in dir_content:
        new_absolute_path = path.join(absolute_path, name)
        new_relative_path = to_relative_path(new_absolute_path)
        # '.cdb' and '.swp' files are skipped
        if (path.isfile(new_absolute_path)) and ('.cdb' not in name) and ('~' not in name) and not pattern.search(name):
            if only_names:
                relative_path = to_relative_path(absolute_path)
                output.append({'relative_dirname': relative_path, 'filename': name})
            else:
                items = get_list_from_file(path.join(common.WAZUH_PATH, new_relative_path))
                output.append({'relative_dirname': new_relative_path, 'filename': name, 'items': items})
        elif path.isdir(new_absolute_path):
            output += iterate_lists(new_absolute_path, only_names=only_names)

    return output


def split_key_value_with_quotes(line: str, file_path: str = '/CDB_LISTS_PATH') -> tuple:
    """Return the key and value of a cdb list line when they are surrounded by quotes.

    Parameters
    ----------
    line : str
        String to split in key and value.
    file_path : str
        Relative path of list file which contains "line". Default: '/CDB_LISTS_PATH'

    Raises
    ------
    WazuhError(1800)
        If the input line has a wrong format.

    Returns
    -------
    tupe
        Key of the CDB list line and value of the CDB list line.
    """
    first_quote = find_nth(line, '"', 1)
    second_quote = find_nth(line, '"', 2)

    # Check if key AND value are surrounded by double quotes
    if line.count('"') == 4:
        third_quote = find_nth(line, '"', 3)
        fourth_quote = find_nth(line, '"', 4)

        key = line[first_quote + 1: second_quote]
        value = line[third_quote + 1: fourth_quote]

        # Check that the line starts with "...
        # Check that the line has the structure ...":"...
        # Check that the line finishes with ..."
        if first_quote != 0 or line[second_quote: third_quote + 1] != '":"' or fourth_quote != len(
                line) - 1:
            raise WazuhError(1800, extra_message={'path': path.join('WAZUH_HOME', file_path)})

    # Check whether the string surrounded by quotes is the key or the value
    elif line.count('"') == 2:
        # Check if the key is surrounded by quotes
        if line.find(":") > first_quote:
            key = line[first_quote + 1: second_quote]
            value = line[second_quote + 2:]

            # Check that the line starts with "...
            # Check that the line has the structure ...":...
            if first_quote != 0 or line[second_quote: second_quote + 2] != '":':
                raise WazuhError(1800, extra_message={'path': path.join('WAZUH_HOME', file_path)})

        # Check if the value is surrounded by quotes
        if line.find(":") < first_quote:
            key = line[: line.find(":")]
            value = line[first_quote + 1: second_quote]

            # Check that the line finishes with ..."
            # Check that the line has the structure ...:"...
            if second_quote != len(line) - 1 or line[first_quote - 1: first_quote + 1] != ':"':
                raise WazuhError(1800, extra_message={'path': path.join('WAZUH_HOME', file_path)})

    # There is an odd number of quotes (or more than 4)
    else:
        raise WazuhError(1800, extra_message={'path': path.join('WAZUH_HOME', file_path)})

    return key, value


def get_list_from_file(path: str, raw: bool = False) -> Union[dict, str]:
    """Get CDB list from a file.

    Parameters
    ----------
    path : str
        Full path of list file to get.
    raw : bool, optional
        Respond in raw format.

    Raises
    ------
    WazuhError(1800)
        Bad format in CDB list.
    WazuhError(1802)
        CDB list file not found.
    WazuhError(1803)
        Error reading list file (permissions).
    WazuhError(1804)
        Error reading list file (filepath).

    Returns
    -------
    dict or str
        CDB list.
    """
    # Match empty lines or lines which start with "TEMPLATE:"
    regex_without_template = r'^(?!.*TEMPLATE)(.*)$'
    result = {}

    try:
        with open(path) as f:
            output = f.read()

        if raw:
            result = output
        else:
            for match in re.finditer(regex_without_template, output.strip(), re.MULTILINE):
                line = match.group(1)
                if '"' not in line:
                    # Check if key and value are not surrounded by double quotes
                    key, value = line.split(':')
                else:
                    # Check if key and/or value are surrounded by double quotes
                    key, value = split_key_value_with_quotes(line, path)
                result[key] = value

    except OSError as e:
        if e.errno == 2:
            raise WazuhError(1802)
        elif e.errno == 13:
            raise WazuhError(1803)
        elif e.errno == 21:
            raise WazuhError(1804, extra_message="{0} {1}".format(path, "is a directory"))
        else:
            raise e
    except ValueError:
        raise WazuhError(1800, extra_message={'path': path})

    return result


def validate_cdb_list(content: str):
    """Validate a CDB list.

    This regex allow any line like key:value. If key or value contains ":", the whole
    key or value must be within quotes:
    - test_key:test_value     VALID
    - "test:key":test_value   VALID
    - "test:key":"test:value" VALID
    - "test:key":test:value   INVALID
    - test:key:test_value     INVALID

    Parameters
    ----------
    content : str
        Content of file to be validated.

    Raises
    -------
    WazuhError(1800)
        Bad format in CDB list.
    WazuhError(1112)
        Empty CDB list.
    """
    regex_cdb = re.compile(r'(?:^"([\w\-: ]+?)"|^[^:"\s]+):(?:"([\w\-: ]*?)"$|[^:\"]*$)')

    if len(content) == 0:
        raise WazuhError(1112)

    for line in content.splitlines():
        if not re.match(regex_cdb, line):
            raise WazuhError(1800)


def create_list_file(full_path: str, content: str, permissions: int = 0o660) -> str:
    """Create list file.

    Parameters
    ----------
    full_path : str
        Full path where the file will be created.
    content : str
        Content of file to be created.
    permissions : int
        String mask in octal notation.

    Raises
    ------
    WazuhError(1806)
        Error trying to create CDB list file.

    Returns
    -------
    full_path : str
        Path to created file.
    """
    try:
        with open(full_path, 'w') as f:
            for element in content.splitlines():
                # Skip empty lines
                if not element:
                    continue
                f.write(element.strip() + '\n')
        chmod(full_path, permissions)
    except IOError:
        raise WazuhError(1806)

    return full_path


def delete_list(rel_path: str):
    """Delete a Wazuh CDB list file.

    Parameters
    ----------
    rel_path : str
        Relative path of the file to delete.
    """
    delete_wazuh_file(path.join(common.WAZUH_PATH, rel_path))

    # Also delete .cdb file (if exists).
    try:
        remove(path.join(common.WAZUH_PATH, rel_path + common.COMPILED_LISTS_EXTENSION))
    except (IOError, OSError):
        pass


def get_filenames_paths(filenames_list: list, root_directory: str = common.USER_LISTS_PATH) -> list:
    """Get full paths from filename list. I.e: test_filename -> {wazuh_path}/etc/lists/test_filename

    Parameters
    ----------
    filenames_list : list
        Filenames to be searched inside root_directory.
    root_directory : str
        Directory where to start the recursive filenames search. Default: common.USER_LISTS_PATH

    Returns
    -------
    list
        Full path to filenames.
    """
    return [str(next(Path(root_directory).rglob(file), path.join(common.USER_LISTS_PATH, file)))
            for file in filenames_list]
