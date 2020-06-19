# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from os import listdir
from os.path import isfile, isdir, join

from wazuh import common
from wazuh.exception import WazuhError

REQUIRED_FIELDS = ['relative_dirname', 'filename']
SORT_FIELDS = ['relative_dirname', 'filename']

_regex_path = r'^(etc/lists/)[\w\.\-/]+$'
_pattern_path = re.compile(_regex_path)


def get_relative_path(path):
    """Get relative path

    :param path: Original path
    :return: Relative path (from Wazuh base directory)
    """
    return path.replace(common.ossec_path, '')[1:]


def check_path(path):
    """Check if path is well formed (without './' or '../')

    :param path: Path to check
    :return: Result of check the path (boolean)
    """
    if './' in path or '../' in path or not _pattern_path.match(path):
        raise WazuhError(1801)


@common.context_cached('system_lists')
def iterate_lists(absolute_path=common.lists_path, only_names=False):
    """Get the content of all CDB lists

    :param absolute_path: Full path of directory to get CDB lists
    :param only_names: If this parameter is true, only the name of all lists will be showed
    :return: List with all CDB lists
    """
    dir_content = listdir(absolute_path)
    output = list()

    # For skipping .swp files
    regex_swp = r'^\.{1}[\w\-/]+(.swp){1}$'
    pattern = re.compile(regex_swp)

    for name in dir_content:
        new_absolute_path = join(absolute_path, name)
        new_relative_path = get_relative_path(new_absolute_path)
        # '.cdb' and '.swp' files are skipped
        if (isfile(new_absolute_path)) and ('.cdb' not in name) and ('~' not in name) and not pattern.search(name):
            if only_names:
                relative_path = get_relative_path(absolute_path)
                output.append({'relative_dirname': relative_path, 'filename': name})
            else:
                items = get_list_from_file(new_relative_path)
                output.append({'relative_dirname': new_relative_path, 'filename': name, 'items': items})
        elif isdir(new_absolute_path):
            output += iterate_lists(new_absolute_path, only_names=only_names)

    return output


def get_list_from_file(path):
    """Get CDB list from file

    :param path: Relative path of list file to get
    :return: CDB list
    """
    file_path = join(common.ossec_path, path)
    output = list()

    try:
        with open(file_path) as f:
            for line in f.read().splitlines():
                if 'TEMPLATE' not in line:
                    key, value = line.split(':')
                    output.append({'key': key, 'value': value})
    except OSError as e:
        if e.errno == 2:
            raise WazuhError(1802)
        elif e.errno == 13:
            raise WazuhError(1803)
        elif e.errno == 21:
            raise WazuhError(1804, extra_message="{0} {1}".format(join('WAZUH_HOME', file_path), "is a directory"))
        else:
            raise e
    except ValueError:
        raise WazuhError(1800, extra_message={'path': join('WAZUH_HOME', file_path)})

    return output
