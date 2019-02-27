#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


from os import listdir
from os.path import isfile, isdir, join
import re

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.utils import sort_array, search_array


_regex_path = r'^(etc/lists/)[\w\.\-/]+$'
_pattern_path = re.compile(_regex_path)


def _get_relative_path(path):
    """
    Get relative path
    :param path: Original path
    :return: Relative path (from Wazuh base directory)
    """
    return path.replace(common.ossec_path, '')[1:]


def _check_path(path):
    """
    Check if path is well formed (without './' or '../')
    :param path: Path to check
    :return: Result of check the path (boolean)
    """
    if './' in path or '../' in path or not _pattern_path.match(path):
        raise WazuhException(1801)


def _iterate_lists(absolute_path, only_names=False):
    """
    Get the content of all CDB lists
    :param absolute_path: Full path of directory to get CDB lists
    :param only_names: If this parameter is true, only the name of all lists will be showed
    :return: List with all CDB lists
    """
    output = []
    dir_content = listdir(absolute_path)

    # for skipping .swp files
    regex_swp = r'^\.{1}[\w\-/]+(.swp){1}$'
    pattern = re.compile(regex_swp)

    for name in dir_content:
        new_absolute_path = join(absolute_path, name)
        new_relative_path = _get_relative_path(new_absolute_path)
        # '.cdb' and '.swp' files are skipped
        if (isfile(new_absolute_path)) \
            and ('.cdb' not in name)  \
            and ('~' not in name) \
            and not pattern.search(name):
            if only_names:
                relative_path = _get_relative_path(absolute_path)
                output.append({'path': relative_path, 'name': name})
            else:
                items = get_list_from_file(new_relative_path)
                output.append({'path': new_relative_path, 'items': items})
        elif isdir(new_absolute_path):
            if only_names:
                output += _iterate_lists(new_absolute_path, only_names=True)
            else:
                output += _iterate_lists(new_absolute_path)

    return output


def get_lists(path=None, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Get CDB lists
    :param path: Relative path of list file to get (if it is not specified, all lists will be returned)
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items.
    :param search:  Looks for items with the specified string.
    :return: CDB list
    """

    output = []

    if limit == 0:
        raise WazuhException(1406)

    # if path parameter is present, return only CDB list from path
    if path:
        # check if path is correct
        _check_path(path)
        output.append(get_list_from_file(path))
    else:
        output = _iterate_lists(common.lists_path)

    if offset:
        output = output[offset:]

    if search:
        # only search in path field
        output = search_array(output, search['value'], search['negation'], fields=['path'])

    if sort:
        output = sort_array(output, sort['fields'], sort['order'], allowed_sort_fields=['path'])

    # limit is common.database_limit by default
    output = output[:limit]

    return {'totalItems' : len(output), 'items': output}


def get_list_from_file(path):
    """
    Get CDB list from file
    :param path: Relative path of list file to get
    :return: CDB list
    """
    file_path = join(common.ossec_path, path)
    output = []

    try:
        with open(file_path) as f:
            for line in f.read().splitlines():
                if 'TEMPLATE' in line:
                    continue
                else:
                    key, value = line.split(':')
                    output.append({'key': key, 'value': value})

    except IOError:
        raise WazuhException(1006)

    except ValueError:
        raise WazuhException(1800, {'path': path})

    except Exception:
        raise WazuhException(1000)

    return output


def get_path_lists(offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Get paths of all CDB lists
    :return: List with paths of all CDB lists
    """
    output = _iterate_lists(common.lists_path, only_names=True)

    if limit == 0:
        raise WazuhException(1406)

    if offset:
        output = output[offset:]

    if search:
        # only search in path field
        output = search_array(output, search['value'], search['negation'], fields=['name', 'path'])

    if sort:
        output = sort_array(output, sort['fields'], sort['order'], allowed_sort_fields=['name', 'path'])

    # limit is common.database_limit by default
    output = output[:limit]

    return {'totalItems': len(output), 'items': output}
