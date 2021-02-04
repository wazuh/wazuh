# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from pathlib import Path
from shutil import Error

from wazuh.core import common
from wazuh.core.cdb_list import iterate_lists, get_list_from_file, REQUIRED_FIELDS, SORT_FIELDS, create_tmp_list, \
    get_relative_path, delete_list
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array, delete_wazuh_file, safe_move
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=['lists:read'], resources=['list:file:{filename}'])
def get_lists(filename=None, offset=0, limit=common.database_limit, select=None, sort_by=None, sort_ascending=True,
              search_text=None, complementary_search=False, search_in_fields=None, relative_dirname=None):
    """Get CDB lists content.

    Parameters
    ----------
    filename : list
        Filenames to filter by.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    select : list
        List of selected fields to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : boolean
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    search_in_fields : str
        Name of the field to search in for the `search_text`.
    relative_dirname : str
         Filter by relative dirname.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Lists content.
    """
    result = AffectedItemsWazuhResult(all_msg='All specified lists were returned',
                                      some_msg='Some lists were not returned',
                                      none_msg='No list was returned')
    dirname = os.path.join(common.ossec_path, relative_dirname) if relative_dirname else None

    # Get full paths from filename list. I.e: test_filename -> {wazuh_path}/etc/lists/test_filename
    paths = [str(next(Path(common.lists_path).rglob(file), os.path.join(common.lists_path, file))) for file in filename]

    lists = list()
    for path in paths:
        if not any([dirname is not None and os.path.dirname(path) != dirname, not os.path.isfile(path)]):
            lists.append({'items': [{'key': key, 'value': value} for key, value in get_list_from_file(path).items()],
                          'relative_dirname': os.path.dirname(get_relative_path(path)),
                          'filename': os.path.split(get_relative_path(path))[1]})

    data = process_array(lists, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, select=select, allowed_sort_fields=SORT_FIELDS,
                         required_fields=REQUIRED_FIELDS)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['lists:read'], resources=['list:file:{filename}'])
def get_list_file(filename=None, raw=None):
    """Get a CDB list file content. The file is recursively searched.

    Parameters
    ----------
    filename : list
        Full path of CDB list file to get.
    raw : bool, optional
        Respond in raw format.

    Returns
    -------
    result : AffectedItemsWazuhResult
        CDB list content.
    """
    result = AffectedItemsWazuhResult(all_msg='CDB list was returned',
                                      none_msg='No list was returned')

    try:
        # Recursively search for filename inside {wazuh_path}/etc/lists/
        content = get_list_from_file(str(next(Path(common.lists_path).rglob(filename[0]), '')), raw)
        if raw:
            result = content
        else:
            result.affected_items.append(content)
            result.total_affected_items = 1
    except WazuhError as e:
        result.add_failed_item(id_=filename[0], error=e)

    return result


@expose_resources(actions=['lists:update'], resources=['*:*:*'])
def upload_list_file(filename=None, content=None, overwrite=False):
    """Upload a new list file.

    Parameters
    ----------
    filename : str
        Destination path of the new file.
    content : str
        Content of file to be uploaded.
    overwrite : bool
        True for updating existing files, false otherwise.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation message.
    """
    result = AffectedItemsWazuhResult(all_msg='CDB list file uploaded successfully',
                                      none_msg='Could not upload CDB list file')
    path = os.path.join('etc', 'lists', filename)

    try:
        if len(content) == 0:
            raise WazuhError(1112)

        # Validation is performed after creating tmp file, so it has to be created before overwriting file (if needed).
        tmp_list_file = create_tmp_list(content)
        try:
            # If file already exists and overwrite is False, raise exception.
            if not overwrite and os.path.exists(os.path.join(common.ossec_path, path)):
                raise WazuhError(1905)
            elif overwrite and os.path.exists(os.path.join(common.ossec_path, path)):
                # Original file will not be deleted if create_tmp_list validation was not successful.
                delete_list_file(filename=filename)
            # If file with same name already exists in subdirectory.
            elif str(next(Path(common.lists_path).rglob(filename), '')) != '':
                raise WazuhError(1805)

            try:
                # Move temporary file to group folder.
                safe_move(tmp_list_file, os.path.join(common.ossec_path, path), permissions=0o660)
            except Error:
                raise WazuhInternalError(1016)

            result.affected_items.append(path)
            result.total_affected_items = len(result.affected_items)
        finally:
            os.path.exists(tmp_list_file) and delete_wazuh_file(tmp_list_file)
    except WazuhError as e:
        result.add_failed_item(id_=path, error=e)

    return result


@expose_resources(actions=['lists:delete'], resources=['list:file:{filename}'])
def delete_list_file(filename):
    """Delete a CDB list file.

    Parameters
    ----------
    filename : list
        Destination path of the new file.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation message.
    """
    result = AffectedItemsWazuhResult(all_msg='CDB list file was successfully deleted',
                                      none_msg='Could not delete CDB list file')
    path = get_relative_path(os.path.join(common.lists_path, filename[0]))

    try:
        delete_list(path)
        result.affected_items.append(path)
    except WazuhError as e:
        result.add_failed_item(id_=path, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['lists:read'], resources=['list:file:{filename}'])
def get_path_lists(filename=None, offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True,
                   search_text=None, complementary_search=False, search_in_fields=None, relative_dirname=None):
    """Get paths of all CDB lists.

    Parameters
    ----------
    filename : list
        List of filenames to filter by.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : boolean
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Find items with the specified string.
    complementary_search : bool
        If True, only results NOT containing `search_text` will be returned. If False, only results that contains
        `search_text` will be returned.
    search_in_fields : str
        Name of the field to search in for the `search_text`.
    relative_dirname : str
         Filter by relative dirname.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Paths of all CDB lists.
    """
    result = AffectedItemsWazuhResult(all_msg='All specified paths were returned',
                                      some_msg='Some paths were not returned',
                                      none_msg='No path was returned')

    # Get relative paths from filename list. I.e: test_filename -> etc/lists/test_filename
    paths = [
        os.path.relpath(
            str(next(Path(common.lists_path).rglob(file), os.path.join(common.lists_path, file))),
            common.ossec_path
        ) for file in filename
    ]

    lists = iterate_lists(only_names=True)
    for item in list(lists):
        if any([relative_dirname is not None and item['relative_dirname'] != relative_dirname,
                os.path.join(item['relative_dirname'], item['filename']) not in paths]):
            lists.remove(item)

    data = process_array(lists, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result
