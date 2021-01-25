# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from pathlib import Path
from shutil import Error

from wazuh.core import common
from wazuh.core.cdb_list import iterate_lists, get_list_from_file, REQUIRED_FIELDS, SORT_FIELDS, create_tmp_list
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array, delete_file, safe_move
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=['lists:read'], resources=['list:path:{path}'])
def get_lists(path=None, offset=0, limit=common.database_limit, select=None, sort_by=None, sort_ascending=True,
              search_text=None, complementary_search=False, search_in_fields=None, relative_dirname=None,
              filename=None):
    """Get CDB lists

    :param path: Relative path of list file to get (if it is not specified, all lists will be returned)
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param select: List of selected fields to return
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param relative_dirname: Filters by relative dirname.
    :param filename: List of filenames to filter by.
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='All specified lists were returned',
                                      some_msg='Some lists were not returned',
                                      none_msg='No list was returned')

    lists = list()
    for rel_p in path:
        if not any([relative_dirname is not None and os.path.dirname(rel_p) != relative_dirname,
                    filename is not None and os.path.split(rel_p)[1] not in filename]):
            lists.append({'items': [{'key': key, 'value': value} for key, value in get_list_from_file(
                os.path.join(common.ossec_path, rel_p)).items()],
                          'relative_dirname': os.path.dirname(rel_p),
                          'filename': os.path.split(rel_p)[1]})

    data = process_array(lists, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, select=select, allowed_sort_fields=SORT_FIELDS,
                         required_fields=REQUIRED_FIELDS)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['lists:read'], resources=['list:path:{filename}'])
def get_list_file(filename=None, raw=None):
    """Get content of a CDB list file. The file is recursively searched.

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
        # rglob will recursively search for filename inside {wazuh_path}/etc/lists/
        content = get_list_from_file(str(next(Path(common.lists_path).rglob(filename[0]), '')), raw)
        if raw:
            result = content
        else:
            result.affected_items.append(content)
            result.total_affected_items = 1
    except WazuhError as e:
        result.add_failed_item(id_=filename[0], error=e)

    return result


@expose_resources(actions=['lists:update'], resources=['list:path:{filename}'])
def upload_list_file(filename=None, content=None, overwrite=False):
    """Upload a new list file.

    Parameters
    ----------
    filename : list
        Destination path of the new file.
    content : str
        Content of file to be uploaded.
    overwrite : bool
        True for updating existing files, false otherwise

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation message.
    """
    result = AffectedItemsWazuhResult(all_msg='CDB list file uploaded successfully',
                                      none_msg='Could not upload CDB list file')
    path = os.path.join('etc', 'lists', filename[0])

    try:
        if len(content) == 0:
            raise WazuhError(1112)

        # Validation is performed after creating tmp file, so it has to be created before overwriting file (if needed)
        tmp_list_file = create_tmp_list(content)
        try:
            # If file already exists and overwrite is False, raise exception
            if not overwrite and os.path.exists(os.path.join(common.ossec_path, path)):
                raise WazuhError(1905)
            elif overwrite and os.path.exists(os.path.join(common.ossec_path, path)):
                # Original file will not be deleted if create_tmp_list validation was not successful.
                delete_list_file(filename=filename[0])

            try:
                # Move temporary file to group folder
                safe_move(tmp_list_file, os.path.join(common.ossec_path, path), permissions=0o660)
            except Error:
                raise WazuhInternalError(1016)

            result.affected_items.append(path)
            result.total_affected_items = len(result.affected_items)
        finally:
            os.path.exists(tmp_list_file) and delete_file(tmp_list_file)
    except WazuhError as e:
        result.add_failed_item(id_=path, error=e)

    return result


@expose_resources(actions=['lists:delete'], resources=['list:path:{filename}'])
def delete_list_file(filename):
    """Delete a CDB list file.

    Parameters
    ----------
    filename : str
        Destination path of the new file.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation message.
    """
    result = AffectedItemsWazuhResult(all_msg='CDB list file was successfully deleted',
                                      none_msg='Could not delete CDB list file')
    path = str(next(Path(common.lists_path).rglob(filename[0]), ''))

    try:
        delete_file(path)
        result.affected_items.append(os.path.relpath(path, common.ossec_path))
    except WazuhError as e:
        result.add_failed_item(id_=filename[0], error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['lists:read'], resources=['list:path:{path}'])
def get_path_lists(path=None, offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True,
                   search_text=None, complementary_search=False, search_in_fields=None, relative_dirname=None,
                   filename=None):
    """Get paths of all CDB lists

    :param path: List of paths to read lists from
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param relative_dirname: Filters by relative dirname.
    :param filename: List of filenames to filter by.
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='All specified paths were returned',
                                      some_msg='Some paths were not returned',
                                      none_msg='No path was returned')

    lists = iterate_lists(only_names=True)
    for item in list(lists):
        if any([relative_dirname is not None and item['relative_dirname'] != relative_dirname,
                filename is not None and item['filename'] not in filename,
                os.path.join(item['relative_dirname'], item['filename']) not in path]):
            lists.remove(item)

    data = process_array(lists, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result
