# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from wazuh.core import common
from wazuh.core.cdb_list import iterate_lists, get_list_from_file, REQUIRED_FIELDS, SORT_FIELDS
from wazuh.rbac.decorators import expose_resources
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array


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
            lists.append({'items': get_list_from_file(rel_p),
                          'relative_dirname': os.path.dirname(rel_p),
                          'filename': os.path.split(rel_p)[1]})

    data = process_array(lists, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, select=select, allowed_sort_fields=SORT_FIELDS,
                         required_fields=REQUIRED_FIELDS)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

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
