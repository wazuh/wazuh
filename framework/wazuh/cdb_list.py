# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.core.cdb_list import check_path, iterate_lists
from wazuh.rbac.decorators import expose_resources
from wazuh.results import AffectedItemsWazuhResult
from wazuh.utils import process_array


@expose_resources(actions=['lists:read'], resources=['list:path:{path}'])
def get_lists(path=None, offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True, search_text=None,
              complementary_search=False, search_in_fields=None):
    """Get CDB lists

    :param path: Relative path of list file to get (if it is not specified, all lists will be returned)
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(none_msg='No list was shown',
                                      some_msg='Some lists could not be shown',
                                      all_msg='All specified lists were shown')
    lists = iterate_lists()
    for l in list(lists):
        if l['path'] not in path:
            lists.remove(l)

    result.affected_items = process_array(
        lists, search_text=search_text, search_in_fields=search_in_fields, complementary_search=complementary_search,
        sort_by=sort_by, sort_ascending=sort_ascending, allowed_sort_fields=['path'], offset=offset, limit=limit
    )['items']
    result.total_affected_items += len(result.affected_items)

    return result


@expose_resources(actions=['lists:read'], resources=['list:path:{path}'])
def get_path_lists(path=None, offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True, search_text=None,
                   complementary_search=False, search_in_fields=None):
    """Get paths of all CDB lists

    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(none_msg='No path was shown',
                                      some_msg='Some paths could not be shown',
                                      all_msg='All specified paths were shown')
    lists = iterate_lists(only_names=True)
    for l in list(lists):
        if l['path'] not in path:
            lists.remove(l)

    result.affected_items = process_array(
        lists, search_text=search_text, search_in_fields=search_in_fields, complementary_search=complementary_search,
        sort_by=sort_by, sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    result.total_affected_items += len(result.affected_items)

    return result
