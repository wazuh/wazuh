# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import os

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import cdb_list
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_lists(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                    select: list = None, sort: str = None, search: str = None, filename: str = None,
                    relative_dirname: str = None):
    """ Get all CDB lists

    :param pretty: Show results in human-readable format.
    :param wait_for_complete: Disable timeout response.
    :param offset: First element to return in the collection.
    :param limit: Maximum number of elements to return.
    :param select: List of selected fields to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string.
    :param filename: List of filenames to filter by.
    :param relative_dirname: Filters by relative dirname
    :return: Data object
    """
    path = [os.path.join(relative_dirname, item) for item in filename] if filename and relative_dirname else None
    f_kwargs = {'offset': offset,
                'select': select,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['relative_dirname',
                                                                                             'filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'filename': filename,
                'relative_dirname': relative_dirname,
                'path': path
                }

    dapi = DistributedAPI(f=cdb_list.get_lists,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_lists_files(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                          limit: int = None, sort: str = None, search: str = None, filename: str = None,
                          relative_dirname: str = None):
    """ Get paths from all CDB lists

    :param pretty: Show results in human-readable format.
    :param wait_for_complete: Disable timeout response.
    :param offset: First element to return in the collection.
    :param limit: Maximum number of elements to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string.
    :param filename: List of filenames to filter by.
    :param relative_dirname: Filters by relative dirname
    :return: Data object
    """
    path = [os.path.join(relative_dirname, item) for item in filename] if filename and relative_dirname else None
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['relative_dirname',
                                                                                             'filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'search_in_fields': ['filename', 'relative_dirname'],
                'filename': filename,
                'relative_dirname': relative_dirname,
                'path': path
                }

    dapi = DistributedAPI(f=cdb_list.get_path_lists,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
