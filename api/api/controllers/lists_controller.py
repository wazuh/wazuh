# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh import cdb_list
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_lists(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
              sort: str = None, search: str = None, path: str = None):
    """ Get all CDB lists

    :param pretty: Show results in human-readable format.
    :param wait_for_complete: Disable timeout response.
    :param offset: First element to return in the collection.
    :param limit: Maximum number of elements to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string.
    :param path: Filters by list path.
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),  'path': path}

    dapi = DistributedAPI(f=cdb_list.get_lists,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_list(pretty: bool = False, wait_for_complete: bool = False, path: str = None):
    """ Get CBD list from a specific file path

    :param pretty: Show results in human-readable format.
    :param wait_for_complete: Disable timeout response.
    :param path: File path to load list from
    """
    f_kwargs = {'file_path': path}

    dapi = DistributedAPI(f=cdb_list.get_list,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_lists_files(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                    sort: str = None, search: str = None):
    """ Get paths from all CDB lists

    :param pretty: Show results in human-readable format.
    :param wait_for_complete: Disable timeout response.
    :param offset: First element to return in the collection.
    :param limit: Maximum number of elements to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string.
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=cdb_list.get_path_lists,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200
