# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from connexion.lifecycle import ConnexionResponse

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh import cdb_list

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_lists(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
              sort: str = None, search: str = None, path: str = None, status: str = None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param path: Filters by rule path.
    :type path: str
    :param status: Filters by rules status.
    :type status: List[str]
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),  'path': path, 'status': status}

    dapi = DistributedAPI(f=cdb_list.get_lists,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


def get_lists_files():
    pass
