# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
from typing import List

import connexion

import wazuh.ciscat as ciscat
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, parse_api_param, exception_handler, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_agents_ciscat_results(agent_id: str, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                              limit: int = None, select: List[str] = None, sort: str = None, search: str = None,
                              benchmark: str = None, profile: str = None, fail: int = None, error: int = None,
                              notchecked: int = None, unknown: int = None, score: int = None):
    """Get CIS-CAT results from an agent

    Returns the agent's ciscat results info.

    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param pretty: Show results in human-readable format 
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param benchmark: Filters by benchmark type.
    :param profile: Filters by evaluated profile.
    :param pass: Filters by passed checks
    :param fail: Filters by failed checks
    :param error: Filters by encountered errors
    :param notchecked: Filters by not checked
    :param unknown: Filters by unknown results.
    :param score: Filters by final score
    """

    # We get pass param using connexion as pass is a python reserved keyword
    try:
        pass_ = connexion.request.args['pass']
    except KeyError:
        pass_ = None

    f_kwargs = {
        'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
        'search': parse_api_param(search, 'search'), 'select': select, 'agent_id': agent_id,
        'filters': {
            'benchmark': benchmark, 'profile': profile, 'pass': pass_, 'fail': fail, 'error': error,
            'notchecked': notchecked, 'unknown': unknown, 'score': score
                }
            }

    dapi = DistributedAPI(f=ciscat.get_ciscat_results,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200
