# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.common import DATABASE_LIMIT
from wazuh.task import get_task_status

logger = logging.getLogger('wazuh')


async def get_tasks_status(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                           limit: int = DATABASE_LIMIT, tasks_list: list = None, agents_list: list = None,
                           command: str = None, node: str = None, module: str = None, status: str = None, q: str = None,
                           search: str = None, select: str = None, sort: str = None) -> ConnexionResponse:
    """Check the status of the specified tasks.

    Parameters
    ----------
    request : request.connexion
    tasks_list : list
        List of tasks ID.
    agents_list : list
        List of agents ID.
    offset : int
        First element to return.
    limit : int
        Maximum number of elements to return. Default: DATABASE_LIMIT
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/. at the beginning to list in ascending
        or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return.
    q : str
        Query to filter results by.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    command : str
        Filters by command.
    node : str
        Filters by node.
    module : str
        Filters by module.
    status : str
        Filters by status.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'select': select, 'search': parse_api_param(search, 'search'),
                'offset': offset, 'limit': limit,
                'filters': {
                    'task_list': tasks_list,
                    'agent_list': agents_list,
                    'status': status,
                    'module': module,
                    'command': command,
                    'node': node
                },
                'sort': parse_api_param(sort, 'sort'), 'q': q
                }

    dapi = DistributedAPI(f=get_task_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
