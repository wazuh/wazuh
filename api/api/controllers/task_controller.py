# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.common import database_limit
from wazuh.task import get_task_status

logger = logging.getLogger('wazuh')


async def get_tasks_status(request, pretty=False, wait_for_complete=False, offset=0, limit=database_limit,
                           tasks_list=None, agents_list=None, command=None, node=None, module=None, status=None, q=None,
                           search=None, select=None, sort=None):
    """Check the status of the specified tasks

    Parameters
    ----------
    tasks_list : list
        List of task's IDs
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Tasks's status
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
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
