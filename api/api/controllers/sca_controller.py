# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import logging

from aiohttp import web
from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc

import wazuh.sca as sca
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.common import database_limit

logger = logging.getLogger('wazuh-api')


async def get_sca_agent(request, agent_id=None, pretty=False, wait_for_complete=False, name=None, description=None,
                        references=None, offset=0, limit=database_limit, sort=None, search=None, q=None):
    """Get security configuration assessment (SCA) database of an agent

    Parameters
    ----------
    agent_id : str
        Agent ID. All possible values since 000 onwards.
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response
    name : str
        Filters by policy name
    description : str
        Filters by policy description
    references : str
        Filters by references
    offset : int
        First element to return in the collection
    limit : int
        Maximum number of elements to return
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order
    search : str
        Looks for elements with the specified string
    q : str
        Query to filter results by. This is specially useful to filter by total checks passed, failed or total score (fields pass, fail, score)

    Returns
    -------
    AllItemsResponseSCADatabase
    """
    filters = {'name': name,
               'description': description,
               'references': references}

    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': q,
                'filters': filters}
    dapi = DistributedAPI(f=sca.get_sca_list,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_sca_checks(request, agent_id=None, pretty=False, wait_for_complete=False, policy_id=None, title=None,
                         description=None, rationale=None, remediation=None, command=None, status=None, reason=None,
                         file=None, process=None, directory=None, registry=None, references=None, result=None,
                         condition=None, offset=0, limit=database_limit, sort=None, search=None, q=None):
    """Get policy monitoring alerts for a given policy

    Parameters
    ----------
    agent_id : str
        Agent ID. All possible values since 000 onwards
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response
    policy_id : str
        Filters by policy id
    title : str
        Filters by title
    description : str
        Filters by policy description
    rationale : str
        Filters by rationale
    remediation : str
        Filters by remediation
    command : str
        Filters by command
    status : str
        Filters by status
    reason : str
        Filters by reason
    file : str
        Filters by file
    process : str
        Filters by process
    directory : str
        Filters by directory
    registry : str
        Filters by registry
    references : str
        Filters by references
    result : str
        Filters by result
    condition : str
        Filters by condition
    offset : int
        First element to return in the collection
    limit : int
        Maximum number of elements to return
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order
    search : str
        Looks for elements with the specified string
    q : str
        Query to filter results by. This is specially useful to filter by total checks passed, failed or total score (fields pass, fail, score)

    Returns
    -------
    AllItemsResponseSCADatabase
    """
    filters = {'title': title,
               'description': description,
               'rationale': rationale,
               'remediation': remediation,
               'command': command,
               'status': status,
               'reason': reason,
               'file': file,
               'process': process,
               'directory': directory,
               'registry': registry,
               'references': references,
               'result': result,
               'condition': condition}

    f_kwargs = {'policy_id': policy_id,
                'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': q,
                'filters': filters}

    dapi = DistributedAPI(f=sca.get_sca_checks,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
