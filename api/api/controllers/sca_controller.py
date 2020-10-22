# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import logging

from aiohttp import web

import wazuh.sca as sca
from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.common import database_limit
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh')


async def get_sca_agent(request, agent_id=None, pretty=False, wait_for_complete=False, name=None, description=None,
                        references=None, offset=0, limit=database_limit, sort=None, search=None, q=None):
    """Get security configuration assessment (SCA) database of an agent

    :param agent_id: Agent ID. All possible values from 000 onwards.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param name: Filters by policy name
    :param description: Filters by policy description
    :param references: Filters by references
    :param offset:First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. This is specially useful to filter by total checks passed, failed or total
    score (fields pass, fail, score)
    :return: AllItemsResponseSCADatabase
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

    :param agent_id: Agent ID. All possible values from 000 onwards
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param policy_id: Filters by policy id
    :param title: Filters by title
    :param description: Filters by policy description
    :param rationale: Filters by rationale
    :param remediation: Filters by remediation
    :param command: Filters by command
    :param status: Filters by status
    :param reason: Filters by reason
    :param file: Filters by file
    :param process: Filters by process
    :param directory: Filters by directory
    :param registry: Filters by registry
    :param references: Filters by references
    :param result: Filters by result
    :param condition: Filters by condition
    :param offset:First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. This is specially useful to filter by total checks passed, failed or total
    score (fields pass, fail, score)
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
