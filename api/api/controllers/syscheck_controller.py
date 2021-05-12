# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.syscheck import run, clear, files, last_scan

logger = logging.getLogger('wazuh-api')


async def put_syscheck(request, agents_list='*', pretty=False, wait_for_complete=False):
    """Run a syscheck scan in the specified agents.

    Parameters
    ----------
    list_agents : str
        List of agent ids.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    result : json_response
        Json response with the API response.
    """
    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=run,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_syscheck_agent(request, agent_id, pretty=False, wait_for_complete=False, offset=0,
                             limit=None, select=None, sort=None, search=None, distinct=False,
                             summary=False, md5=None, sha1=None, sha256=None, q=None, arch=None):
    """Get file integrity monitoring scan result from an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    search : str
        Looks for elements with the specified string.
    summary : bool
        Returns a summary grouping by filename.
    md5 : str
        Filters files with the specified MD5 checksum.
    sha1 : str
        Filters files with the specified SHA1 checksum.
    sha256 : str
        Filters files with the specified SHA256 checksum.
    distinct : bool
        Look for distinct values.
    q : str
        Query to filter results by.
    arch : str
        Specify whether the associated entry is 32 or 64 bits. Allowed values: '[x32]' and '[x64]'.

    Returns
    -------
    result : json_response
        Json response with the API response.
    """

    # get type parameter from query
    type_ = request.query.get('type', None)
    # get hash parameter from query
    hash_ = request.query.get('hash', None)
    # get file parameter from query
    file_ = request.query.get('file', None)

    filters = {'type': type_, 'md5': md5, 'sha1': sha1, 'sha256': sha256, 'hash': hash_, 'file': file_, 'arch': arch,
               'value.name': request.query.get('value.name', None), 'value.type': request.query.get('value.type', None)}

    f_kwargs = {'agent_list': [agent_id], 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'summary': summary, 'filters': filters, 'distinct': distinct, 'q': q}

    dapi = DistributedAPI(f=files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_syscheck_agent(request, agent_id='*', pretty=False, wait_for_complete=False):
    """Clear file integrity monitoring scan results for a specified agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    result : json_response
        Json response with the API response.
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_last_scan_agent(request, agent_id, pretty=False, wait_for_complete=False):
    """Return when the last syscheck scan of a specified agent started and ended

    Parameters
    ----------
    agent_id : str
        Agent ID.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    result : json_response
        Json response with the API response.
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=last_scan,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
