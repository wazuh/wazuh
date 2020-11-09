# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import parse_api_param, remove_nones_to_dict, raise_if_exc
from wazuh import rootcheck
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh')


async def put_rootcheck(request, pretty=False, wait_for_complete=False, agents_list='*'):
    """Run rootcheck scan over the agent_ids.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agent's IDs.
    """
    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=rootcheck.run,
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


async def delete_rootcheck(request, pretty=False, wait_for_complete=False, agents_list='*'):
    """Clear the rootcheck database for a list of agents.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agent's IDs.
    """
    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=rootcheck.clear,
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


async def get_rootcheck_agent(request, pretty=False, wait_for_complete=False, agent_id=None, offset=0, limit=None,
                              sort=None, search=None, select=None, q='', distinct=None, status='all', pci_dss=None,
                              cis=None):
    """Return a list of events from the rootcheck database.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        ID of the agent's rootcheck info to retrieve.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    select : str
        Select which fields to return (separated by comma).
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.
    status : str
        Filter by scan status.
    pci_dss : str
        Filter by PCI requirement.
    cis : str
        Filter by CIS requirement.
    """
    f_kwargs = {'agent_list': [agent_id],
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': select,
                'q': q,
                'distinct': distinct,
                'filters': {
                    'status': status,
                    'pci_dss': pci_dss,
                    'cis': cis
                    },
                }

    dapi = DistributedAPI(f=rootcheck.get_rootcheck_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_last_scan_agent(request, pretty=False, wait_for_complete=False, agent_id=None):
    """Get the last rootcheck scan of an agent.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        ID of the agent's rootcheck info to retrieve.
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=rootcheck.get_last_scan,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
