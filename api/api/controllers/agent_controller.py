# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Union

from aiohttp import web
from connexion.lifecycle import ConnexionResponse

from api.encoder import dumps, prettify
from api.models.agent_added_model import AgentAddedModel
from api.models.agent_inserted_model import AgentInsertedModel
from api.models.base_model_ import Body
from api.models.group_added_model import GroupAddedModel
from api.util import parse_api_param, remove_nones_to_dict, raise_if_exc, deprecate_endpoint
from api.validator import check_component_configuration_pair
from wazuh import agent, stats
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.common import DATABASE_LIMIT
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')


async def delete_agents(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = None,
                        purge: bool = False, status: str = None, q: str = None, older_than: str = None,
                        manager: str = None, version: str = None, group: str = None, node_name: str = None,
                        name: str = None, ip: str = None) -> web.Response:
    """Delete all agents or a list of them based on optional criteria.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agents IDs. If the 'all' keyword is indicated, all the agents are deleted.
    purge : bool
        Delete an agent from the key store.
    status : str
        Filter by agent status. Use commas to filter by multiple statuses.
    q : str
        Query to filter agents by.
    older_than : str
        Filter out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’,
        ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never_connected agents, use the register date.
    manager : str
        Filter by the name of the manager to which agents are connected.
    version : str
        Filter by agents version.
    group : str
        Filter by group of agents.
    node_name : str
        Filter by node name.
    name : str
        Filter by agent name.
    ip : str
        Filter by agent IP.

    Returns
    -------
    web.Response
        Agents which have been deleted.
    """
    if 'all' in agents_list:
        agents_list = None
    f_kwargs = {'agent_list': agents_list,
                'purge': purge,
                'filters': {
                    'status': status,
                    'older_than': older_than,
                    'manager': manager,
                    'version': version,
                    'group': group,
                    'node_name': node_name,
                    'name': name,
                    'ip': ip,
                    'registerIP': request.query.get('registerIP', None)
                },
                'q': q
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query.get(field, None)

    dapi = DistributedAPI(f=agent.delete_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agents(request, pretty: bool = False, wait_for_complete: bool = False, agents_list: str = None,
                     offset: int = 0, limit: int = DATABASE_LIMIT, select: str = None, sort: str = None,
                     search: str = None, status: str = None, q: str = None, older_than: str = None, manager: str = None,
                     version: str = None, group: str = None, node_name: str = None, name: str = None, ip: str = None,
                     group_config_status: str = None, distinct: bool = False) -> web.Response:
    """Get information about all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agents IDs.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: DATABASE_LIMIT
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    status : str
        Filter by agent status. Use commas to enter multiple statuses.
    q : str
        Query to filter results by. For example "q&#x3D;&amp;quot;status&#x3D;active&amp;quot;".
    older_than : str
        Filter out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’,
        ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never_connected agents, use the register date.
    manager : str
        Filter by manager hostname to which agents are connected.
    version : str
        Filter by agents version.
    group : str
        Filter by agent group.
    node_name : str
        Filter by node name.
    name : str
        Filter by agent name.
    ip : str
        Filter by agent IP.
    group_config_status : str
        Filter by agent groups configuration sync status.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response
        Response with all selected agents' information.
    """
    f_kwargs = {'agent_list': agents_list,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': select,
                'filters': {
                    'status': status,
                    'older_than': older_than,
                    'manager': manager,
                    'version': version,
                    'group': group,
                    'node_name': node_name,
                    'name': name,
                    'ip': ip,
                    'registerIP': request.query.get('registerIP', None),
                    'group_config_status': group_config_status
                },
                'q': q,
                'distinct': distinct
                }
    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query.get(field, None)

    dapi = DistributedAPI(f=agent.get_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def add_agent(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Add a new Wazuh agent.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await AgentAddedModel.get_kwargs(request)

    dapi = DistributedAPI(f=agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def reconnect_agents(request, pretty: bool = False, wait_for_complete: bool = False,
                           agents_list: Union[list, str] = '*') -> web.Response:
    """Force reconnect all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format. Default `False`
    wait_for_complete : bool
        Disable timeout response. Default `False`
    agents_list : list or str
        List of agent IDs. All possible values from 000 onwards. Default `*`

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=agent.reconnect_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          rbac_permissions=request['token_info']['rbac_policies'],
                          broadcasting=agents_list == '*',
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def restart_agents(request, pretty: bool = False, wait_for_complete: bool = False,
                         agents_list: str = '*') -> web.Response:
    """Restart all agents or a list of them.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agents IDs. Default: `*`

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=agent.restart_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          rbac_permissions=request['token_info']['rbac_policies'],
                          broadcasting=agents_list == '*',
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def restart_agents_by_node(request, node_id: str, pretty: bool = False,
                                 wait_for_complete: bool = False) -> web.Response:
    """Restart all agents belonging to a node.

    Parameters
    ----------
    node_id : str
        Cluster node name.
    pretty : bool, optional
        Show results in human-readable format. Default `False`
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`

    Returns
    -------
    web.Response
        API response.
    """
    nodes = raise_if_exc(await get_system_nodes())

    f_kwargs = {'node_id': node_id, 'agent_list': '*'}

    dapi = DistributedAPI(f=agent.restart_agents_by_node,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_config(request, pretty: bool = False, wait_for_complete: bool = False, agent_id: str = None,
                           component: str = None, **kwargs: dict) -> web.Response:
    """Get agent active configuration.

    Returns the active configuration the agent is currently using. This can be different from the configuration present
    in the configuration file, if it has been modified and the agent has not been restarted yet.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 000 onwards.
    component : str
        Selected agent's component which configuration is got.

    Returns
    -------
    web.Response
        API response with the agent configuration.
    """
    f_kwargs = {'agent_list': [agent_id],
                'component': component,
                'config': kwargs.get('configuration', None)
                }

    raise_if_exc(check_component_configuration_pair(f_kwargs['component'], f_kwargs['config']))

    dapi = DistributedAPI(f=agent.get_agent_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_single_agent_multiple_groups(request, agent_id: str, groups_list: str = None, pretty: bool = False,
                                              wait_for_complete: bool = False) -> web.Response:
    """Remove the agent from all groups or a list of them.

    The agent will automatically revert to the "default" group if it is removed from all its assigned groups.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 000 onwards.
    groups_list : str
        Array of groups IDs to remove the agent from.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': [agent_id],
                'group_list': groups_list}

    dapi = DistributedAPI(f=agent.remove_agent_from_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@deprecate_endpoint()
async def get_sync_agent(request, agent_id: str, pretty: bool = False, wait_for_complete=False) -> web.Response:
    """Get agent configuration sync status.

    Return whether the agent group configuration has been synchronized with the agent or not.

    Parameters
    ----------
    request : connexion.request
    agent_id : str
        Agent ID.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Reponse
        API response with the agent configuration sync status.
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=agent.get_agents_sync_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_single_agent_single_group(request, agent_id: str, group_id: str, pretty: bool = False,
                                           wait_for_complete: bool = False) -> web.Response:
    """Remove agent from a single group.

    Removes an agent from a group. If the agent has multigroups, it will preserve all previous groups except the last
    one.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 000 onwards.
    group_id : str
        ID of the group to remove the agent from.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': [agent_id],
                'group_list': [group_id]}

    dapi = DistributedAPI(f=agent.remove_agent_from_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_agent_single_group(request, agent_id: str, group_id: str, force_single_group: bool = False,
                                 pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Assign an agent to the specified group.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 000 onwards.
    group_id : str
        ID of the group to remove the agent from.
    force_single_group : bool
        Forces the agent to belong to only the specified group.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': [agent_id],
                'group_list': [group_id],
                'replace': force_single_group}

    dapi = DistributedAPI(f=agent.assign_agents_to_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_key(request, agent_id: str, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get agent key.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 000 onwards.

    Returns
    -------
    web.Response
        API response with the specified agent's key.
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=agent.get_agents_keys,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def restart_agent(request, agent_id: str, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Restart an agent.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 000 onwards.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=agent.restart_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_upgrade_agents(request, agents_list: str = None, pretty: bool = False, wait_for_complete: bool = False,
                             wpk_repo: str = None, upgrade_version: str = None, use_http: bool = False,
                             force: bool = False, q: str = None, manager: str = None, version: str = None,
                             group: str = None, node_name: str = None, name: str = None,
                             ip: str = None) -> web.Response:
    """Upgrade agents using a WPK file from an online repository.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agent IDs. All possible values from 000 onwards.
    wpk_repo : str
        WPK repository.
    upgrade_version : str
        Wazuh version to upgrade to.
    use_http : bool
        Use protocol http. If it's false use https. By default the value is set to false.
    force : bool
        Force upgrade.
    q : str
        Query to filter agents by.
    manager : str
        Filter by manager hostname to which agents are connected.
    version : str
        Filter by agents version.
    group : str
        Filter by group of agents.
    node_name : str
        Filter by node name.
    name : str
        Filter by agent name.
    ip : str
        Filter by agent IP.

    Returns
    -------
    web.Response
        Upgrade message after trying to upgrade the agents.
    """
    # If we use the 'all' keyword and the request is distributed_master, agents_list must be '*'
    if 'all' in agents_list:
        agents_list = '*'

    f_kwargs = {'agent_list': agents_list,
                'wpk_repo': wpk_repo,
                'version': upgrade_version,
                'use_http': use_http,
                'force': force,
                'filters': {
                    'manager': manager,
                    'version': version,
                    'group': group,
                    'node_name': node_name,
                    'name': name,
                    'ip': ip,
                    'registerIP': request.query.get('registerIP', None)
                },
                'q': q
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query.get(field, None)

    dapi = DistributedAPI(f=agent.upgrade_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies'],
                          broadcasting=agents_list == '*'
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_upgrade_custom_agents(request, agents_list: str = None, pretty: bool = False,
                                    wait_for_complete: bool = False, file_path: str = None, installer: str = None,
                                    q: str = None, manager: str = None, version: str = None, group: str = None,
                                    node_name: str = None, name: str = None, ip: str = None) -> web.Response:
    """Upgrade agents using a local WPK file.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agent IDs. All possible values from 000 onwards.
    file_path : str
        Path to the WPK file. The file must be on a folder on the Wazuh's installation directory (by default, <code>/var/ossec</code>).
    installer : str
        Installation file.
    q : str
        Query to filter agents by.
    manager : str
        Filter by manager hostname to which agents are connected.
    version : str
        Filter by agents version.
    group : str
        Filter by group of agents.
    node_name : str
        Filter by node name.
    name : str
        Filter by agent name.
    ip : str
        Filter by agent IP.

    Returns
    -------
    web.Response
        Upgrade message after trying to upgrade the agents.
    """
    # If we use the 'all' keyword and the request is distributed_master, agents_list must be '*'
    if 'all' in agents_list:
        agents_list = '*'

    f_kwargs = {'agent_list': agents_list,
                'file_path': file_path,
                'installer': installer,
                'filters': {
                    'manager': manager,
                    'version': version,
                    'group': group,
                    'node_name': node_name,
                    'name': name,
                    'ip': ip,
                    'registerIP': request.query.get('registerIP', None)
                },
                'q': q
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query.get(field, None)

    dapi = DistributedAPI(f=agent.upgrade_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies'],
                          broadcasting=agents_list == '*'
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_upgrade(request, agents_list: str = None, pretty: bool = False, wait_for_complete: bool = False,
                            q: str = None, manager: str = None, version: str = None, group: str = None,
                            node_name: str = None, name: str = None, ip: str = None) -> web.Response:
    """Get upgrade results from agents.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agent IDs. All possible values from 000 onwards.
    q : str
        Query to filter agents by.
    manager : str
        Filter by manager hostname to which agents are connected.
    version : str
        Filter by agents version.
    group : str
        Filter by group of agents.
    node_name : str
        Filter by node name.
    name : str
        Filter by agent name.
    ip : str
        Filter by agent IP.

    Returns
    -------
    web.Response
        Upgrade message after having upgraded the agents.
    """
    f_kwargs = {'agent_list': agents_list,
                'filters': {
                    'manager': manager,
                    'version': version,
                    'group': group,
                    'node_name': node_name,
                    'name': name,
                    'ip': ip,
                    'registerIP': request.query.get('registerIP', None)
                },
                'q': q
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query.get(field, None)

    dapi = DistributedAPI(f=agent.get_upgrade_result,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_daemon_stats(request, agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                           daemons_list: list = None) -> web.Response:
    """Get Wazuh statistical information from the specified daemons of a specified agent.

    Parameters
    ----------
    request : connexion.request
    agent_id : str
        ID of the agent from which the statistics are obtained.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    daemons_list : list
        List of the daemons to get statistical information from.

    Returns
    -------
    web.Response
        API response.
    """
    daemons_list = daemons_list or []
    f_kwargs = {'agent_list': [agent_id],
                'daemons_list': daemons_list}

    dapi = DistributedAPI(f=stats.get_daemons_stats_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies'])
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_component_stats(request, pretty=False, wait_for_complete=False, agent_id=None, component=None):
    """Get a specified agent's component stats.

    Parameters
    ----------
    request : connexion.request
    agent_id : str
        ID of the agent from which the statistics are obtained.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    daemons_list : list
        List of the daemons to get statistical information from.

    Returns
    -------
    web.Response
        API response.
    """
    daemons_list = daemons_list or []
    f_kwargs = {'agent_list': [agent_id],
                'daemons_list': daemons_list}

    dapi = DistributedAPI(f=stats.get_daemons_stats_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies'])
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_component_stats(request, pretty: bool = False, wait_for_complete: bool = False, agent_id: str = None,
                              component: str = None) -> web.Response:
    """Get a specified agent's component stats.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID for which the specified component's stats are got. All possible values from 000 onwards.
    component : str
        Selected agent's component which stats are got.

    Returns
    -------
    web.Response
        API response with the module stats.
    """
    f_kwargs = {'agent_list': [agent_id],
                'component': component}

    dapi = DistributedAPI(f=stats.get_agents_component_stats_json,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def post_new_agent(request, agent_name: str, pretty: bool = False,
                         wait_for_complete: bool = False) -> web.Response:
    """Add agent (quick method).

    Parameters
    ----------
    request : connexion.request
    agent_name : str
        Name used to register the agent.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = await AgentAddedModel.get_kwargs({'name': agent_name})

    dapi = DistributedAPI(f=agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_multiple_agent_single_group(request, group_id: str, agents_list: str = None, pretty: bool = False,
                                             wait_for_complete: bool = False) -> web.Response:
    """Remove agents assignment from a specified group.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group ID.
    agents_list : str
        Array of agent's IDs.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    if 'all' in agents_list:
        agents_list = None
    f_kwargs = {'agent_list': agents_list,
                'group_list': [group_id]}

    dapi = DistributedAPI(f=agent.remove_agents_from_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_multiple_agent_single_group(request, group_id: str, agents_list: str = None, pretty: bool = False,
                                          wait_for_complete: bool = False,
                                          force_single_group: bool = False) -> web.Response:
    """Add multiple agents to a group.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group ID.
    agents_list : str
        List of agents IDs.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    force_single_group : bool
        Forces the agent to belong to only the specified group.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'group_list': [group_id],
                'replace': force_single_group}

    dapi = DistributedAPI(f=agent.assign_agents_to_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_groups(request, groups_list: str = None, pretty: bool = False,
                        wait_for_complete: bool = False) -> web.Response:
    """Delete all groups or a list of them.

    Parameters
    ----------
    request : connexion.request
    groups_list : str
        Array of group's IDs.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    if 'all' in groups_list:
        groups_list = None
    f_kwargs = {'group_list': groups_list}

    dapi = DistributedAPI(f=agent.delete_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_list_group(request, pretty: bool = False, wait_for_complete: bool = False,
                        groups_list: str = None, offset: int = 0, limit: int = None,
                        sort: str = None, search: str = None, q: str = None, select: str = None,
                        distinct: bool = False) -> web.Response:
    """Get groups.

    Returns a list containing basic information about each agent group such as number of agents belonging to the group
    and the checksums of the configuration and shared files.

    Parameters
    ----------
    request : connexion.request
    groups_list : str
        Array of group's IDs.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response
        API response.
    """
    hash_ = request.query.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
    f_kwargs = {'offset': offset,
                'limit': limit,
                'group_list': groups_list,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['name'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'hash_algorithm': hash_,
                'q': q,
                'select': select,
                'distinct': distinct}

    dapi = DistributedAPI(f=agent.get_agent_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agents_in_group(request, group_id: str, pretty: bool = False, wait_for_complete: bool = False,
                              offset: int = 0, limit: int = DATABASE_LIMIT, select: str = None, sort: str = None,
                              search: str = None, status: str = None, q: str = None,
                              distinct: bool = False) -> web.Response:
    """Get the list of agents that belongs to the specified group.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group ID.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: DATABASE_LIMIT
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    status : str
        Filters by agent status. Use commas to enter multiple statuses.
    q : str
        Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'group_list': [group_id],
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': select,
                'filters': {
                    'status': status,
                },
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=agent.get_agents_in_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def post_group(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Create a new group.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await GroupAddedModel.get_kwargs(request)

    dapi = DistributedAPI(f=agent.create_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_group_config(request, group_id: str, pretty: bool = False, wait_for_complete: bool = False,
                           offset: int = 0, limit: int = DATABASE_LIMIT) -> web.Response:
    """Get group configuration defined in the `agent.conf` file.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group ID.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: DATABASE_LIMIT

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'group_list': [group_id],
                'offset': offset,
                'limit': limit}

    dapi = DistributedAPI(f=agent.get_agent_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_group_config(request, body: dict, group_id: str, pretty: bool = False,
                           wait_for_complete: bool = False) -> web.Response:
    """Update group configuration.

    Update a specified group's configuration. This API call expects a full valid XML file with the shared configuration
    tags/syntax.

    Parameters
    ----------
    request : connexion.request
    body : dict
        Dictionary with the new group configuration.
        The body is obtained from the XML file and decoded in this function.
    group_id : str
        Group ID.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/xml')
    parsed_body = Body.decode_body(body, unicode_error=2006, attribute_error=2007)

    f_kwargs = {'group_list': [group_id],
                'file_data': parsed_body}

    dapi = DistributedAPI(f=agent.upload_group_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_group_files(request, group_id: str, pretty: bool = False, wait_for_complete: bool = False,
                          offset: int = 0, limit: int = None, sort: str = None, search: str = None, 
                          q: str = None, select: str = None, distinct: bool = False) -> web.Response:
    """Get the files placed under the group directory.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group ID.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response
        API response.
    """
    hash_ = request.query.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
    f_kwargs = {'group_list': [group_id],
                'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ["filename"],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'hash_algorithm': hash_,
                'q': q,
                'select': select,
                'distinct': distinct}

    dapi = DistributedAPI(f=agent.get_group_files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_group_file_json(request, group_id: str, file_name: str, pretty: bool = False,
                              wait_for_complete: bool = False) -> web.Response:
    """Get the files placed under the group directory in JSON format.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group ID.
    file_name : str
        Name of the file to be obtained.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'group_list': [group_id],
                'filename': file_name,
                'type_conf': request.query.get('type', None),
                'return_format': 'json'}

    dapi = DistributedAPI(f=agent.get_file_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_group_file_xml(request, group_id: str, file_name: str, pretty: bool = False,
                             wait_for_complete: bool = False) -> ConnexionResponse:
    """Get the files placed under the group directory in XML format.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group ID.
    file_name : str
        Name of the file to be obtained.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    connexion.lifecycle.ConnexionResponse
        API response.
    """
    f_kwargs = {'group_list': [group_id],
                'filename': file_name,
                'type_conf': request.query.get('type', None),
                'return_format': 'xml'}

    dapi = DistributedAPI(f=agent.get_file_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    response = ConnexionResponse(body=data["data"], mimetype='application/xml')

    return response


async def restart_agents_by_group(request, group_id: str, pretty: bool = False,
                                  wait_for_complete: bool = False) -> web.Response:
    """Restart all agents from a group.

    Parameters
    ----------
    request : connexion.request
    group_id : str
        Group name.
    pretty : bool, optional
        Show results in human-readable format. Default `False`
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'group_list': [group_id], 'select': ['id'], 'limit': None}
    dapi = DistributedAPI(f=agent.get_agents_in_group,
                          f_kwargs=f_kwargs,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    agents = raise_if_exc(await dapi.distribute_function())

    agent_list = [a['id'] for a in agents.affected_items]
    if not agent_list:
        data = AffectedItemsWazuhResult(none_msg='Restart command was not sent to any agent')
        return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)

    f_kwargs = {'agent_list': agent_list}
    dapi = DistributedAPI(f=agent.restart_agents_by_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def insert_agent(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Insert a new agent.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await AgentInsertedModel.get_kwargs(request)

    dapi = DistributedAPI(f=agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_no_group(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                             limit: int = DATABASE_LIMIT, select=None, sort=None, search=None, q=None) -> web.Response:
    """Get agents without group.

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: DATABASE_LIMIT
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    q : str
        Query to filter results by. For example "q&#x3D;&amp;quot;status&#x3D;active&amp;quot;".

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': 'id!=000;group=null' + (';' + q if q else '')}

    dapi = DistributedAPI(f=agent.get_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_outdated(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                             limit: int = DATABASE_LIMIT, sort: str = None, search: str = None,
                             q: str = None) -> web.Response:
    """Get outdated agents.

    Parameters
    ----------
    request : connexion.request
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: DATABASE_LIMIT
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    q : str
        Query to filter results by. For example "q&#x3D;&amp;quot;status&#x3D;active&amp;quot;".

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': q}

    dapi = DistributedAPI(f=agent.get_outdated_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_fields(request, pretty: bool = False, wait_for_complete: bool = False, fields: str = None,
                           offset: int = 0, limit: int = DATABASE_LIMIT, sort: str = None, search: str = None,
                           q: str = None) -> web.Response:
    """Get distinct fields in agents.

    Returns all the different combinations that agents have for the selected fields. It also indicates the total number
    of agents that have each combination.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    fields : str
        List of fields affecting the operation.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Looks for elements with the specified string.
    q : str
        Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'fields': fields,
                'q': q}

    dapi = DistributedAPI(f=agent.get_distinct_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_summary_status(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get agents status summary.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=agent.get_agents_summary_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_summary_os(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get agents OS summary.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=agent.get_agents_summary_os,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
