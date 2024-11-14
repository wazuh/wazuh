# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Union

from connexion import request
from connexion.lifecycle import ConnexionResponse
from wazuh import agent, stats
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.common import DATABASE_LIMIT

from api.controllers.util import JSON_CONTENT_TYPE, json_response
from api.models.agent_registration_model import AgentRegistrationModel
from api.models.agent_group_added_model import GroupAddedModel
from api.models.base_model_ import Body
from api.util import parse_api_param, raise_if_exc, remove_nones_to_dict
from api.validator import check_component_configuration_pair

logger = logging.getLogger('wazuh-api')


async def delete_agents(
    pretty: bool = False,
    wait_for_complete: bool = False,
    agents_list: list = None,
    name: str = None,
    group: str = None,
    type: str = None,
    version: str = None,
    older_than: str = None,
    is_connected: bool = None,
) -> ConnexionResponse:
    """Delete all agents or a list of them based on optional criteria.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agents IDs. If the 'all' keyword is indicated, all the agents are deleted.
    name : str
        Filter by name.
    group : str
        Filter by group.
    type : str
        Filter by type.
    version : str
        Filter by version.
    older_than : str
        Filter out disconnected agents for longer than specified. Time in seconds, '[n_days]d',
        '[n_hours]h', '[n_minutes]m' or '[n_seconds]s'. For never_connected agents, use the register date.
    is_connected : bool
        Filter by connection status.

    Returns
    -------
    ConnexionResponse
        Agents which have been deleted.
    """
    if 'all' in agents_list:
        agents_list = []

    f_kwargs = {
        'agent_list': agents_list,
        'filters': {
            'name': name,
            'groups': group,
            'type': type,
            'version': version,
            'last_login': older_than,
            'is_connected': is_connected,
            'host.ip': request.query_params.get('remote.ip', None),
            'host.os.full': request.query_params.get('os.full', None),
        },
    }

    dapi = DistributedAPI(
        f=agent.delete_agents,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_any',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )

    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agents(
    pretty: bool = False,
    wait_for_complete: bool = False,
    agents_list: list = None,
    name: str = None,
    group: str = None,
    type: str = None,
    version: str = None,
    older_than: str = None,
    offset: int = 0,
    limit: int = DATABASE_LIMIT,
    select: str = None,
    sort: str = None,
    is_connected: bool = None,
) -> ConnexionResponse:
    """Get information about all agents or a list of them.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agents IDs.
    name : str
        Filter by agent name.
    group : str
        Filter by agent group.
    type : str
        Filter by agents type.
    version : str
        Filter by agents version.
    older_than : str
        Filter out disconnected agents for longer than specified. Time in seconds, '[n_days]d',
        '[n_hours]h', '[n_minutes]m' or '[n_seconds]s'. For never_connected agents, use the register date.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: DATABASE_LIMIT
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    is_connected : bool
        Filter by connection status.

    Returns
    -------
    ConnexionResponse
        Response with all selected agents' information.
    """
    if older_than is not None and older_than.isnumeric():
        older_than = f'{older_than}s'

    f_kwargs = {
        'agent_list': agents_list if agents_list is not None else [],
        'filters': {
            'name': name,
            'groups': group,
            'type': type,
            'version': version,
            'last_login': older_than,
            'is_connected': is_connected,
            'host.ip': request.query_params.get('remote.ip', None),
            'host.os.full': request.query_params.get('os.full', None),
        },
        'offset': offset,
        'limit': limit,
        'select': select,
        'sort': sort,
    }

    dapi = DistributedAPI(
        f=agent.get_agents,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_any',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def add_agent(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Add a new Wazuh agent.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await AgentRegistrationModel.get_kwargs(request)

    dapi = DistributedAPI(
        f=agent.add_agent,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_any',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )

    raise_if_exc(await dapi.distribute_function())

    return ConnexionResponse(status_code=201)


async def reconnect_agents(pretty: bool = False, wait_for_complete: bool = False,
                           agents_list: Union[list, str] = '*') -> ConnexionResponse:
    """Force reconnect all agents or a list of them.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format. Default `False`
    wait_for_complete : bool
        Disable timeout response. Default `False`
    agents_list : list or str
        List of agent IDs. Default `*`

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(f=agent.reconnect_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          broadcasting=agents_list == '*',
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def restart_agents(
    pretty: bool = False, wait_for_complete: bool = False, agents_list: str = '*'
) -> ConnexionResponse:
    """Restart all agents or a list of them.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agents IDs. Default: `*`

    Returns
    -------
    ConnexionResponse
        API response.
    """
    if agents_list == '*':
        agents_list = []

    f_kwargs = {'agent_list': agents_list}

    dapi = DistributedAPI(
        f=agent.restart_agents,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_any',
        is_async=True,
        wait_for_complete=wait_for_complete,
        rbac_permissions=request.context['token_info']['rbac_policies'],
        logger=logger
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


# TODO(#25554): Review whether to keep this endpoint or not
async def restart_agents_by_node(node_id: str, pretty: bool = False,
                                 wait_for_complete: bool = False) -> ConnexionResponse:
    """Restart all agents belonging to a node.

    Parameters
    ----------
    node_id : str
        Cluster node ID.
    pretty : bool, optional
        Show results in human-readable format. Default `False`
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`

    Returns
    -------
    ConnexionResponse
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
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_config(pretty: bool = False, wait_for_complete: bool = False, agent_id: str = None,
                           component: str = None, **kwargs: dict) -> ConnexionResponse:
    """Get agent active configuration.

    Returns the active configuration the agent is currently using. This can be different from the configuration present
    in the configuration file, if it has been modified and the agent has not been restarted yet.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 001 onwards.
    component : str
        Selected agent's component which configuration is got.

    Returns
    -------
    ConnexionResponse
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
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_single_agent_multiple_groups(agent_id: str, groups_list: str = None, pretty: bool = False,
                                              wait_for_complete: bool = False) -> ConnexionResponse:
    """Remove the agent from all groups or a list of them.

    The agent will automatically revert to the "default" group if it is removed from all its assigned groups.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 001 onwards.
    groups_list : str
        Array of groups IDs to remove the agent from.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'agent_list': [agent_id],
                'group_list': groups_list}

    dapi = DistributedAPI(f=agent.remove_agent_from_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_key(agent_id: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get agent key.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID. All possible values from 001 onwards.

    Returns
    -------
    ConnexionResponse
        API response with the specified agent's key.
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=agent.get_agents_keys,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def restart_agent(agent_id: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Restart an agent.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent UUID.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # f_kwargs = {'agent_list': [agent_id]}

    # dapi = DistributedAPI(
    #     f=agent.restart_agents,
    #     f_kwargs=remove_nones_to_dict(f_kwargs),
    #     request_type='local_any',
    #     is_async=True,
    #     wait_for_complete=wait_for_complete,
    #     logger=logger,
    #     rbac_permissions=request.context['token_info']['rbac_policies']
    # )
    # data = raise_if_exc(await dapi.distribute_function())

    # return json_response(data, pretty=pretty)
    return json_response({'message': 'To be implemented'}, status_code=501)


async def put_upgrade_agents(agents_list: str = None, pretty: bool = False, wait_for_complete: bool = False,
                             wpk_repo: str = None, upgrade_version: str = None, use_http: bool = False,
                             force: bool = False, package_type: str = None, q: str = None, manager: str = None,
                             version: str = None, group: str = None, node_name: str = None, name: str = None,
                             ip: str = None) -> ConnexionResponse:
    """Upgrade agents using a WPK file from an online repository.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agent IDs. All possible values from 001 onwards.
    wpk_repo : str
        WPK repository.
    upgrade_version : str
        Wazuh version to upgrade to.
    use_http : bool
        Use protocol http. If it's false use https. By default the value is set to false.
    force : bool
        Force upgrade.
    package_type : str
        Default package type (rpm, deb).
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
    ConnexionResponse
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
                'package_type': package_type,
                'filters': {
                    'manager': manager,
                    'version': version,
                    'group': group,
                    'node_name': node_name,
                    'name': name,
                    'ip': ip,
                    'registerIP': request.query_params.get('registerIP', None)
                },
                'q': q
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query_params.get(field, None)

    dapi = DistributedAPI(f=agent.upgrade_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          broadcasting=agents_list == '*'
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_upgrade_custom_agents(agents_list: str = None, pretty: bool = False,
                                    wait_for_complete: bool = False, file_path: str = None, installer: str = None,
                                    q: str = None, manager: str = None, version: str = None, group: str = None,
                                    node_name: str = None, name: str = None, ip: str = None) -> ConnexionResponse:
    """Upgrade agents using a local WPK file.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agent IDs. All possible values from 001 onwards.
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
    ConnexionResponse
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
                    'registerIP': request.query_params.get('registerIP', None)
                },
                'q': q
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query_params.get(field, None)

    dapi = DistributedAPI(f=agent.upgrade_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          broadcasting=agents_list == '*'
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_upgrade(agents_list: str = None, pretty: bool = False, wait_for_complete: bool = False,
                            q: str = None, manager: str = None, version: str = None, group: str = None,
                            node_name: str = None, name: str = None, ip: str = None) -> ConnexionResponse:
    """Get upgrade results from agents.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : str
        List of agent IDs. All possible values from 001 onwards.
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
    ConnexionResponse
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
                    'registerIP': request.query_params.get('registerIP', None)
                },
                'q': q
                }

    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = request.query_params.get(field, None)

    dapi = DistributedAPI(f=agent.get_upgrade_result,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_daemon_stats(agent_id: str, pretty: bool = False, wait_for_complete: bool = False,
                           daemons_list: list = None) -> ConnexionResponse:
    """Get Wazuh statistical information from the specified daemons of a specified agent.

    Parameters
    ----------
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
    ConnexionResponse
        API response.
    """
    daemons_list = daemons_list or []
    f_kwargs = {'agent_list': [agent_id],
                'daemons_list': daemons_list}

    dapi = DistributedAPI(f=stats.get_daemons_stats_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'])
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_component_stats(pretty: bool = False, wait_for_complete: bool = False, agent_id: str = None,
                              component: str = None) -> ConnexionResponse:
    """Get a specified agent's component stats.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agent_id : str
        Agent ID for which the specified component's stats are obtained. Accepted values
        from 001 onwards.
    component : str
        Selected agent's component which stats are got.

    Returns
    -------
    ConnexionResponse
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
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_multiple_agent_single_group(group_id: str, agents_list: str = None, pretty: bool = False,
                                             wait_for_complete: bool = False) -> ConnexionResponse:
    """Remove agents assignment from a specified group.

    Parameters
    ----------
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
    ConnexionResponse
        API response.
    """
    if 'all' in agents_list:
        agents_list = None
    f_kwargs = {'agent_list': agents_list,
                'group_list': [group_id]}

    dapi = DistributedAPI(f=agent.remove_agents_from_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_multiple_agent_single_group(group_id: str, agents_list: str = None, pretty: bool = False,
                                          wait_for_complete: bool = False,
                                          force_single_group: bool = False) -> ConnexionResponse:
    """Add multiple agents to a group.

    Parameters
    ----------
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
    ConnexionResponse
        API response.
    """
    f_kwargs = {'agent_list': agents_list,
                'group_list': [group_id],
                'replace': force_single_group}

    dapi = DistributedAPI(f=agent.assign_agents_to_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_groups(groups_list: str = None, pretty: bool = False,
                        wait_for_complete: bool = False) -> ConnexionResponse:
    """Delete all groups or a list of them.

    Parameters
    ----------
    groups_list : str
        Array of group's IDs.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    if 'all' in groups_list:
        groups_list = None
    f_kwargs = {'group_list': groups_list}

    dapi = DistributedAPI(f=agent.delete_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_list_group(pretty: bool = False, wait_for_complete: bool = False,
                        groups_list: str = None, offset: int = 0, limit: int = None,
                        sort: str = None, search: str = None, q: str = None, select: str = None,
                        distinct: bool = False) -> ConnexionResponse:
    """Get groups.

    Returns a list containing basic information about each agent group such as number of agents belonging to the group
    and the checksums of the configuration and shared files.

    Parameters
    ----------
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
    ConnexionResponse
        API response.
    """
    hash_ = request.query_params.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
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
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agents_in_group(group_id: str, pretty: bool = False, wait_for_complete: bool = False,
                              offset: int = 0, limit: int = DATABASE_LIMIT, select: str = None, sort: str = None,
                              search: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get the list of agents that belongs to the specified group.

    Parameters
    ----------
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
    ConnexionResponse
        API response.
    """
    f_kwargs = {
        'group_list': [group_id],
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['name'],
        'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'q': q,
        'select': select,
        'distinct': distinct
    }

    dapi = DistributedAPI(f=agent.get_agents_in_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def post_group(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Create a new group.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await GroupAddedModel.get_kwargs(request)

    dapi = DistributedAPI(f=agent.create_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_group_config(group_id: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get group configuration defined in the `agent.conf` file.

    Parameters
    ----------
    group_id : str
        Group ID.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'group_list': [group_id]}

    dapi = DistributedAPI(f=agent.get_group_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_group_config(body: bytes, group_id: str, pretty: bool = False,
                           wait_for_complete: bool = False) -> ConnexionResponse:
    """Update group configuration.

    Update a specified group's configuration. This API call expects a full valid YAML file with the shared configuration
    syntax.

    Parameters
    ----------
    body : bytes
        Bytes object with the new group configuration.
        The body is obtained from the YAML file and decoded in this function.
    group_id : str
        Group ID.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/x-yaml')
    parsed_body = Body.decode_body(body, unicode_error=1911, attribute_error=1912)

    f_kwargs = {'group_list': [group_id],
                'file_data': parsed_body}

    dapi = DistributedAPI(f=agent.update_group_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_no_group(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                             limit: int = DATABASE_LIMIT, select=None, sort=None, search=None, q=None) -> ConnexionResponse:
    """Get agents without group.

    Parameters
    ----------
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
    ConnexionResponse
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': 'group=null' + (';' + q if q else '')}

    dapi = DistributedAPI(f=agent.get_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_outdated(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                             limit: int = DATABASE_LIMIT, sort: str = None, search: str = None,
                             select: str = None, q: str = None) -> ConnexionResponse:
    """Get outdated agents.

    Parameters
    ----------
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
    select : str
        Select which fields to return (separated by comma).
    q : str
        Query to filter results by. For example "q&#x3D;&amp;quot;status&#x3D;active&amp;quot;".

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': select,
                'q': q}

    dapi = DistributedAPI(f=agent.get_outdated_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_fields(pretty: bool = False, wait_for_complete: bool = False, fields: str = None,
                           offset: int = 0, limit: int = DATABASE_LIMIT, sort: str = None, search: str = None,
                           q: str = None) -> ConnexionResponse:
    """Get distinct fields in agents.

    Returns all the different combinations that agents have for the selected fields. It also indicates the total number
    of agents that have each combination.

    Parameters
    ----------
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
    ConnexionResponse
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
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_summary_status(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get agents status summary.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=agent.get_agents_summary_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agent_summary_os(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get agents OS summary.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=agent.get_agents_summary_os,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
