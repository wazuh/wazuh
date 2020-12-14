# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web
from connexion.lifecycle import ConnexionResponse

import wazuh.agent as agent
from api import configuration
from api.encoder import dumps, prettify
from api.models.agent_added_model import AgentAddedModel
from api.models.agent_inserted_model import AgentInsertedModel
from api.models.base_model_ import Body
from api.models.group_added_model import GroupAddedModel
from api.util import parse_api_param, remove_nones_to_dict, raise_if_exc
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.common import database_limit
from wazuh.core.exception import WazuhError

logger = logging.getLogger('wazuh-api')


async def delete_agents(request, pretty=False, wait_for_complete=False, agents_list=None, purge=False, status=None,
                        older_than="7d"):
    """Delete all agents or a list of them with optional criteria based on the status or time of the last connection.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param purge: Delete an agent from the key store
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’,
    ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never_connected agents, uses the register date.
    :return: AllItemsResponseAgentIDs
    """
    if 'all' in agents_list:
        agents_list = None
    f_kwargs = {'agent_list': agents_list,
                'purge': purge,
                'status': status,
                'older_than': older_than,
                'use_only_authd': configuration.api_conf['use_only_authd']
                }
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


async def get_agents(request, pretty=False, wait_for_complete=False, agents_list=None, offset=0, limit=database_limit,
                     select=None, sort=None, search=None, status=None, q=None, older_than=None,
                     manager=None, version=None, group=None, node_name=None, name=None, ip=None):
    """Get information about all agents or a list of them

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’,
    ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never_connected agents, uses the register date.
    :param manager: Filters by manager hostname to which agents are connected.
    :param version: Filters by agents version.
    :param group: Filters by group of agents.
    :param node_name: Filters by node name.
    :param name: Filters by agent name.
    :param ip: Filters by agent IP
    :return: AllItemsResponseAgents
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
                    'registerIP': request.query.get('registerIP', None)
                },
                'q': q
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


async def add_agent(request, pretty=False, wait_for_complete=False):
    """Add a new Wazuh agent.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: AgentIdKey
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await AgentAddedModel.get_kwargs(request)

    f_kwargs['use_only_authd'] = configuration.api_conf['use_only_authd']

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


async def restart_agents(request, pretty=False, wait_for_complete=False, agents_list='*'):
    """ Restarts all agents

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agents_list: List of agent's IDs.
    :return: AllItemsResponseAgentIDs
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


async def restart_agents_by_node(request, node_id, pretty=False, wait_for_complete=False):
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
    Response
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


async def get_agent_config(request, pretty=False, wait_for_complete=False, agent_id=None, component=None, **kwargs):
    """Get active configuration

    Returns the active configuration the agent is currently using. This can be different from the
    configuration present in the configuration file, if it has been modified and the agent has
    not been restarted yet.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All possible values from 000 onwards.
    :param component: Selected agent's component.
    :return: AgentConfiguration
    """
    f_kwargs = {'agent_list': [agent_id],
                'component': component,
                'config': kwargs.get('configuration', None)
                }

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


async def delete_single_agent_multiple_groups(request, agent_id, groups_list=None, pretty=False,
                                              wait_for_complete=False):
    """'Remove the agent from all groups or a list of them.

    The agent will automatically revert to the "default" group if it is removed from all its assigned groups.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param groups_list: Array of group's IDs.
    :return: AllItemsResponseGroupIDs
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


async def get_sync_agent(request, agent_id, pretty=False, wait_for_complete=False):
    """Get agent configuration sync status.

    Returns whether the agent configuration has been synchronized with the agent
    or not. This can be useful to check after updating a group configuration.

    :param agent_id: Agent ID. All possible values from 000 onwards.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout responseç
    :return: AgentSync
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


async def delete_single_agent_single_group(request, agent_id, group_id, pretty=False, wait_for_complete=False):
    """Remove agent from a single group.

    Removes an agent from a group. If the agent has multigroups, it will preserve all previous groups except the last
    one.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All possible values from 000 onwards.
    :param group_id: Group ID.
    :return: ApiResponse
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


async def put_agent_single_group(request, agent_id, group_id, force_single_group=False, pretty=False,
                                 wait_for_complete=False):
    """Assign an agent to the specified group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All possible values from 000 onwards.
    :param group_id: Group ID.
    :param force_single_group: Forces the agent to belong to a single group
    :return: ApiResponse
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


async def get_agent_key(request, agent_id, pretty=False, wait_for_complete=False):
    """Get agent key.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All possible values from 000 onwards.
    :return: AllItemsResponseAgentsKeys
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


async def restart_agent(request, agent_id, pretty=False, wait_for_complete=False):
    """Restart an agent.

    :param agent_id: Agent ID. All possible values from 000 onwards.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: AllItemsResponseAgentIDs
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


async def put_upgrade_agents(request, agents_list=None, pretty=False, wait_for_complete=False, wpk_repo=None,
                             version=None, use_http=False, force=False):
    """Upgrade agents using a WPK file from online repository.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agent IDs. All possible values from 000 onwards.
    wpk_repo : str
        WPK repository.
    version : str
        Wazuh version to upgrade to.
    use_http : bool
        Use protocol http. If it's false use https. By default the value is set to false.
    force : bool
        Force upgrade.

    Returns
    -------
    ApiResponse
        Upgrade message after trying to upgrade the agents.
    """
    f_kwargs = {'agent_list': agents_list,
                'wpk_repo': wpk_repo,
                'version': version,
                'use_http': use_http,
                'force': force}

    dapi = DistributedAPI(f=agent.upgrade_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_upgrade_custom_agents(request, agents_list=None, pretty=False, wait_for_complete=False,
                                    file_path=None, installer=None):
    """Upgrade agents using a local WPK file.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agent IDs. All possible values from 000 onwards.
    file_path : str
        Path to the WPK file. The file must be on a folder on the Wazuh's installation directory (by default, <code>/var/ossec</code>).
    installer : str
        Installation file.

    Returns
    -------
    ApiResponse
        Upgrade message after trying to upgrade the agents.
    """
    f_kwargs = {'agent_list': agents_list,
                'file_path': file_path,
                'installer': installer}

    dapi = DistributedAPI(f=agent.upgrade_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_agent_upgrade(request, agents_list=None, pretty=False, wait_for_complete=False):
    """Get upgrade results from agents.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    agents_list : list
        List of agent IDs. All possible values from 000 onwards.

    Returns
    -------
    ApiResponse
        Upgrade message after having upgraded the agents.
    """
    f_kwargs = {'agent_list': agents_list}

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


async def post_new_agent(request, agent_name, pretty=False, wait_for_complete=False):
    """Add agent (quick method)

    Adds a new agent with name `agent_name`. This agent will use `any` as IP.'

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_name: Agent name used when the agent was registered.
    :return: AgentIdKeyData
    """
    f_kwargs = {'name': agent_name, 'use_only_authd': configuration.api_conf['use_only_authd']}

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


async def delete_multiple_agent_single_group(request, group_id, agents_list=None, pretty=False,
                                             wait_for_complete=False):
    """Removes agents assignment from a specified group.

    :param group_id: Group ID.
    :param agents_list: Array of agent's IDs.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: AllItemsResponseAgentIDs
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


async def put_multiple_agent_single_group(request, group_id, agents_list=None, pretty=False, wait_for_complete=False,
                                          force_single_group=False):
    """Add multiple agents to a group

    :param group_id: Group ID.
    :param agents_list: List of agents ID.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param force_single_group: Forces the agent to belong to a single group
    :return: AllItemsResponseAgentIDs
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


async def delete_groups(request, groups_list=None, pretty=False, wait_for_complete=False):
    """Delete all groups or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param groups_list: Array of group's IDs.
    :return: AllItemsResponseGroupIDs + AgentGroupDeleted
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


async def get_list_group(request, pretty=False, wait_for_complete=False, groups_list=None, offset=0, limit=None,
                         sort=None, search=None):
    """Get groups.

    Returns a list containing basic information about each agent group such as number of agents belonging to the group
    and the checksums of the configuration and shared files.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param groups_list: Array of group's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return: AllItemsResponseGroups
    """
    hash_ = request.query.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
    f_kwargs = {'offset': offset,
                'limit': limit,
                'group_list': groups_list,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'hash_algorithm': hash_}
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


async def get_agents_in_group(request, group_id, pretty=False, wait_for_complete=False, offset=0, limit=database_limit,
                              select=None, sort=None, search=None, status=None, q=None):
    """Get the list of agents that belongs to the specified group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :return: AllItemsResponseAgents
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
                'q': q}

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


async def post_group(request, pretty=False, wait_for_complete=False):
    """Create a new group.
    
    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ApiResponse
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


async def get_group_config(request, group_id, pretty=False, wait_for_complete=False, offset=0, limit=database_limit):
    """Get group configuration defined in the `agent.conf` file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :return: GroupConfiguration
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


async def put_group_config(request, body, group_id, pretty=False, wait_for_complete=False):
    """Update group configuration.

    Update an specified group's configuration. This API call expects a full valid XML file with the shared configuration
    tags/syntax.

    :param body: Body parameters
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: ApiResponse
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


async def get_group_files(request, group_id, pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                          search=None):
    """Get the files placed under the group directory

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return: GroupFile
    """
    hash_ = request.query.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
    f_kwargs = {'group_list': [group_id],
                'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ["filename"],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'hash_algorithm': hash_}

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


async def get_group_file_json(request, group_id, file_name, pretty=False, wait_for_complete=False):
    """Get the files placed under the group directory in json format.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param file_name: Filename
    :return: File data in JSON
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


async def get_group_file_xml(request, group_id, file_name, pretty=False, wait_for_complete=False):
    """Get the files placed under the group directory in xml format.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param file_name: Filename
    :return: File data in XML
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


async def restart_agents_by_group(request, group_id, pretty=False, wait_for_complete=False):
    """Restart all agents from a group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: AllItemsResponseAgents
    """
    f_kwargs = {'group_id': group_id}

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


async def insert_agent(request, pretty=False, wait_for_complete=False):
    """Insert a new agent

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: AgentIdKey
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await AgentInsertedModel.get_kwargs(request)

    # Get IP if not given
    if not f_kwargs['ip']:
        if configuration.api_conf['behind_proxy_server']:
            try:
                f_kwargs['ip'] = request.headers['X-Forwarded-For']
            except KeyError:
                raise_if_exc(WazuhError(1120))
        else:
            peername = request.transport.get_extra_info('peername')
            if peername is not None:
                f_kwargs['ip'], _ = peername
    f_kwargs['use_only_authd'] = configuration.api_conf['use_only_authd']

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


async def get_agent_no_group(request, pretty=False, wait_for_complete=False, offset=0, limit=database_limit,
                             select=None, sort=None, search=None, q=None):
    """Get agents without group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :return: AllItemsResponseAgents
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


async def get_agent_outdated(request, pretty=False, wait_for_complete=False, offset=0, limit=database_limit, sort=None,
                             search=None, q=None):
    """Get outdated agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :return: AllItemsResponseAgentsSimple
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


async def get_agent_fields(request, pretty=False, wait_for_complete=False, fields=None, offset=0, limit=database_limit,
                           select=None, sort=None, search=None, q=None):
    """Get distinct fields in agents.

    Returns all the different combinations that agents have for the selected fields. It also indicates the total number
    of agents that have each combination.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param fields: List of fields affecting the operation.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :return: ListMetadata
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
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


async def get_agent_summary_status(request, pretty=False, wait_for_complete=False):
    """Get agents status summary.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response

    Returns
    -------
    AgentsSummaryStatus
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


async def get_agent_summary_os(request, pretty=False, wait_for_complete=False):
    """Get agents OS summary.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response

    Returns
    -------
    ListMetadata
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
