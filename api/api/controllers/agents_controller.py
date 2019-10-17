# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

import connexion

import wazuh.agent as agent
from api import configuration
from api.authentication import get_permissions
from api.models.agent_added import AgentAdded
from api.models.agent_inserted import AgentInserted
from api.models.base_model_ import Data
from api.util import parse_api_param
from api.util import remove_nones_to_dict, exception_handler, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.common import database_limit
from wazuh.exception import WazuhError

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def delete_agents(pretty=False, wait_for_complete=False, list_agents=None, purge=False, status='all', older_than="7d"):
    """Delete all agents or a list of them with optional criteria based on the status or time of the last connection.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_agents: List of agent's IDs.
    :param purge: Delete an agent from the key store
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’,
    ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never_connected agents, uses the register date.
    :return: AllItemsResponseAgentIDs
    """
    f_kwargs = {'agent_list': list_agents,
                'purge': purge,
                'status': status,
                'older_than': older_than
                }

    dapi = DistributedAPI(f=agent.delete_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agents(pretty=False, wait_for_complete=False, list_agents=None, offset=0, limit=database_limit, select=None,
               sort=None, search=None, status=None, q=None, older_than=None, manager=None, version=None, group=None,
               node_name=None, name=None, ip=None):
    """Get information about all agents or a list of them

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_agents: List of agent's IDs.
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
    f_kwargs = {'agent_list': list_agents,
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
                    'registerIP': connexion.request.args.get('registerIP', None)
                },
                'q': q
                }
    # Add nested fields to kwargs filters
    nested = ['os.version', 'os.name', 'os.platform']
    for field in nested:
        f_kwargs['filters'][field] = connexion.request.args.get(field, None)

    dapi = DistributedAPI(f=agent.get_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def add_agent(pretty=False, wait_for_complete=False):
    """Add a new Wazuh agent.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: AgentIdKey
    """
    # Get body parameters
    if connexion.request.is_json:
        agent_added_model = AgentAdded.from_dict(connexion.request.get_json())
    else:
        raise WazuhError(1750)

    f_kwargs = agent_added_model.to_dict()

    # Get IP if not given
    if not f_kwargs['ip']:
        if configuration.read_api_config()['behind_proxy_server']:
            try:
                f_kwargs['ip'] = connexion.request.headers['X-Forwarded-For']
            except Exception:
                raise WazuhError(1120)
        else:
            f_kwargs['ip'] = connexion.request.remote_addr

    dapi = DistributedAPI(f=agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def restart_agents(pretty=False, wait_for_complete=False, list_agents='*'):
    """ Restarts all agents

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_agents: List of agent's IDs.
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': list_agents}

    dapi = DistributedAPI(f=agent.restart_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization']),
                          broadcasting=list_agents == '*',
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_agent(agent_id, pretty=False, wait_for_complete=False, purge=False):
    """Delete an agent

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param purge: Delete an agent from the key store
    :return: Data
    """
    f_kwargs = {'agent_list': [agent_id],
                'purge': purge,
                'older_than': "0s"
                }

    dapi = DistributedAPI(f=agent.delete_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agent(agent_id, pretty=False, wait_for_complete=False, select=None):
    """Get various information from an agent

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.r
    :param select: Select which fields to return (separated by comma)
    :return: Agent
    """
    f_kwargs = {'agent_list': [agent_id],
                'select': select
                }

    dapi = DistributedAPI(f=agent.get_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agent_config(pretty=False, wait_for_complete=False, agent_id=None, component=None, **kwargs):
    """Get active configuration

    Returns the active configuration the agent is currently using. This can be different from the
    configuration present in the configuration file, if it has been modified and the agent has
    not been restarted yet.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param component: Selected agent's component.
    :return: AgentConfigurationData
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
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def delete_single_agent_multiple_groups(agent_id, list_groups=None, pretty=False, wait_for_complete=False):
    """'Remove the agent from all groups or a list of them.

    The agent will automatically revert to the "default" group if it is removed from all its assigned groups.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param list_groups: Array of group's IDs.
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': [agent_id],
                'group_list': list_groups}

    dapi = DistributedAPI(f=agent.remove_agent_from_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_sync_agent(agent_id, pretty=False, wait_for_complete=False):
    """Get agent configuration sync status.

    Returns whether the agent configuration has been synchronized with the agent
    or not. This can be useful to check after updating a group configuration.

    :param agent_id: Agent ID. All posible values since 000 onwards.
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
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_single_agent_single_group(agent_id, group_id, pretty=False, wait_for_complete=False):
    """Remove agent from a single group.

    Removes an agent from a group. If the agent has multigroups, it will preserve all previous groups except the last
    one.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param group_id: Group ID.
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': [agent_id],
                'group_list': [group_id]}

    dapi = DistributedAPI(f=agent.remove_agent_from_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_agent_single_group(agent_id, group_id, force_single_group=False, pretty=False, wait_for_complete=False):
    """Assign an agent to the specified group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param group_id: Group ID.
    :param force_single_group: Forces the agent to belong to a single group
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': [agent_id],
                'group_id': group_id,
                'replace': force_single_group}

    dapi = DistributedAPI(f=agent.assign_agents_to_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agent_key(agent_id, pretty=False, wait_for_complete=False):
    """Get agent key.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :return: AgentKey
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=agent.get_agents_keys,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def restart_agent(agent_id, pretty=False, wait_for_complete=False):
    """Restart an agent.

    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': [agent_id]}

    dapi = DistributedAPI(f=agent.restart_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_upgrade_agent(agent_id, pretty=False, wait_for_complete=False, wpk_repo=None, version=None, use_http=False,
                      force=False):
    """Upgrade agent using a WPK file from online repository.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param wpk_repo: WPK repository.
    :param version: Wazuh version to upgrade to.
    :param use_http: Use protocol http. If it's false use https. By default the value is set to false.
    :param force: Force upgrade.
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': [agent_id],
                'wpk_repo': wpk_repo,
                'version': version,
                'use_http': use_http,
                'force': force}

    dapi = DistributedAPI(f=agent.upgrade_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=True,  # Force wait_for_complete until timeout problems are resolved
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_upgrade_custom_agent(agent_id, pretty=False, wait_for_complete=False, file_path=None, installer=None):
    """Upgrade agent using a local WPK file.'.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param file_path: Path to the WPK file. The file must be on a folder on the Wazuh's installation directory
    (by default, <code>/var/ossec</code>).
    :type installer: str
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': [agent_id],
                'file_path': file_path,
                'installer': installer}

    dapi = DistributedAPI(f=agent.upgrade_agents_custom,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=True,  # Force wait_for_complete until timeout problems are resolved
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def post_new_agent(agent_name, pretty=False, wait_for_complete=False):
    """Add agent (quick method)

    Adds a new agent with name `agent_name`. This agent will use `any` as IP.'

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_name: Agent name used when the agent was registered.
    :return: AgentIdKeyData
    """
    f_kwargs = {'name': agent_name}

    dapi = DistributedAPI(f=agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_upgrade(agent_id, timeout=3, pretty=False, wait_for_complete=False):
    """Get upgrade result from agent.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param timeout: Seconds to wait for the agent to respond.
    :return: CommonResponse
    """
    f_kwargs = {'agent_list': [agent_id],
                'timeout': timeout}

    dapi = DistributedAPI(f=agent.get_upgrade_result,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_multiple_agent_single_group(group_id, list_agents=None, pretty=False, wait_for_complete=False):
    """Removes agents assignment from a specified group.

    :param group_id: Group ID.
    :param list_agents: Array of agent's IDs.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: AllItemsResponseAgentIDs
    """
    f_kwargs = {'agent_list': list_agents,
                'group_list': [group_id]}

    dapi = DistributedAPI(f=agent.remove_agents_from_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_multiple_agent_single_group(group_id, list_agents=None, pretty=False, wait_for_complete=False,
                                    force_single_group=False):
    """Add multiple agents to a group

    :param group_id: Group ID.
    :param list_agents: List of agents ID.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param force_single_group: Forces the agent to belong to a single group
    :return: AllItemsResponseAgentIDs
    """
    f_kwargs = {'agent_list': list_agents,
                'group_list': [group_id],
                'replace': force_single_group}

    dapi = DistributedAPI(f=agent.assign_agents_to_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_groups(list_groups=None, pretty=False, wait_for_complete=False):
    """Delete all groups or a list of them.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_groups: Array of group's IDs.
    :return: AllItemsResponseGroupIDs + AgentGroupDeleted
    """
    f_kwargs = {'group_list': list_groups}

    dapi = DistributedAPI(f=agent.delete_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_list_group(pretty=False, wait_for_complete=False, list_groups=None, offset=0, limit=None, sort=None, search=None):
    """Get groups.

    Returns a list containing basic information about each agent group such as number of agents belonging to the group
    and the checksums of the configuration and shared files.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_groups: Array of group's IDs.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return: AllItemsResponseGroups
    """
    hash_ = connexion.request.args.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
    f_kwargs = {'offset': offset,
                'limit': limit,
                'group_list': list_groups,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['name'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'search_in_fields': ['name'],
                'hash_algorithm': hash_}

    dapi = DistributedAPI(f=agent.get_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_single_group(group_id, pretty=False, wait_for_complete=False):
    """Deletes a group. Agents that were assigned only to the deleted group will automatically revert to the default group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: AgentGroupDeleted
    """
    f_kwargs = {'group_list': [group_id]}

    dapi = DistributedAPI(f=agent.delete_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agents_in_group(group_id, pretty=False, wait_for_complete=False, offset=0, limit=database_limit, select=None,
                        sort=None, search=None, status=None, q=None):
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
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': select,
                'filters': {
                    'status': status,
                },
                'q': 'group=' + group_id + (';' + q if q else '')}

    dapi = DistributedAPI(f=agent.get_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def post_group(group_id, pretty=False, wait_for_complete=False):
    """Create a new group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: ApiResponse
    """
    f_kwargs = {'group_id': group_id}

    dapi = DistributedAPI(f=agent.create_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_group_config(group_id, pretty=False, wait_for_complete=False):
    """Get group configuration defined in the `agent.conf` file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: GroupConfiguration
    """
    f_kwargs = {'group_list': [group_id]}
    dapi = DistributedAPI(f=agent.get_agent_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def put_group_config(body, group_id, pretty=False, wait_for_complete=False):
    """Update group configuration.

    Update an specified group's configuration. This API call expects a full valid XML file with the shared configuration
    tags/syntax.

    :param body: Body parameters
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: CommonResponse
    """
    # Parse body to utf-8
    try:
        body = body.decode('utf-8')
    except UnicodeDecodeError:
        return 'Error parsing body request to UTF-8', 400
    except AttributeError:
        return 'Body is empty', 400

    f_kwargs = {'group_list': [group_id],
                'file_data': body}

    dapi = DistributedAPI(f=agent.upload_group_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_group_files(group_id, pretty=False, wait_for_complete=False, offset=0, limit=database_limit, sort=None,
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
    :return: Data
    """
    hash_ = connexion.request.args.get('hash', 'md5')  # Select algorithm to generate the returned checksums.
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
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_group_file_json(group_id, file_name, pretty=False, wait_for_complete=False):
    """Get the files placed under the group directory in json format.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param file_name: Filename
    :return: Data
    """
    f_kwargs = {'group_list': [group_id],
                'filename': file_name,
                'type_conf': connexion.request.args.get('type', None),
                'return_format': 'json'}

    dapi = DistributedAPI(f=agent.get_file_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_group_file_xml(group_id, file_name, pretty=False, wait_for_complete=False):
    """Get the files placed under the group directory in xml format.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param file_name: Filename
    :return: Data
    """
    f_kwargs = {'group_list': [group_id],
                'filename': file_name,
                'type_conf': connexion.request.args.get('type', None),
                'return_format': 'xml'}

    dapi = DistributedAPI(f=agent.get_file_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = connexion.lifecycle.ConnexionResponse(body=data["message"], mimetype='application/xml')

    return response


@exception_handler
def insert_agent(pretty=False, wait_for_complete=False):
    """ Insert a new agent

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: Data
    """
    # Get body parameters
    if connexion.request.is_json:
        agent_inserted_model = AgentInserted.from_dict(connexion.request.get_json())
    else:
        raise WazuhError(1750)

    f_kwargs = agent_inserted_model.to_dict()

    # Get IP if not given
    if not f_kwargs['ip']:
        if configuration.read_api_config()['behind_proxy_server']:
            try:
                f_kwargs['ip'] = connexion.request.headers['X-Forwarded-For']
            except Exception:
                raise WazuhError(1120)
        else:
            f_kwargs['ip'] = connexion.request.remote_addr

    dapi = DistributedAPI(f=agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_by_name(agent_name, pretty=False, wait_for_complete=False, select=None):
    """Get various information from an agent using its name

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_name: Agent name used when the agent was registered.
    :param select: Select which fields to return (separated by comma)
    :return: Data
    """
    f_kwargs = {'filters': {'name': agent_name},
                'select': select}

    dapi = DistributedAPI(f=agent.get_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agent_no_group(pretty=False, wait_for_complete=False, offset=0, limit=database_limit, select=None, sort=None,
                       search=None, q=None):
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
    :return: Data
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
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agent_outdated(pretty=False, wait_for_complete=False, offset=None, limit=None, sort=None, search=None, q=None):
    """Get outdated agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :return: Data
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
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_fields(pretty=False, wait_for_complete=False, offset=0, limit=database_limit, select=None, sort=None,
                     search=None, fields=None, q=None):
    """Get distinct fields in agents.

    Returns all the different combinations that agents have for the selected fields. It also indicates the total number
    of agents that have each combination.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param fields: List of fields affecting the operation.
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :return: Data
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
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_summary_status(pretty=False, wait_for_complete=False):
    """Get agents status summary.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: Data
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=agent.get_agents_summary_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_summary_os(pretty=False, wait_for_complete=False, offset=None, limit=None, search=None, q=None):
    """Get agents OS summary.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :return: Data
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'search': parse_api_param(search, 'search'),
                'q': q}

    dapi = DistributedAPI(f=agent.get_agents_summary_os,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=get_permissions(connexion.request.headers['Authorization'])
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200
