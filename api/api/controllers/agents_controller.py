# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

import connexion
from connexion.lifecycle import ConnexionResponse

import wazuh.configuration as config
from api import configuration
from api.models.agent_added import AgentAdded
from api.models.agent_inserted import AgentInserted
from api.models.agent_list_model import AgentList
from api.models.base_model_ import Data
from api.util import parse_api_param
from api.util import remove_nones_to_dict, exception_handler, raise_if_exc
from wazuh.agent import Agent
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def delete_agents(pretty=False, wait_for_complete=False, list_agents='all', purge=None, status='all', older_than=None):
    """Delete agents

    Deletes agents, using a list of them or a criterion based on the status or time of the last connection.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_agents: Array of agent ID’s]
    :param purge: Delete an agent from the key store
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’,
    ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never connected agents, uses the register date.
    :return: AgentAllItemsAffected
    """
    f_kwargs = {'list_agent': list_agents,
                'purge': purge,
                'status': status,
                'older_than': older_than
                }

    dapi = DistributedAPI(f=Agent.remove_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_all_agents(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                   status=None, q='', older_than=None, os_platform=None, os_version=None, os_name=None, manager=None,
                   version=None, group=None, node_name=None, name=None, ip=None, registerIP=None):
    """Get all agents

    Returns a list with the available agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’,
    ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never connected agents, uses the register date.
    :param os_platform: Filters by OS platform.
    :param os_version: Filters by OS version.
    :param os_name: Filters by OS name.
    :param manager: Filters by manager hostname to which agents are connected.
    :param version: Filters by agents version.
    :param group: Filters by group of agents.
    :param node_name: Filters by node name.
    :param name: Filters by agent name.
    :param ip: Filters by agent IP
    :param registerIP: Filters by agent register IP
    :return: AllAgents
    """

    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort.replace('os_', 'os.') if sort else sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': [x.replace('os_', 'os.') for x in select] if select else select,
                'filters': {
                    'status': status,
                    'older_than': older_than,
                    'os.platform': os_platform,
                    'os.version': os_version,
                    'os.name': os_name,
                    'manager': manager,
                    'version': version,
                    'group': group,
                    'node_name': node_name,
                    'name': name,
                    'ip': ip,
                    'registerIP': registerIP
                },
                'q': q
                }

    dapi = DistributedAPI(f=Agent.get_agents_overview,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def restart_all_agents(pretty=True, wait_for_complete=False):
    """Restarts all agents

    :param wait_for_complete: Disable timeout response
    :return: CommonResponse
    """

    dapi = DistributedAPI(f=Agent.restart_agents,
                          f_kwargs={'restart_all': True},
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def add_agent(pretty=False, wait_for_complete=False):
    """Add a new agent into the cluster.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param name: Agent name.
    :param ip: If this is not included, the API will get the IP automatically. If you are behind a proxy, you must set
    the option BehindProxyServer to yes at API configuration. Allowed values: IP, IP/NET, ANY
    :param force_time: Remove the old agent with the same IP if disconnected since <force_time> seconds.
    :return: AgentIdKeyData
    """
    # get body parameters
    if connexion.request.is_json:
        agent_added_model = AgentAdded.from_dict(connexion.request.get_json())
    else:
        raise WazuhError(1750)

    f_kwargs = {**{}, **agent_added_model.to_dict()}

    if not f_kwargs['ip']:
        if configuration.read_api_config()['behind_proxy_server']:
            try:
                f_kwargs['ip'] = connexion.request.headers['X-Forwarded-For']
            except Exception:
                raise WazuhError(1120)
        else:
            f_kwargs['ip'] = connexion.request.remote_addr

    dapi = DistributedAPI(f=Agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def delete_agent(agent_id, pretty=False, wait_for_complete=False, purge=False):
    """Delete an agent

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param purge: Delete an agent from the key store
    :return: AgentItemsAffected
    """
    f_kwargs = {'agent_id': agent_id,
                'purge': purge
                }

    dapi = DistributedAPI(f=Agent.remove_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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
    f_kwargs = {'agent_id': agent_id,
                'select': select
                }

    dapi = DistributedAPI(f=Agent.get_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_config(agent_id, component, configuration, pretty=False, wait_for_complete=False):
    """Get active configuration

    Returns the active configuration the agent is currently using. This can be different from the
    configuration present in the configuration file, if it has been modified and the agent has
    not been restarted yet.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param component: Selected agent's component.
    :param configuration: Selected agent's configuration to read.
    :return: AgentConfigurationData
    """
    f_kwargs = {'agent_id': agent_id,
                'component': component,
                'configuration': configuration
                }

    dapi = DistributedAPI(f=Agent.get_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def delete_agent_group(agent_id, pretty=False, wait_for_complete=False):
    """Removes agent from all groups.

    Removes the agent from all groups. The agent will automatically revert to the "default" group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :return: CommonResponse
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=Agent.unset_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_sync_agent(agent_id, pretty=False, wait_for_complete=False):
    """Get agent configuration sync status.

    Returns whether the agent configuration has been synchronized with the agent
    or not. This can be useful to check after updating a group configuration.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :return: AgentSync
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=Agent.get_sync_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def delete_agent_single_group(agent_id, group_id, pretty=False, wait_for_complete=False):
    """Remove agent from a single group.

    Removes an agent from a group. If the agent has multigroups, it will preserve all previous groups except the last
    one.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param group_id: Group ID.
    :return: CommonResponse
    """
    f_kwargs = {'agent_id': agent_id,
                'group_id': group_id}

    dapi = DistributedAPI(f=Agent.unset_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_agent_single_group(agent_id, group_id, force_single_group=False, pretty=False,
                           wait_for_complete=False):
    """Add an agent to the specified group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param group_id: Group ID.
    :param force_single_group: Forces the agent to belong to a single group
    :return: CommonResponse
    """
    f_kwargs = {'agent_id': agent_id,
                'group_id': group_id,
                'replace': force_single_group}

    dapi = DistributedAPI(f=Agent.set_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=Agent.get_agent_key,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def put_restart_agent(agent_id, pretty=False, wait_for_complete=False):
    """Restart an agent.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :return: CommonResponse
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=Agent.restart_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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
    :param version: Filters by agents version.
    :param use_http: Use protocol http. If it's false use https. By default the value is set to false.
    :param version: Force upgrade.
    :return: CommonResponse
    """
    f_kwargs = {'agent_id': agent_id,
                'wpk_repo': wpk_repo,
                'version': version,
                'use_http': use_http,
                'force': force}

    dapi = DistributedAPI(f=Agent.upgrade_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_upgrade_custom_agent(agent_id, pretty=False, wait_for_complete=False, file_path=None,
                             installer=None):
    """Upgrade agent using a local WPK file.'.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :param file_path: Path to the WPK file. The file must be on a folder on the Wazuh's installation directory
    (by default, <code>/var/ossec</code>).
    :type installer: str
    :return: CommonResponse
    """
    f_kwargs = {'agent_id': agent_id,
                'file_path': file_path,
                'installer': installer}

    dapi = DistributedAPI(f=Agent.upgrade_agent_custom,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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

    dapi = DistributedAPI(f=Agent.add_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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
    f_kwargs = {'agent_id': agent_id,
                'timeout': timeout}

    dapi = DistributedAPI(f=Agent.get_upgrade_result,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_multiple_agent_group(list_agents, group_id, pretty=False, wait_for_complete=False):
    """Remove multiple agents from a single group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_agents: Array of agent's IDs.
    :param group_id: Group ID.
    :return: AgentItemsAffected
    """
    f_kwargs = {'agent_id_list': list_agents,
                'group_id': group_id}

    dapi = DistributedAPI(f=Agent.unset_group_list,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def put_multiple_agent_group(group_id, pretty=False, wait_for_complete=False):
    """Add multiple agents to a group

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param agent_id_list: List of agents ID.
    :return: AgentItemsAffected
    """
    # get body parameters
    if connexion.request.is_json:
        agent_list_model = AgentList.from_dict(connexion.request.get_json())
    else:
        raise WazuhError(1750)

    agent_dict = agent_list_model.to_dict()
    agent_dict['agent_id_list'] = agent_dict.pop('ids')

    f_kwargs = {**{'group_id': group_id}, **agent_dict}

    dapi = DistributedAPI(f=Agent.set_group_list,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_list_group(list_groups, pretty=False, wait_for_complete=False):
    """Delete a list of groups.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param list_groups: Array of group's IDs.
    :return: AgentGroupDeleted
    """
    f_kwargs = {'group_id': list_groups}

    dapi = DistributedAPI(f=Agent.remove_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_list_group(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None):
    """Get all groups.

    Returns a list containing basic information about each agent group such as number of agents belonging to the group
    and the checksums of the configuration and shared files.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param hash: Select algorithm to generate the returned checksums.
    :return: Data
    """
    hash_ = connexion.request.args.get('hash', 'md5')
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'hash_algorithm': hash_}

    dapi = DistributedAPI(f=Agent.get_all_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def delete_group(group_id, pretty=False, wait_for_complete=False):
    """Delete group.

    Deletes a group. Agents that were assigned only to the deleted group will automatically revert to the default group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: AgentGroupDeleted
    """
    f_kwargs = {'group_id': group_id}

    dapi = DistributedAPI(f=Agent.remove_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agent_in_group(group_id, pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None,
                       search=None, status=None, q=''):
    """Get agents in a group.

    Returns the list of agents that belongs to the specified group.

    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param group_id: Group ID.
    :type group_id: str
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :type status: List[str]
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :type q: str

    :return:
    """
    f_kwargs = {'group_id': group_id,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort.replace('os_', 'os.') if sort else sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'select': [x.replace('os_', 'os.') for x in select] if select else select,
                'filters': {
                    'status': status,
                },
                'q': q}

    dapi = DistributedAPI(f=Agent.get_agent_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )

    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def post_group(group_id, pretty=False, wait_for_complete=False):
    """Create a new group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: message
    """
    f_kwargs = {'group_id': group_id}

    dapi = DistributedAPI(f=Agent.create_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_group_config(group_id, pretty=False, wait_for_complete=False, offset=0, limit=None):
    """Get group configuration defined in the `agent.conf` file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :return: Data
    """
    f_kwargs = {'group_id': group_id,
                'offset': offset,
                'limit': limit}

    dapi = DistributedAPI(f=config.get_agent_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def put_group_config(body, group_id, pretty=False, wait_for_complete=False):
    """Update group configuration.

    Update an specified group's configuration. This API call expects a full valid XML file with the shared configuration
    tags/syntax.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :return: CommonResponse
    """
    try:
        connexion.request.headers['Content-type']
    except KeyError:
        return 'Content-type header is mandatory', 400

    # parse body to utf-8
    try:
        body = body.decode('utf-8')
    except UnicodeDecodeError:
        return 'Error parsing body request to UTF-8', 400
    except AttributeError:
        return 'Body is empty', 400

    f_kwargs = {'group_id': group_id,
                'file_data': body}

    dapi = DistributedAPI(f=config.upload_group_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_group_files(group_id, pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None,
                    hash='md5'):
    """Get the files placed under the group directory

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param hash: Select algorithm to generate the returned checksums.
    :return: Data
    """
    f_kwargs = {'group_id': group_id,
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'hash_algorithm': hash}

    dapi = DistributedAPI(f=Agent.get_group_files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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
    :param type: Type of file.
    :return: Data
    """
    type_ = connexion.request.args.get('type')

    f_kwargs = {'group_id': group_id,
                'filename': file_name,
                'type_conf': type_,
                'return_format': 'json'}

    dapi = DistributedAPI(f=config.get_file_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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
    ::param file_name: Filename
    :param type_: Type of file.
    :return: Data
    """
    type_ = connexion.request.args.get('type_')

    f_kwargs = {'group_id': group_id,
                'filename': file_name,
                'type_conf': type_,
                'return_format': 'xml'}

    dapi = DistributedAPI(f=config.get_file_conf,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = ConnexionResponse(body=data["message"], mimetype='application/xml')

    return response


@exception_handler
def put_group_file(body, group_id, file_name, pretty=False, wait_for_complete=False):
    """Update group configuration.

    Update an specified group's configuration. This API call expects a full valid XML file with the shared configuration
    tags/syntax.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param group_id: Group ID.
    :param file_name: File name
    :return: CommonResponse
    """
    try:
        connexion.request.headers['Content-type']
    except KeyError:
        return 'Content-type header is mandatory', 400

    # Parse body to utf-8
    try:
        body = body.decode('utf-8')
    except UnicodeDecodeError:
        return 'Error parsing body request to UTF-8', 400
    except AttributeError:
        return 'Body is empty', 400

    f_kwargs = {'group_id': group_id,
                'file_name': file_name,
                'file_data': body}

    dapi = DistributedAPI(f=config.upload_group_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


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
    f_kwargs = {**{}, **agent_inserted_model.to_dict()}

    # Get IP if not given
    if not f_kwargs['ip']:
        if configuration.read_api_config()['behind_proxy_server']:
            try:
                f_kwargs['ip'] = connexion.request.headers['X-Forwarded-For']
            except Exception:
                raise WazuhError(1120)
        else:
            f_kwargs['ip'] = connexion.request.remote_addr

    dapi = DistributedAPI(f=Agent.insert_agent,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
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
    f_kwargs = {'agent_name': agent_name,
                'select': [x.replace('os_', 'os.') for x in select] if select else select}

    dapi = DistributedAPI(f=Agent.get_agent_by_name,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_no_group(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                       q=''):
    """Get agents without group.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: Select which fields to return (separated by comma)
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :return: Data
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': q}

    dapi = DistributedAPI(f=Agent.get_agents_without_group,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_outdated(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, q=''):
    """Get outdated agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :return: Data
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'q': q}

    dapi = DistributedAPI(f=Agent.get_outdated_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def restart_list_agents(pretty=False, wait_for_complete=False):
    """Restart a list of agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param ids: List of agents ID.
    :return: AgentItemsAffected
    """
    # get body parameters
    if connexion.request.is_json:
        agent_list_model = AgentList.from_dict(connexion.request.get_json())
    else:
        raise WazuhError(1750)
    agent_dict = agent_list_model.to_dict()
    agent_dict['agent_id'] = agent_dict.pop('ids')

    f_kwargs = {**{}, **agent_dict}

    dapi = DistributedAPI(f=Agent.restart_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_agent_fields(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                     fields=None, q=''):
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
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :return: Data
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': [x.replace('os_', 'os.') for x in select] if select else select,
                'sort': parse_api_param(sort.replace('os_', 'os.') if sort else sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'fields': fields,
                'q': q}

    dapi = DistributedAPI(f=Agent.get_distinct_agents,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_summary(pretty=False, wait_for_complete=False, ):
    """Get a summary of the available agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: Data
    """

    dapi = DistributedAPI(f=Agent.get_agents_summary,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_agent_summary_os(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None, q=''):
    """Get OS summary.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :return: Data
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'),
                'q': q}

    dapi = DistributedAPI(f=Agent.get_os_summary,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200
