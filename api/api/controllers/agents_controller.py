# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from wazuh.agent import Agent
from wazuh.cluster.dapi.dapi import DistributedAPI
from api.util import remove_nones_to_dict, exception_handler, raise_if_exc, parse_api_param
from api.models.base_model_ import Data

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


def delete_agents(pretty=False, wait_for_complete=False, ids=None, purge=None, status=None, older_than=None):  # noqa: E501
    """Delete agents

    Removes agents, using a list of them or a criterion based on the status or time of the last connection. The Wazuh API must be restarted after removing an agent.  # noqa: E501

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param ids: Array of agent ID’s
    :type ids: List[str]
    :param purge: Delete an agent from the key store
    :type purge: bool
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :type status: List[str]
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’, ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never connected agents, uses the register date. 
    :type older_than: str

    :rtype: AgentDeletedData
    """

    f_kwargs = {'list_agent_ids': ids,
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
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200


def get_all_agents(pretty=False, wait_for_complete=False, offset=0, limit=None, select=None, sort=None, search=None,
                   status=None, q='', older_than=None, os_platform=None, os_version=None, os_name=None, manager=None,
                   version=None, group=None, node_name=None, name=None, ip=None):  # noqa: E501
    """Get all agents

    Returns a list with the available agents. # noqa: E501

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order. 
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by agent status. Use commas to enter multiple statuses.
    :type status: List[str]
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;Active&amp;quot;
    :type q: str
    :param older_than: Filters out disconnected agents for longer than specified. Time in seconds, ‘[n_days]d’, ‘[n_hours]h’, ‘[n_minutes]m’ or ‘[n_seconds]s’. For never connected agents, uses the register date. 
    :type older_than: str
    :param os_platform: Filters by OS platform.
    :type os_platform: str
    :param os_version: Filters by OS version.
    :type os_version: str
    :param os_name: Filters by OS name.
    :type os_name: str
    :param manager: Filters by manager hostname to which agents are connected.
    :type manager: str
    :param version: Filters by agents version.
    :type version: str
    :param group: Filters by group of agents.
    :type group: str
    :param node_name: Filters by node name.
    :type node_name: str
    :param name: Filters by agent name.
    :type name: str
    :param ip: Filters by agent IP
    :type ip: str

    :rtype: AllAgents
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort': sort,
                'search': search,
                'select': select,
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
                    'ip': ip
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
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200


@exception_handler
def restart_all_agents(pretty=True, wait_for_complete=False):  # noqa: E501
    """Restarts all agents

     # noqa: E501

    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool

    :rtype: AgentRestarted
    """

    dapi = DistributedAPI(f=Agent.restart_agents,
                          f_kwargs={'restart_all': True},
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200


def add_agent():
    pass


def delete_agent():
    pass


def get_agent(agent_id, pretty=False, wait_for_complete=False, select=None):  # noqa: E501
    """Get an agent

    Returns various information from an agent.'  # noqa: E501

    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :type agent_id: str
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]

    :rtype: AgentData
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
    data = loop.run_until_complete(dapi.distribute_function())

    return data, 200


def get_agent_config(agent_id, component, configuration, pretty=False, wait_for_complete=False):  # noqa: E501
    """Get active configuration

    Returns the active configuration the agent is currently using. This can be different from the 
    configuration present in the configuration file, if it has been modified and the agent has 
    not been restarted yet.  # noqa: E501

    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param agent_id: Agent ID. All posible values since 000 onwards.
    :type agent_id: str
    :param component: Selected agent's component.
    :type component: str
    :param configuration: Selected agent's configuration to read.
    :type configuration: str

    :rtype: AgentConfigurationData
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


def delete_agent_group():
    pass


def get_sync_agent():
    pass


def delete_agent_single_group():
    pass


def put_agent_single_group():
    pass


def get_agent_key():
    pass


def put_restart_agent():
    pass


def put_upgrade_agent():
    pass


def put_upgrade_custom_agent():
    pass


def put_new_agent():
    pass


def get_agent_upgrade():
    pass


def delete_multiple_agent_group():
    pass


def post_multiple_agent_group():
    pass


def delete_list_group():
    pass


def get_list_group():
    pass


def delete_group():
    pass


def get_agent_in_group():
    pass


def put_group():
    pass


def get_group_config():
    pass


def post_group_config():
    pass


def get_group_files():
    pass


def get_group_file():
    pass


def post_group_file():
    pass


def insert_agent():
    pass


def get_agent_by_name():
    pass


def get_agent_no_group():
    pass


def get_agent_outdated():
    pass


def restart_list_agents():
    pass


def get_agent_fields():
    pass


def get_agent_summary():
    pass


def get_agent_summary_os():
    pass
