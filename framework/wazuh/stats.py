# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib
import datetime

from wazuh.core import common
from wazuh.core import exception
from wazuh.core.agent import Agent, get_agents_info, get_rbac_filters, WazuhDBQueryAgents
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhException, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.stats import get_daemons_stats_, get_daemons_stats_socket, hourly_, totals_, weekly_
from wazuh.rbac.decorators import expose_resources

cluster_enabled = not read_cluster_config(from_import=True)['disabled']
node_id = get_node().get('node') if cluster_enabled else None


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def totals(date: datetime.date) -> AffectedItemsWazuhResult:
    """Retrieve statistical information for the current or specified date.

    Parameters
    ----------
    date : datetime.date
        Date object with the date value of the stats.

    Returns
    -------
    AffectedItemsWazuhResult
        Array of dictionaries. Each dictionary represents an hour.
    """
    result = AffectedItemsWazuhResult(all_msg='Statistical information for each node was successfully read',
                                      some_msg='Could not read statistical information for some nodes',
                                      none_msg='Could not read statistical information for any node'
                                      )
    affected = totals_(date)
    result.affected_items = affected
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def hourly() -> AffectedItemsWazuhResult:
    """Compute hourly averages.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary with averages and interactions.
    """
    result = AffectedItemsWazuhResult(all_msg='Statistical information per hour for each node was successfully read',
                                      some_msg='Could not read statistical information per hour for some nodes',
                                      none_msg='Could not read statistical information per hour for any node'
                                      )
    result.affected_items = hourly_()
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def weekly() -> AffectedItemsWazuhResult:
    """Compute weekly averages.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary for each week day.
    """
    result = AffectedItemsWazuhResult(all_msg='Statistical information per week for each node was successfully read',
                                      some_msg='Could not read statistical information per week for some nodes',
                                      none_msg='Could not read statistical information per week for any node'
                                      )
    result.affected_items = weekly_()
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701, 1703, 1707]})
def get_daemons_stats_agents(daemons_list: list = None, agent_list: list = None):
    """Get agents statistical information from the specified daemons.
    If the daemons list is empty, the stats from all daemons will be retrieved.
    If the `all` keyword is included in the agents list, the stats from all the agents will be retrieved.

    Parameters
    ----------
    daemons_list : list
        List of the daemons to get statistical information from.
    agent_list : list
        List of agents ID's.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary with daemon's statistical information of the specified agents.
    """
    agent_list = agent_list or ["all"]
    daemon_socket_mapping = {'wazuh-remoted': common.REMOTED_SOCKET,
                             'wazuh-analysisd': common.ANALYSISD_SOCKET}
    result = AffectedItemsWazuhResult(all_msg='Statistical information for each daemon was successfully read',
                                      some_msg='Could not read statistical information for some daemons',
                                      none_msg='Could not read statistical information for any daemon',
                                      sort_casting=['str'])

    if agent_list:
        if 'all' not in agent_list:
            system_agents = get_agents_info()
            rbac_filters = get_rbac_filters(system_resources=system_agents, permitted_resources=agent_list)

            with WazuhDBQueryAgents(limit=None, select=["id", "status"], **rbac_filters) as db_query:
                data = db_query.run()

            agent_list = set(agent_list)

            with contextlib.suppress(KeyError):
                agent_list.remove('000')
                result.add_failed_item('000', exception.WazuhError(1703))

            # Add non-existent agents to failed_items
            not_found_agents = agent_list - system_agents
            [result.add_failed_item(id_=agent, error=exception.WazuhResourceNotFound(1701)) for agent in
             not_found_agents]

            # Add non-active agents to failed_items
            non_active_agents = [agent['id'] for agent in data['items'] if agent['status'] != 'active']
            [result.add_failed_item(id_=agent, error=exception.WazuhError(1707)) for agent in non_active_agents]
            non_active_agents = set(non_active_agents)

            eligible_agents = agent_list - not_found_agents - non_active_agents

            # Transform the format of the agent ids to the general format
            eligible_agents = [int(agent) for agent in eligible_agents]

            # To avoid the socket error 'Error 11 - Too many agents', we must use chunks of less than 75 agents
            agents_chunks = [eligible_agents[x:x + 74] for x in range(0, len(eligible_agents), 74)]

            for daemon in daemons_list or daemon_socket_mapping.keys():
                daemon_results = []
                for chunk in agents_chunks:
                    try:
                        for partial_daemon_result in daemon_results:
                            if partial_daemon_result['name'] == daemon:
                                partial_daemon_result['agents'].extend(
                                    get_daemons_stats_socket(daemon_socket_mapping[daemon],
                                                             agents_list=chunk)['agents'])
                                break
                        else:
                            daemon_results.append(
                                get_daemons_stats_socket(daemon_socket_mapping[daemon], agents_list=chunk))
                    except exception.WazuhException as e:
                        result.add_failed_item(id_=daemon, error=e)
                result.affected_items.extend(daemon_results)

            # Sort list of affected agents
            for affected_item in result.affected_items:
                affected_item['agents'].sort(key=lambda d: d['id'])

        else:  # 'all' in agent_list
            for daemon in daemons_list or daemon_socket_mapping.keys():
                daemon_results = []
                try:
                    last_id = 0
                    while True:
                        stats = get_daemons_stats_socket(daemon_socket_mapping[daemon], agents_list='all',
                                                         last_id=last_id)
                        for partial_daemon_result in daemon_results:
                            if partial_daemon_result['name'] == daemon:
                                partial_daemon_result['agents'].extend(stats['data']['agents'])
                                break
                        else:
                            daemon_results.append(stats['data'])

                        if len(stats['data']['agents']) > 0:
                            last_id = stats['data']['agents'][-1]['id']
                        if stats['message'] != 'due':
                            break

                except exception.WazuhException as e:
                    result.add_failed_item(id_=daemon, error=e)
                result.affected_items.extend(daemon_results)
            # The affected agents are sorted, no need to sort here

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_daemons_stats(daemons_list: list = None) -> AffectedItemsWazuhResult:
    """Get statistical information from the specified daemons.
    If the list is empty, the stats from all daemons will be retrieved.

    Parameters
    ----------
    daemons_list : list
        List of the daemons to get statistical information from.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary with the stats of the input file.
    """
    daemon_socket_mapping = {'wazuh-remoted': common.REMOTED_SOCKET,
                             'wazuh-analysisd': common.ANALYSISD_SOCKET,
                             'wazuh-db': common.WDB_SOCKET,
                             'wazuh-modulesd': common.WMODULES_SOCKET}
    result = AffectedItemsWazuhResult(all_msg='Statistical information for each daemon was successfully read',
                                      some_msg='Could not read statistical information for some daemons',
                                      none_msg='Could not read statistical information for any daemon')

    for daemon in daemons_list or daemon_socket_mapping.keys():
        try:
            result.affected_items.append(get_daemons_stats_socket(daemon_socket_mapping[daemon]))
        except WazuhException as e:
            result.add_failed_item(id_=daemon, error=e)

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def deprecated_get_daemons_stats(filename):
    """Get daemons stats from an input file.

    Parameters
    ----------
    filename: str
        Full path of the file to get information.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary with the stats of the input file.
    """
    result = AffectedItemsWazuhResult(
        all_msg='Statistical information for each node was successfully read',
        some_msg='Could not read statistical information for some nodes',
        none_msg='Could not read statistical information for any node'
    )
    result.affected_items = get_daemons_stats_(filename)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_agents_component_stats_json(agent_list: list = None, component: str = None) -> AffectedItemsWazuhResult:
    """Get statistics of an agent's component.

    Parameters
    ----------
    agent_list: list, optional
        List of agents ID's, by default None.
    component: str, optional
        Name of the component to get stats from, by default None.

    Returns
    -------
    AffectedItemsWazuhResult
        Component stats.
    """
    result = AffectedItemsWazuhResult(all_msg='Statistical information for each agent was successfully read',
                                      some_msg='Could not read statistical information for some agents',
                                      none_msg='Could not read statistical information for any agent')
    system_agents = get_agents_info()
    for agent_id in agent_list:
        try:
            if agent_id not in system_agents:
                raise exception.WazuhResourceNotFound(1701)
            result.affected_items.append(Agent(agent_id).get_stats(component=component))
        except exception.WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result
