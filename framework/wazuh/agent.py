# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os import chmod, chown, path
from typing import Optional, Union

from server_management_api.models.agent_enrollment_model import Host
from wazuh.core import common, configuration
from wazuh.core.agent import (
    Agent,
    get_agents_info,
    get_groups,
)
from wazuh.core.cluster.cluster import get_node
from wazuh.core.exception import WazuhError, WazuhException, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.agent import DEFAULT_GROUP
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.commands import create_restart_command, create_set_group_command
from wazuh.core.indexer.models.agent import Host as IndexerAgentHost
from wazuh.core.indexer.models.commands import ResponseResult
from wazuh.core.InputValidator import InputValidator
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.core.utils import get_group_file_path, get_hash, process_array
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.rbac.decorators import expose_resources

node_id = get_node().get('node')


def build_agents_query(agent_list: list, filters: dict) -> dict:
    """Build the query to filter agents.

    Parameters
    ----------
    agent_list : list
        List of agents ID's.
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}.

    Returns
    -------
    dict
        The query with the given parameters.
    """
    # TODO: The query build should be improved in https://github.com/wazuh/wazuh/issues/25289

    last_login_key = 'last_login'

    query_filters = []
    if agent_list:
        query_filters.append({IndexerKey.TERMS: {IndexerKey._ID: agent_list}})

    if last_login_key in filters and filters[last_login_key] is not None:
        query_filters.append(
            {IndexerKey.RANGE: {last_login_key: {IndexerKey.LTE: f'{IndexerKey.NOW}-{filters[last_login_key]}'}}}
        )
        filters.pop(last_login_key)

    for key, value in filters.items():
        if value is not None:
            query_filters.append({IndexerKey.TERM: {key: value}})

    return {IndexerKey.QUERY: {IndexerKey.BOOL: {IndexerKey.FILTER: query_filters}}}


@expose_resources(
    actions=['agent:reconnect'], resources=['agent:id:{agent_list}'], post_proc_kwargs={'exclude_codes': [1701, 1707]}
)
def reconnect_agents(agent_list: Union[list, str] = None) -> AffectedItemsWazuhResult:
    """Force reconnect a list of agents.

    Parameters
    ----------
    agent_list : list or str
        List of agent IDs. All possible values from 001 onwards. Default `*`

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(
        all_msg='Force reconnect command was sent to all agents',
        some_msg='Force reconnect command was not sent to some agents',
        none_msg='Force reconnect command was not sent to any agent',
    )

    system_agents = get_agents_info()
    with WazuhQueue(common.AR_SOCKET) as wq:
        for agent_id in agent_list:
            try:
                if agent_id not in system_agents:
                    raise WazuhResourceNotFound(1701)
                Agent(agent_id).reconnect(wq)
                result.affected_items.append(agent_id)
            except WazuhException as e:
                result.add_failed_item(id_=agent_id, error=e)

    result.total_affected_items = len(result.affected_items)
    result.affected_items.sort(key=int)

    return result


@expose_resources(
    actions=['agent:restart'],
    resources=['agent:id:{agent_list}'],
    post_proc_kwargs={'exclude_codes': [1701, 1703, 1707]},
)
async def restart_agents(agent_list: list) -> AffectedItemsWazuhResult:
    """Restart a list of agents.

    Parameters
    ----------
    agent_list : list
        List of agents IDs.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(
        all_msg='Restart command was sent to all agents',
        some_msg='Restart command was not sent to some agents',
        none_msg='Restart command was not sent to any agent',
    )

    async with get_indexer_client() as indexer_client:
        query = {IndexerKey.MATCH_ALL: {}}
        agents = await indexer_client.agents.search(query={IndexerKey.QUERY: query}, select='agent.id')

        available_agents = [agent.id for agent in agents]

        if len(agent_list) == 0:
            # Send the restart command to all available agents
            agent_list = available_agents
        else:
            for not_found_id in set(agent_list) - set(available_agents):
                result.add_failed_item(not_found_id, error=WazuhResourceNotFound(1701))
                agent_list.remove(not_found_id)

        if len(agent_list) > 0:
            commands = []
            for agent_id in agent_list:
                command = create_restart_command(agent_id=agent_id)
                commands.append(command)

            response = await indexer_client.commands_manager.create(commands)
            if response.result in (ResponseResult.OK, ResponseResult.CREATED):
                result.affected_items.extend(agent_list)
            else:
                for agent_id in agent_list:
                    result.add_failed_item(id_=agent_id, error=WazuhError(1762, extra_message=response.result.value))

    result.total_affected_items = len(agent_list)

    return result


@expose_resources(
    actions=['agent:read'], resources=['agent:id:{agent_list}'], post_proc_kwargs={'exclude_codes': [1701]}
)
async def get_agents(
    agent_list: list,
    filters: Optional[dict] = None,
    offset: int = 0,
    limit: int = common.DATABASE_LIMIT,
    sort: dict = None,
    select: dict = None,
) -> AffectedItemsWazuhResult:
    """Get a list of available agents with basic attributes.

    Parameters
    ----------
    agent_list : list
        List of agent UUIDs to filter.
    filters : dict
        Defines required field filters. Format: {"field1": "value1", "field2": ["value2", "value3"]}.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: common.DATABASE_LIMIT
    select : dict
        Select fields to return. Format: {"fields": ["field1", "field2"]}.
    sort : dict
        Sorts the items. Format: {"fields": ["field1","field2"], "order": "asc|desc"}.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(
        all_msg='All selected agents information was returned',
        some_msg='Some agents information was not returned',
        none_msg='No agent information was returned',
    )

    query = build_agents_query(agent_list, filters)

    async with get_indexer_client() as indexer:
        items = await indexer.agents.search(query, select=select, exclude='key', limit=limit, offset=offset, sort=sort)

    result.affected_items.extend(items)
    result.total_affected_items = len(items)

    return result


@expose_resources(actions=['group:read'], resources=['group:id:{group_list}'], post_proc_func=None)
async def get_agents_in_group(
    group_list: list,
    offset: int = 0,
    limit: int = None,
    sort_by: list = None,
    sort_ascending: bool = True,
    search_text: str = None,
    complementary_search: bool = False,
    q: str = None,
    select: str = None,
    distinct: bool = False,
) -> AffectedItemsWazuhResult:
    """Get the list of agents that belong to a specific group.

    Parameters
    ----------
    group_list : list
        List containing the group ID.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: common.DATABASE_LIMIT
    sort_by : list
        Fields to sort the items by.
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order. Default: True
    search_text : str
        Text to search.
    complementary_search : bool
        Find items without the text to search. Default: False
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Raises
    ------
    WazuhResourceNotFound(1710)
        If the group does not exist.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(
        all_msg='All selected groups information was returned',
        some_msg='Some groups information was not returned',
        none_msg='No group information was returned',
    )

    group_id = group_list[0]
    system_groups = get_groups()

    if group_id not in system_groups:
        raise WazuhResourceNotFound(1710)

    async with get_indexer_client() as indexer_client:
        agents = await indexer_client.agents.get_group_agents(group_id)

    data = process_array(
        agents,
        offset=offset,
        limit=limit,
        sort_by=sort_by,
        sort_ascending=sort_ascending,
        search_text=search_text,
        complementary_search=complementary_search,
        q=q,
        select=select,
        distinct=distinct,
        allowed_select_fields=Agent.new_fields,
        allowed_sort_fields=Agent.new_fields,
    )

    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(
    actions=['agent:delete'],
    resources=['agent:id:{agent_list}'],
    post_proc_kwargs={'exclude_codes': [1701, 1703, 1731]},
)
async def delete_agents(
    agent_list: list,
    filters: Optional[dict] = None,
) -> AffectedItemsWazuhResult:
    """Delete a list of agents or all of them if receive an empty list.

    Parameters
    ----------
    agent_list : list
        List of agents ID's to be deleted.
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}.

    Returns
    -------
    AffectedItemsWazuhResult
        Result with affected agents.
    """
    result = AffectedItemsWazuhResult(
        all_msg='All selected agents were deleted',
        some_msg='Some agents were not deleted',
        none_msg='No agents were deleted',
    )

    async with get_indexer_client() as indexer:
        available_agents = [
            item.id for item in await indexer.agents.search(query=build_agents_query(agent_list, filters))
        ]
        not_found_agents = set(agent_list) - set(available_agents)

        for not_found_id in not_found_agents:
            result.add_failed_item(not_found_id, error=WazuhResourceNotFound(1701))

        agent_list = available_agents

        deleted_items = await indexer.agents.delete(agent_list)

    result.affected_items = deleted_items
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['agent:create'], resources=['*:*:*'], post_proc_func=None)
async def add_agent(
    id: str,
    name: str,
    key: str,
    type: str,
    version: str,
    host: Host = None,
) -> WazuhResult:
    """Add a new Wazuh agent.

    Parameters
    ----------
    id : str
        Agent ID.
    name : str
        Agent name.
    key : str
        Agent key.
    type : str
        Agent type.
    version : str
        Agent version.
    host : Host
        Agent host information.

    Raises
    ------
    WazuhError(1738)
        Name length is greater than 128 characters.

    Returns
    -------
    WazuhResult
        Added agent information.
    """
    # Check length of agent name
    if len(name) > common.AGENT_NAME_LEN_LIMIT:
        raise WazuhError(1738)

    async with get_indexer_client() as indexer_client:
        new_agent = await indexer_client.agents.create(
            id=id,
            name=name,
            key=key,
            type=type,
            version=version,
            host=IndexerAgentHost(
                architecture=host['architecture'],
                ip=host['ip'],
                hostname=host['hostname'],
                os=host['os'],
            )
            if host
            else None,
        )

    return WazuhResult({'data': new_agent})


@expose_resources(
    actions=['group:read'], resources=['group:id:{group_list}'], post_proc_kwargs={'exclude_codes': [1710]}
)
async def get_agent_groups(
    group_list: list = None,
    offset: int = 0,
    limit: int = None,
    sort_by: list = None,
    sort_ascending: bool = True,
    search_text: str = None,
    complementary_search: bool = False,
    hash_algorithm: str = 'md5',
    q: str = None,
    select: str = None,
    distinct: bool = False,
) -> AffectedItemsWazuhResult:
    """Get the existing groups.

    Parameters
    ----------
    group_list : list
        List of group names.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return. Default: common.DATABASE_LIMIT
    sort_by : list
        Fields to sort the items by.
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order. Default: True
    search_text : str
        Text to search.
    complementary_search : bool
        Find items without the text to search. Default: False
    hash_algorithm : str
        hash algorithm used to get mergedsum and configsum. Default: 'md5'
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    affected_groups = list()
    result = AffectedItemsWazuhResult(
        all_msg='All selected groups information was returned',
        some_msg='Some groups information was not returned',
        none_msg='No group information was returned',
    )

    if group_list:
        system_groups = get_groups()

        # Add failed items
        for invalid_group in set(group_list) - system_groups:
            group_list.remove(invalid_group)
            result.add_failed_item(id_=invalid_group, error=WazuhResourceNotFound(1710))

        for name in group_list:
            group = {'name': name}

            conf_sum = get_hash(get_group_file_path(name), hash_algorithm)
            if conf_sum:
                group['configSum'] = conf_sum

            affected_groups.append(group)

        data = process_array(
            affected_groups,
            offset=offset,
            limit=limit,
            sort_by=sort_by,
            sort_ascending=sort_ascending,
            search_text=search_text,
            complementary_search=complementary_search,
            q=q,
            select=select,
            distinct=distinct,
        )
        result.affected_items = data['items']
        result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['group:create'], resources=['*:*:*'], post_proc_func=None)
async def create_group(group_id: str) -> WazuhResult:
    """Create a group.

    Parameters
    ----------
    group_id : str
        Group ID.

    Raises
    ------
    WazuhError(1722)
        If there was a validation error.
    WazuhError(1711)
        If the group already exists.
    WazuhError(1713)
        If the group ID is not valid.
    WazuhInternalError(1005)
        If there was an error reading a file.

    Returns
    -------
    WazuhResult
        WazuhResult object with a operation message.
    """
    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhError(1722)

    if group_id.lower() == 'agent-template':
        raise WazuhError(1713, extra_message=group_id)

    group_path = get_group_file_path(group_id)

    if group_id.lower() == 'default' or path.exists(group_path):
        raise WazuhError(1711, extra_message=group_id)

    # Create group in /etc/wazuh-server/groups
    try:
        with open(group_path, 'w') as f:
            # TODO(#25121): Write group configuration template
            f.write('# Group configuration')

        chown(group_path, common.wazuh_uid(), common.wazuh_gid())
        chmod(group_path, 0o660)
        msg = f"Group '{group_id}' created."
    except Exception as e:
        raise WazuhInternalError(1005, extra_message=str(e))

    return WazuhResult({'message': msg})


@expose_resources(
    actions=['group:delete'], resources=['group:id:{group_list}'], post_proc_kwargs={'exclude_codes': [1710, 1712]}
)
async def delete_groups(group_list: list = None) -> AffectedItemsWazuhResult:
    """Delete a list of groups and remove it from every agent assignations.

    Parameters
    ----------
    group_list : list
        List of Group names.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(
        all_msg='All selected groups were deleted',
        some_msg='Some groups were not deleted',
        none_msg='No group was deleted',
    )

    system_groups = get_groups()
    for group_id in group_list:
        try:
            # Check if group exists
            if group_id not in system_groups:
                raise WazuhResourceNotFound(1710)
            elif group_id == DEFAULT_GROUP:
                raise WazuhError(1712)

            async with get_indexer_client() as indexer_client:
                # Get the list of agents belonging to the group to send them the set-group command
                agents = await indexer_client.agents.get_group_agents(group_name=group_id)

                if len(agents) > 0:
                    commands = []
                    for agent in agents:
                        agent.groups.remove(group_id)
                        command = create_set_group_command(agent_id=agent.id, groups=agent.groups)
                        commands.append(command)

                    response = await indexer_client.commands_manager.create(commands)
                    if response.result not in (ResponseResult.OK, ResponseResult.CREATED):
                        raise WazuhError(1762, extra_message=response.result.value)

                await indexer_client.agents.delete_group(group_name=group_id)

            await Agent.delete_single_group(group_id)
            result.affected_items.append(group_id)
        except WazuhException as e:
            result.add_failed_item(id_=group_id, error=e)

    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['group:modify_assignments'], resources=['group:id:{replace_list}'], post_proc_func=None)
@expose_resources(actions=['group:modify_assignments'], resources=['group:id:{group_list}'], post_proc_func=None)
@expose_resources(
    actions=['agent:modify_group'],
    resources=['agent:id:{agent_list}'],
    post_proc_kwargs={'exclude_codes': [1701, 1751, 1752]},
)
async def assign_agents_to_group(
    group_list: list = None, agent_list: list = None, replace: bool = False, replace_list: list = None
) -> AffectedItemsWazuhResult:
    """Assign a list of agents to a group.

    Parameters
    ----------
    group_list : list
        List with the group ID.
    agent_list : list
        List of Agent IDs.
    replace :  bool
        Whether to append new group to current agent's group or replace it.
    replace_list : list
        List of Group names that can be replaced.

    Raises
    ------
    WazuhResourceNotFound(1710)
        If the group was not found.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    group_id = group_list[0]
    result = AffectedItemsWazuhResult(
        all_msg=f'All selected agents were assigned to {group_id}'
        f'{" and removed from the other groups" if replace else ""}',
        some_msg=f'Some agents were not assigned to {group_id}'
        f'{" and removed from the other groups" if replace else ""}',
        none_msg='No agents were assigned to {0}'.format(group_id),
    )
    # Check if the group exists
    if not Agent.group_exists(group_id):
        raise WazuhResourceNotFound(1710)

    if len(agent_list) == 0:
        query = {IndexerKey.MATCH_ALL: {}}
    else:
        query = {IndexerKey.TERMS: {IndexerKey._ID: agent_list}}

    async with get_indexer_client() as indexer_client:
        available_agents = await indexer_client.agents.search(
            query={IndexerKey.QUERY: query},
            select='agent.id,agent.groups',
        )

        # Check for nonexistent agents
        for not_found_id in set(agent_list) - set([agent.id for agent in available_agents]):
            result.add_failed_item(not_found_id, error=WazuhResourceNotFound(1701))
            agent_list.remove(not_found_id)

        commands = []
        for agent in available_agents:
            # Check if the agent already belongs to the group
            if agent.groups is not None and group_id in agent.groups:
                result.add_failed_item(id_=agent.id, error=WazuhError(1766))
                continue

            await indexer_client.agents.add_agents_to_group(group_name=group_id, agent_ids=agent_list, override=replace)

            if agent.groups is None:
                agent.groups = [group_id]
            else:
                agent.groups.append(group_id)

            command = create_set_group_command(agent_id=agent.id, groups=agent.groups)
            commands.append(command)

        if len(commands) > 0:
            response = await indexer_client.commands_manager.create(commands)
            if response.result in (ResponseResult.OK, ResponseResult.CREATED):
                result.affected_items.extend(agent_list)
            else:
                for agent_id in agent_list:
                    result.add_failed_item(id_=agent_id, error=WazuhError(1762, extra_message=response.result.value))

    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['group:modify_assignments'], resources=['group:id:{group_list}'], post_proc_func=None)
@expose_resources(
    actions=['agent:modify_group'],
    resources=['agent:id:{agent_list}'],
    post_proc_kwargs={'exclude_codes': [1701, 1734]},
)
async def remove_agents_from_group(agent_list: list = None, group_list: list = None) -> AffectedItemsWazuhResult:
    """Remove the assignations of a list of agents with a specified group.

    Parameters
    ----------
    group_list : list
        List with the group ID.
    agent_list : list
        List of Agent IDs.

    Raises
    ------
    WazuhResourceNotFound(1710)
        Group was not found.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    group_id = group_list[0]
    result = AffectedItemsWazuhResult(
        all_msg=f'All selected agents were removed from group {group_id}',
        some_msg=f'Some agents were not removed from group {group_id}',
        none_msg=f'No agent was removed from group {group_id}',
    )

    system_groups = get_groups()
    if group_id not in system_groups:
        raise WazuhResourceNotFound(1710)

    if len(agent_list) == 0:
        query = {IndexerKey.MATCH_ALL: {}}
    else:
        query = {IndexerKey.TERMS: {IndexerKey._ID: agent_list}}

    async with get_indexer_client() as indexer_client:
        agents = await indexer_client.agents.search(query={IndexerKey.QUERY: query}, select='agent.id,agent.groups')

        for not_found_id in set(agent_list) - set([agent.id for agent in agents]):
            result.add_failed_item(not_found_id, error=WazuhResourceNotFound(1701))
            agent_list.remove(not_found_id)

        if len(agent_list) > 0:
            await indexer_client.agents.remove_agents_from_group(group_name=group_id, agent_ids=agent_list)

            commands = []
            for agent in agents:
                if agent.groups is None or group_id not in agent.groups:
                    result.add_failed_item(agent.id, error=WazuhError(1734))
                    continue

                agent.groups.remove(group_id)
                command = create_set_group_command(agent_id=agent.id, groups=agent.groups)
                commands.append(command)

            if len(commands) > 0:
                response = await indexer_client.commands_manager.create(commands)
                if response.result in (ResponseResult.OK, ResponseResult.CREATED):
                    result.affected_items.extend(agent_list)
                else:
                    for agent_id in agent_list:
                        result.add_failed_item(
                            id_=agent_id, error=WazuhError(1762, extra_message=response.result.value)
                        )

    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=['group:read'], resources=['group:id:{group_list}'], post_proc_func=None)
async def get_group_conf(group_list: list = None) -> WazuhResult:
    """Read the configuration of the specified group.

    Parameters
    ----------
    group_list : list
        List with the group ID.

    Returns
    -------
    WazuhResult
        WazuhResult object with the configuration.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to get agent conf for
    # a list of groups
    group_id = group_list[0]

    return WazuhResult({'data': configuration.get_group_conf(group_id=group_id)})


@expose_resources(actions=['group:update_config'], resources=['group:id:{group_list}'], post_proc_func=None)
async def update_group_file(group_list: list = None, file_data: str = None) -> WazuhResult:
    """Update a group file.

    Parameters
    ----------
    group_list : list
        List with the group ID.
    file_data : str
        Relative path of temporary file to upload.

    Returns
    -------
    WazuhResult
        WazuhResult object with the confirmation message.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to update files for
    # a list of groups
    group_id = group_list[0]

    return WazuhResult({'message': configuration.update_group_file(group_id, file_data)})
