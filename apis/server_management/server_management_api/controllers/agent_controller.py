# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Union

from connexion import request
from connexion.lifecycle import ConnexionResponse
from wazuh import agent
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.common import DATABASE_LIMIT

from server_management_api.controllers.util import JSON_CONTENT_TYPE, json_response
from server_management_api.models.agent_enrollment_model import AgentEnrollmentModel
from server_management_api.models.agent_group_added_model import GroupAddedModel
from server_management_api.models.base_model_ import Body
from server_management_api.util import parse_api_param, raise_if_exc, remove_nones_to_dict

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
        '[n_hours]h', '[n_minutes]m' or '[n_seconds]s'. For never_connected agents, use the enrollment date.
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
        rbac_permissions=request.context['token_info']['rbac_policies'],
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
        '[n_hours]h', '[n_minutes]m' or '[n_seconds]s'. For never_connected agents, use the enrollment date.
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
        rbac_permissions=request.context['token_info']['rbac_policies'],
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
    f_kwargs = await AgentEnrollmentModel.get_kwargs(request)

    dapi = DistributedAPI(
        f=agent.add_agent,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_any',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )

    raise_if_exc(await dapi.distribute_function())

    return ConnexionResponse(status_code=201)


async def reconnect_agents(
    pretty: bool = False, wait_for_complete: bool = False, agents_list: Union[list, str] = '*'
) -> ConnexionResponse:
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

    dapi = DistributedAPI(
        f=agent.reconnect_agents,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='distributed_master',
        is_async=False,
        wait_for_complete=wait_for_complete,
        rbac_permissions=request.context['token_info']['rbac_policies'],
        broadcasting=agents_list == '*',
        logger=logger,
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
        logger=logger,
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


async def delete_multiple_agent_single_group(
    group_id: str, agents_list: str = None, pretty: bool = False, wait_for_complete: bool = False
) -> ConnexionResponse:
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
    f_kwargs = {'agent_list': agents_list, 'group_list': [group_id]}

    dapi = DistributedAPI(
        f=agent.remove_agents_from_group,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_multiple_agent_single_group(
    group_id: str,
    agents_list: str = None,
    pretty: bool = False,
    wait_for_complete: bool = False,
    force_single_group: bool = False,
) -> ConnexionResponse:
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
    f_kwargs = {'agent_list': agents_list, 'group_list': [group_id], 'replace': force_single_group}

    dapi = DistributedAPI(
        f=agent.assign_agents_to_group,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_groups(
    groups_list: str = None, pretty: bool = False, wait_for_complete: bool = False
) -> ConnexionResponse:
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

    dapi = DistributedAPI(
        f=agent.delete_groups,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_list_group(
    pretty: bool = False,
    wait_for_complete: bool = False,
    groups_list: str = None,
    offset: int = 0,
    limit: int = None,
    sort: str = None,
    search: str = None,
    q: str = None,
    select: str = None,
    distinct: bool = False,
) -> ConnexionResponse:
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
    f_kwargs = {
        'offset': offset,
        'limit': limit,
        'group_list': groups_list,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['name'],
        'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'hash_algorithm': hash_,
        'q': q,
        'select': select,
        'distinct': distinct,
    }

    dapi = DistributedAPI(
        f=agent.get_agent_groups,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_agents_in_group(
    group_id: str,
    pretty: bool = False,
    wait_for_complete: bool = False,
    offset: int = 0,
    limit: int = DATABASE_LIMIT,
    select: str = None,
    sort: str = None,
    search: str = None,
    q: str = None,
    distinct: bool = False,
) -> ConnexionResponse:
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
        'distinct': distinct,
    }

    dapi = DistributedAPI(
        f=agent.get_agents_in_group,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
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

    dapi = DistributedAPI(
        f=agent.create_group,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
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

    dapi = DistributedAPI(
        f=agent.get_group_conf,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_group_config(
    body: bytes, group_id: str, pretty: bool = False, wait_for_complete: bool = False
) -> ConnexionResponse:
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

    f_kwargs = {'group_list': [group_id], 'file_data': parsed_body}

    dapi = DistributedAPI(
        f=agent.update_group_file,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
