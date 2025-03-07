# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from os import listdir, path, remove
from pathlib import Path

from wazuh.core import common
from wazuh.core.exception import WazuhError
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.InputValidator import InputValidator
from wazuh.core.utils import (
    GROUP_FILE_EXT,
    get_group_file_path,
)

AGENT_FIELDS = {
    'id': 'id',
    'name': 'name',
    'key': 'key',
    'groups': 'groups',
    'type': 'type',
    'version': 'version',
    'last_login': 'last_login',
    'persistent_connection_mode': 'persistent_connection_mode',
}


async def delete_single_group(group_name: str) -> dict:
    """Delete a group.

    Parameters
    ----------
    group_name : str
        Group name.

    Returns
    -------
    dict
        Confirmation message.
    """
    # Delete group file
    group_path = get_group_file_path(group_name)
    if path.exists(group_path):
        try:
            remove(group_path)
        except Exception as e:
            raise WazuhError(1006, extra_message=str(e))

    msg = "Group '{0}' deleted.".format(group_name)
    return {'message': msg}


def group_exists(group_id: str) -> bool:
    """Check if the group exists.

    Parameters
    ----------
    group_id : str
        Group ID.

    Raises
    ------
    WazuhError(1722)
        Incorrect format for group_id.

    Returns
    -------
    bool
        True if group exists, False otherwise.
    """
    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhError(1722)

    return path.exists(get_group_file_path(group_id))


@common.async_context_cached('system_agents')
async def get_agents_info() -> set:
    """Get all agent IDs in the system.

    Returns
    -------
    set
        IDs of all agents in the system.
    """
    async with get_indexer_client() as indexer_client:
        query = {IndexerKey.MATCH_ALL: {}}
        agents = await indexer_client.agents.search(query={IndexerKey.QUERY: query}, select='agent.id')
        return set([agent.id for agent in agents])


@common.context_cached('system_groups')
def get_groups() -> set:
    """Get all groups in the system.

    Returns
    -------
    set
        Names of all groups in the system.
    """
    groups = set()
    for group_file in listdir(common.WAZUH_GROUPS):
        filepath = Path(group_file)
        if filepath.suffix == GROUP_FILE_EXT:
            groups.add(filepath.stem)

    return groups


@common.async_context_cached('system_expanded_groups')
async def expand_group(group_name: str) -> set:
    """Expand a certain group or all (*) of them.

    Parameters
    ----------
    group_name : str
        Name of the group to be expanded.

    Returns
    -------
    set
        Set of agent IDs.
    """
    if group_name == '*':
        return await get_agents_info()

    async with get_indexer_client() as indexer_client:
        agents = await indexer_client.agents.get_group_agents(group_name=group_name)
        return set([agent.id for agent in agents])
