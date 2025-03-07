# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from functools import lru_cache
from os import listdir
from pathlib import Path

from wazuh.core import common
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.utils import (
    GROUP_FILE_EXT,
)
from wazuh.core.wdb import WazuhDBConnection


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


@lru_cache()
def get_manager_name() -> str:
    """This function read the manager name from global.db.

    Returns
    -------
    str
        Manager name.
    """
    # TODO(#25121): This function needs to be redifined according to the required used case.
    wdb_conn = WazuhDBConnection()
    manager_name = wdb_conn.execute('global sql SELECT name FROM agent WHERE (id = 0)')[0]['name']
    wdb_conn.close()

    return manager_name


def get_rbac_filters(system_resources: set = None, permitted_resources: list = None, filters: dict = None) -> dict:
    """This function calculate the list of allowed or denied depending on the list size.

    Parameters
    ----------
    system_resources : set
        System resources for the current request.
    permitted_resources : list
        Resources granted by RBAC.
    filters : dict
        Dictionary with additional filters for the current request.

    Returns
    -------
    dict
        Dictionary with the original filters plus those added by RBAC.
    """
    if not filters:
        filters = dict()
    non_permitted_resources = system_resources - set(permitted_resources)

    if len(permitted_resources) < len(non_permitted_resources):
        filters['rbac_ids'] = permitted_resources
        negate = False
    else:
        filters['rbac_ids'] = list(non_permitted_resources)
        negate = True

    return {'filters': filters, 'rbac_negate': negate}
