# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import re
from functools import lru_cache
from os import listdir, path, remove
from pathlib import Path

from wazuh.core import common
from wazuh.core.exception import WazuhError
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.InputValidator import InputValidator
from wazuh.core.utils import (
    GROUP_FILE_EXT,
    get_date_from_timestamp,
    get_group_file_path,
)
from wazuh.core.wdb import WazuhDBConnection

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


def unify_wazuh_upgrade_version_format(upgrade_version: str) -> str:
    """Format the specified upgrade version into the 'vX.Y.Z' standard.

    Parameters
    ----------
    upgrade_version : str
        String with the specified upgrade version.

    Returns
    -------
    str
        Formatted upgrade version.
    """
    if upgrade_version:
        upgrade_version = re.findall(r'\d+\.\d+\.\d+$', upgrade_version, re.IGNORECASE)[0]
        return f'v{upgrade_version}'


def unify_wazuh_version_format(filters: dict):
    """Verify and format the specified wazuh version into the 'wazuh vX.Y.Z' standard.

    Parameters
    ----------
    filters : dict
        Dictionary field filters required by the user.
    """
    wv = filters.get('version')
    if wv is not None:
        if re.match(r'^v?\d+\.\d+\.\d+$', wv, re.IGNORECASE):
            filters['version'] = f'wazuh {"v" if "v" not in wv else ""}{wv}'
        elif re.match(r'^wazuh \d+\.\d+\.\d+$', wv, re.IGNORECASE):
            filters['version'] = f'{wv.replace(" ", " v")}'


def format_fields(field_name: str, value: str) -> str:
    """Give format to values of specific fields.

    Parameters
    ----------
    field_name : str
        Name of the field to be formatted.
    value : str
        Value of the field.
    """
    if field_name == 'id':
        return str(value).zfill(3)
    elif field_name == 'group':
        return value.split(',')
    elif field_name in ['dateAdd', 'lastKeepAlive', 'disconnection_time']:
        return get_date_from_timestamp(value) if not isinstance(value, str) else value
    else:
        return value


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
