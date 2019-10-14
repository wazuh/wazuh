# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob

from wazuh import common
from wazuh.agent import WazuhDBQueryAgents, WazuhDBQueryMultigroups
from wazuh.database import Connection
from wazuh.exception import WazuhInternalError


def get_agents_info():
    """Get all agents IDs in the system

    :return: List of agents ids
    """
    agents = WazuhDBQueryAgents(select=['id']).run()['items']
    agents_list = set()
    for agent_info in agents:
        agents_list.add(str(agent_info['id']).zfill(3))

    return agents_list


def get_groups():
    """Get all groups in the system

    :return: List of group names
    """
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)
    conn = Connection(db_global[0])
    conn.execute("SELECT name FROM `group`")
    groups = conn.fetch_all()
    groups_list = set()
    for group in groups:
        groups_list.add(group['name'])

    return groups_list


def expand_group(group_name):
    """Expands a certain group or all (*) of them

    :param group_name: Name of the group to be expanded
    :return: List of agents ids
    """
    if group_name == '*':
        data = WazuhDBQueryAgents(select=['group']).run()['items']
        groups = set()
        for agent_group in data:
            groups.update(set(agent_group.get('group', list())))
    else:
        groups = {group_name}
    agents_ids = set()
    for group in groups:
        agents_group = WazuhDBQueryMultigroups(group, select=['id']).run()['items']
        for agent in agents_group:
            agents_ids.add(str(agent['id']).zfill(3))

    return agents_ids
