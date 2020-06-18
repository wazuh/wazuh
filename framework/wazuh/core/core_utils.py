# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob
from os.path import join

from wazuh import common
from wazuh.common import ossec_path
from wazuh.core.core_agent import WazuhDBQueryAgents, WazuhDBQueryMultigroups, WazuhDBQueryGroup
from wazuh.database import Connection
from wazuh.exception import WazuhInternalError


@common.context_cached('system_agents')
def get_agents_info():
    """Get all agents IDs in the system

    :return: List of agents ids
    """
    db_query = WazuhDBQueryAgents(select=['id'])
    query_data = db_query.run()

    return {str(agent_info['id']).zfill(3) for agent_info in query_data['items']}


@common.context_cached('system_groups')
def get_groups():
    """Get all groups in the system

    :return: List of group names
    """
    db_query = WazuhDBQueryGroup(select=['name'], min_select_fields=set())
    query_data = db_query.run()

    return {group['name'] for group in query_data['items']}


@common.context_cached('system_files')
def get_files():
    folders = ['etc/rules', 'etc/decoders', 'etc/lists', 'ruleset/sca', 'ruleset/decoders', 'ruleset/rules']
    files = set()
    for folder in folders:
        for extension in '*.yml', '*.yml.disabled', '*.xml', '*.cdb':
            files.update({f.replace(ossec_path + '/', "") for f in glob(
                join(ossec_path, folder, extension), recursive=True)})
    files.add('etc/ossec.conf')

    return files


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
