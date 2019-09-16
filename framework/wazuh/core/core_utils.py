# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob

from wazuh import common
from wazuh.database import Connection
from wazuh.exception import WazuhInternalError


def get_groups_resources(agent_id):
    """Obtain group resources based on agent_id (all the groups where the agent belongs)

    :param agent_id: Agent_id to search groups for
    :return: Group resources
    """
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)

    conn = Connection(db_global[0])
    if agent_id == '*':
        groups = ['agent:group:*']
        conn.execute("SELECT name FROM `group` WHERE id IN (SELECT DISTINCT id_group FROM belongs)")
    else:
        groups = ['agent:id:*', 'agent:group:*']
        conn.execute("SELECT name FROM `group` WHERE id IN (SELECT id_group FROM belongs WHERE id_agent = :agent_id)",
                     {'agent_id': int(agent_id)})
    result = conn.fetch_all()

    for group in result:
        groups.append('{0}:{1}'.format('agent:group', group['name']))

    return groups


def get_agents_info():
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)

    conn = Connection(db_global[0])
    conn.execute("SELECT id, `group`, manager_host FROM agent")
    agents_info = conn.fetch_all()

    return agents_info


def expand_group(permissions_dict_group, permissions_dict_id):
    def _insert_in_groups(effect, group_dict):
        op_effect = 'deny' if effect == 'allow' else 'allow'
        if '*' in group_dict[effect]:
            group_dict[effect].clear()
            for expanded in expanded_groups:
                if expanded['name'] not in group_dict[op_effect]:
                    group_dict[effect].add(expanded['name'])

    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)

    conn = Connection(db_global[0])
    if '*' in permissions_dict_group['allow'] or '*' in permissions_dict_group['deny']:
        conn.execute("SELECT name FROM `group`")
        expanded_groups = conn.fetch_all()
        _insert_in_groups('allow', permissions_dict_group)
        _insert_in_groups('deny', permissions_dict_group)
    for allowed in permissions_dict_group['allow']:
        conn.execute("SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM `group` WHERE name = :group)",
                     {'group': allowed})
    agents_allowed = conn.fetch_all()
    for agent in agents_allowed:
        agent_id = str(agent['id_agent']).zfill(3)
        if agent_id in permissions_dict_id['deny']:
            permissions_dict_id['deny'].remove(agent_id)
        permissions_dict_id['allow'].add(agent_id)

    for denied in permissions_dict_group['deny']:
        conn.execute("SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM `group` WHERE name = :group)",
                     {'group': denied})
    agents_denied = conn.fetch_all()
    for agent in agents_denied:
        agent_id = str(agent['id_agent']).zfill(3)
        if agent_id in permissions_dict_id['allow']:
            permissions_dict_id['allow'].remove(agent_id)
        permissions_dict_id['deny'].add(agent_id)
