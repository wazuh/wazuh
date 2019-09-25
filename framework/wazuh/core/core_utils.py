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


def expand_group(group):
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)
    conn = Connection(db_global[0])
    if group != 'null':
        conn.execute("SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM `group` WHERE name = :group)",
                     {'group': group})
    else:
        conn.execute("SELECT id FROM agent WHERE `group` IS null")
    agents = conn.fetch_all()
    agents_ids = list()
    for agent in agents:
        agents_ids.append(str(agent['id_agent']).zfill(3))

    return agents_ids
