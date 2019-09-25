# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob

from wazuh import common
from wazuh.agent import WazuhDBQueryAgents, WazuhDBQueryMultigroups
from wazuh.exception import WazuhInternalError


def get_agents_info():
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)
    agents = WazuhDBQueryAgents(select=['id']).run()['items']
    agents_list = set()
    for agent_info in agents:
        agents_list.add(str(agent_info['id']).zfill(3))

    return agents_list


def expand_group(group):
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)
    agents_group = WazuhDBQueryMultigroups(group, select=['id']).run()['items']
    agents_ids = list()
    for agent in agents_group:
        agents_ids.append(str(agent['id']).zfill(3))

    return agents_ids
