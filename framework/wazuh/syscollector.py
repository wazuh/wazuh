#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh import Wazuh


def get_programs(agent_id, offset=0, limit=common.database_limit, select=None):
    """
    Get info about an agent's programs
    """
    valid_select_fields = ['scan_id', 'scan_time', 'format', 'name',
                           'vendor', 'version', 'architecture', 'description']

    if select:
        if not set(select['fields']).issubset(valid_select_fields):
            uncorrect_fields = map(lambda x: str(x), set(select['fields']) - set(valid_select_fields))
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                    format(valid_select_fields, uncorrect_fields))
        select_fields = select['fields']
    else:
        select_fields = valid_select_fields

    return Agent(agent_id)._load_info_from_agent_db(table='sys_programs', select=select_fields)
