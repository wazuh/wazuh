#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob

from wazuh import common
from wazuh.agent import Agent
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery, WazuhDBQueryDistinct


# API field -> DB field
fields_translation = {'scan_id': 'pmg.scan_id',
                      'profile': 'pmg.profile',
                      'pass': 'pmg.pass',
                      'failed': 'pmg.failed',
                      'unknown': 'pmg.unknown',
                      'score': 'pmg.score',
                      'end_scan': 'si.pm_end_scan',
                      'start_scan': 'si.pm_start_scan'}


class WazuhDBQueryPM(WazuhDBQuery):

    def __init__(self, agent_id, offset, limit, sort, search, select, query, count,
                 get_data, default_sort_field='date_last', filters={}, fields=fields_translation):
        Agent(agent_id).get_basic_information()  # check if the agent exists
        db_path = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_path:
            raise WazuhException(1600)

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='pm_global', sort=sort, search=search,
                              select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, db_path=db_path[0],
                              min_select_fields=set(), count=count, get_data=get_data,
                              date_fields={'si.pm_end_scan', 'si.pm_start_scan'})

    def _default_query(self):
        return 'SELECT {0} FROM pm_global pmg INNER JOIN scan_info si ON pmg.scan_id=si.pm_scan_id'


class WazuhDBQueryPMDistinct(WazuhDBQueryDistinct, WazuhDBQueryPM):
    pass


def get_pm_list(agent_id=None, q="", offset=0, limit=common.database_limit,
                sort=None, search=None, select=None, filters={}):
    if select is None:
        select = ['pmg.scan_id', 'pmg.profile', 'pmg.pass', 'pmg.failed', 'pmg.unknown', 'pmg.score',
                  'si.pm_end_scan', 'si.pm_start_scan']

    db_query = WazuhDBQueryPM(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                              select=select, count=True, get_data=True, query=q, filters=filters)
    return db_query.run()
