#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from glob import glob

from wazuh import common
from wazuh.agent import Agent
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery, WazuhDBQueryDistinct
from wazuh.wdb import WazuhDBConnection


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
        self.agent_id = agent_id
        Agent(agent_id).get_basic_information()  # check if the agent exists
        db_path = glob('{0}/{1}.db'.format(common.database_path_agents, agent_id))
        if not db_path:
            raise WazuhException(1600)

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='pm_global', sort=sort, search=search,
                              select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, db_path=db_path[0],
                              min_select_fields=set(), count=count, get_data=get_data,
                              date_fields={'si.pm_end_scan', 'si.pm_start_scan'})
        self.conn = WazuhDBConnection()

    def _default_query(self):
        return 'SELECT {0} FROM pm_global pmg INNER JOIN scan_info si ON pmg.scan_id=si.pm_scan_id'

    def _get_total_items(self):
        self.total_items = self.conn.execute(f'agent {self.agent_id} sql ' + self.query.format(self._default_count_query()), self.request)

    def _get_data(self):
        self._data = self.conn.execute(f'agent {self.agent_id} sql ' + self.query.format(','.join(map(lambda x: self.fields[x], self.select['fields'] | self.min_select_fields))), self.request)

    def _format_data_into_dictionary(self):
        return self._data


class WazuhDBQueryPMDistinct(WazuhDBQueryDistinct, WazuhDBQueryPM):
    pass


def get_pm_list(agent_id=None, q="", offset=0, limit=common.database_limit,
                sort=None, search=None, select=None, filters={}):
    if select is None:
        select = {'fields': ['scan_id', 'profile', 'pass', 'failed', 'unknown',
                             'score', 'end_scan', 'start_scan']
                  }

    db_query = WazuhDBQueryPM(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                              select=select, count=True, get_data=True, query=q, filters=filters)
    return db_query.run()
