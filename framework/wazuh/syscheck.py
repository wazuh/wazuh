

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import time
from glob import glob
from operator import itemgetter
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.ossec_queue import OssecQueue
from wazuh import common
from datetime import datetime
from wazuh.database import Connection
from wazuh.wdb import WazuhDBConnection
from wazuh.utils import WazuhDBQuery, WazuhDBBackend, WazuhVersion


def run(agent_id=None, all_agents=False):
    """
    Runs rootcheck and syscheck.

    :param agent_id: Run rootcheck/syscheck in the agent.
    :param all_agents: Run rootcheck/syscheck in all agents.
    :return: Message.
    """

    if agent_id == "000" or all_agents:
        try:
            SYSCHECK_RESTART = "{0}/var/run/.syscheck_run".format(common.ossec_path)

            fp = open(SYSCHECK_RESTART, 'w')
            fp.write('{0}\n'.format(SYSCHECK_RESTART))
            fp.close()
            ret_msg = "Restarting Syscheck/Rootcheck locally"
        except:
            raise WazuhException(1601, "locally")

        if all_agents:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART)
            oq.close()
    else:
        # Check if agent exists
        agent_info = Agent(agent_id).get_basic_information()
        if 'status' in agent_info:
            agent_status = agent_info['status']
        else:
            agent_status = "N/A"

        if agent_status.lower() != 'active':
            raise WazuhException(1604, '{0} - {1}'.format(agent_id, agent_status))

        oq = OssecQueue(common.ARQUEUE)
        ret_msg = oq.send_msg_to_agent(OssecQueue.HC_SK_RESTART, agent_id)
        oq.close()

    return ret_msg


def clear(agent_id=None, all_agents=False):
    """
    Clears the database.

    :param agent_id: For an agent.
    :param all_agents: For all agents.
    :return: Message.
    """
    agents = [agent_id] if not all_agents else map(itemgetter('id'), Agent.get_agents_overview(select={'fields': ['id']})['items'])

    wdb_conn = WazuhDBConnection()
    for agent in agents:
        Agent(agent).get_basic_information()  # check if the agent exists
        wdb_conn.execute("agent {} sql delete from fim_entry".format(agent), delete=True)
        # update key fields which contains keys to value 000
        wdb_conn.execute("agent {} sql update metadata set value = '000' where key like 'fim_db%'".format(agent), update=True)
        wdb_conn.execute("agent {} sql update metadata set value = '000' where key = 'syscheck-db-completed'".format(agent), update=True)

    return "Syscheck database deleted"


class WazuhDBQuerySyscheck(WazuhDBQuery):

    def __init__(self, agent_id, default_sort_field='mtime', *args, **kwargs):
        super().__init__(backend=WazuhDBBackend(agent_id), default_sort_field=default_sort_field, count=True,
                         get_data=True, date_fields={'mtime', 'date'}, *args, **kwargs)

    def _filter_date(self, date_filter, filter_db_name):
        # dates are stored as timestamps
        date_filter['value'] = int(time.mktime(time.strptime(date_filter['value'], "%Y-%m-%d")))
        self.query += "{0} IS NOT NULL AND {0} {1} :{2}".format(self.fields[filter_db_name], date_filter['operator'],
                                                                date_filter['field'])
        self.request[date_filter['field']] = date_filter['value']

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value):
            if field_name == 'mtime' or field_name == 'date':
                return datetime.utcfromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
            if field_name == 'end' or field_name == 'start':
                return 'ND' if not value else datetime.utcfromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
            else:
                return value

        self._data = [{key: format_fields(key, value) for key, value in item.items() if key in self.select['fields']}
                      for item in self._data]

        return super()._format_data_into_dictionary()


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """
    my_agent = Agent(agent_id)
    # if agent status is never connected, a KeyError happens
    try:
        agent_version = my_agent.get_basic_information(select={'fields': ['version']})['version']
    except KeyError:
        # if the agent is never connected, it won't have either version (key error) or last scan information.
        return {'start': 'ND', 'end': 'ND'}

    if WazuhVersion(agent_version) < WazuhVersion('Wazuh v3.7.0'):
        db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_agent:
            raise WazuhException(1600)
        else:
            db_agent = db_agent[0]
        conn = Connection(db_agent)

        data = {}
        # end time
        query = "SELECT max(date_last) FROM pm_event WHERE log = 'Ending rootcheck scan.'"
        conn.execute(query)
        for tuple in conn:
            data['end'] = tuple['max(date_last)'] if tuple['max(date_last)'] is not None else "ND"

        # start time
        query = "SELECT max(date_last) FROM pm_event WHERE log = 'Starting rootcheck scan.'"
        conn.execute(query)
        for tuple in conn:
            data['start'] = tuple['max(date_last)'] if tuple['max(date_last)'] is not None else "ND"

        return data
    else:
        fim_scan_info = WazuhDBQuerySyscheck(agent_id=agent_id, query='module=fim', offset=0, sort=None, search=None,
                                             limit=common.database_limit, select={'fields': ['end', 'start']},
                                             fields={'end': 'end_scan', 'start': 'start_scan', 'module': 'module'},
                                             table='scan_info', default_sort_field='start_scan').run()['items'][0]

        return fim_scan_info


def files(agent_id=None, offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}, q='',
          summary=False):
    """
    Return a list of files from the database that match the filters

    :param agent_id: Agent ID.
    :param filters: Fields to filter by
    :param summary: Returns a summary grouping by filename.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :param query: Query to filter by
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    parameters = {"date": "date", "mtime": "mtime", "file": "file", "size": "size", "perm": "perm", "uname": "uname",
                  "gname": "gname", "md5": "md5", "sha1": "sha1", "sha256": "sha256", "inode": "inode", "gid": "gid",
                  "uid": "uid", "type": "type"}
    summary_parameters = {"date": "date", "mtime": "mtime", "file": "file"}

    if 'hash' in filters:
        q = f'(md5={filters["hash"]},sha1={filters["hash"]},sha256={filters["hash"]})' + ('' if not q else ';' + q)
        del filters['hash']

    return WazuhDBQuerySyscheck(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                filters=filters, query=q, select=select, table='fim_entry',
                                fields=summary_parameters if summary else parameters).run()
