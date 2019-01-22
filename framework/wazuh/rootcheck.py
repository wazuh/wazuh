#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery, WazuhDBQueryDistinct
from wazuh.agent import Agent
from wazuh.database import Connection
from wazuh.ossec_queue import OssecQueue
from wazuh import common
from glob import glob
from os import remove, path

fields = {'status': 'status', 'event': 'log', 'oldDay': 'date_first', 'readDay': 'date_last', 'pci':'pci_dss', 'cis': 'cis'}

class WazuhDBQueryRootcheck(WazuhDBQuery):

    def __init__(self, agent_id, offset, limit, sort, search, select, query, count, get_data, default_sort_field='date_last', filters={}, fields=fields):
        Agent(agent_id).get_basic_information()  # check if the agent exists
        db_path = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_path:
            raise WazuhException(1600)

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='pm_event', sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field, default_sort_order='DESC', filters=filters,
                              query=query, db_path=db_path[0], min_select_fields=set(), count=count, get_data=get_data,
                              date_fields={'oldDay','readDate'})

    def _parse_filters(self):
        WazuhDBQuery._parse_filters(self)
        # status filter can only appear once in the filter list
        statuses = list(filter(lambda x: x['field'].startswith('status'), self.query_filters))
        if statuses:
            for status in statuses:
                self.query_filters.remove(status)
            first_status = statuses[0]
            first_status['separator'] = 'AND' if first_status['separator'] == '' else first_status['separator']
            self.query_filters.insert(0, statuses[0])
            self.query_filters[-1]['separator'] = ''


    def _filter_status(self, filter_status):
        partial = """SELECT {0} AS status, date_first, date_last, log, pci_dss, cis FROM pm_event AS t
                WHERE date_last {1} (SELECT datetime(date_last, '-86400 seconds') FROM pm_event WHERE log = 'Ending rootcheck scan.')"""

        if filter_status['value'] == 'all':
            self.query = "SELECT {0} FROM (" + partial.format("'outstanding'", '>') + ' UNION ' + partial.format("'solved'",'<=') + \
                    ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.'"
        elif filter_status['value'] == 'outstanding':
            self.query = "SELECT {0} FROM (" + partial.format("'outstanding'", '>') + \
                    ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.'"
        elif filter_status['value'] == 'solved':
            self.query = "SELECT {0} FROM (" + partial.format("'solved'", '<=') + \
                    ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.'"
        else:
            raise WazuhException(1603, filter_status['value'])


    @staticmethod
    def _pass_filter(db_filter):
        return False


class WazuhDBQueryRootcheckDistinct(WazuhDBQueryDistinct, WazuhDBQueryRootcheck): pass


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
        # Check if agent exists and it is active
        agent_info = Agent(agent_id).get_basic_information()
        if 'status' in agent_info:
            agent_status = agent_info['status']
        else:
            agent_status = "N/A"

        if agent_status.lower() != 'active':
            raise WazuhException(1602, '{0} - {1}'.format(agent_id, agent_status))

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

    # Clear DB
    if int(all_agents):
        db_agents = glob('{0}/*-*.db'.format(common.database_path_agents))
    else:
        Agent(agent_id).get_basic_information()  # check if the agent exists
        db_agents = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))

    if not db_agents:
        raise WazuhException(1600)

    for db_agent in db_agents:
        conn = Connection(db_agent)
        conn.begin()
        try:
            conn.execute('DELETE FROM pm_event')
        except Exception as exception:
            raise WazuhException(1654, exception)
        finally:
            conn.commit()
            conn.vacuum()

    # Clear OSSEC info
    if int(all_agents):
        rootcheck_files = glob('{0}/queue/rootcheck/*'.format(common.ossec_path))
    else:
        if agent_id == "000":
            rootcheck_files = ['{0}/queue/rootcheck/rootcheck'.format(common.ossec_path)]
        else:
            agent_info = Agent(agent_id).get_basic_information()
            rootcheck_files = glob('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, agent_info['name'], agent_info['ip']))

    for rootcheck_file in rootcheck_files:
        if path.exists(rootcheck_file):
            remove(rootcheck_file)

    return "Rootcheck database deleted"


def print_db(agent_id=None, q="", offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}):
    """
    Returns a list of events from the database.

    :param agent_id: Agent ID.
    :param filters: Fields to filter by.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param select: Selects which fields to return.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    select = {'fields':["status", "oldDay", "readDay", "event", "pci", "cis"]} if select is None else select
    if 'status' not in q and 'status' not in filters:
        q = 'status=all' + ('' if not q else ';'+q)

    db_query = WazuhDBQueryRootcheck(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                     select=select, count=True, get_data=True, query=q, filters=filters)
    return db_query.run()


def _get_requirement(requirement, agent_id=None, offset=0, limit=common.database_limit, sort=None, search=None, q="", filters={}):
    """
    Get all requirements used in the rootcheck of the agent

    :param requirement: requirement to get
    :param agent_id: Agent ID
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param filters: Fields to filter by.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    db_query = WazuhDBQueryRootcheckDistinct(offset=offset, limit=limit, sort=sort, search=search, filters=filters,
                                            select={'fields':[requirement]}, agent_id=agent_id, fields={requirement:fields[requirement]},
                                             default_sort_field=fields[requirement], count=True, get_data=True, query=q)
    return db_query.run()


def get_pci(agent_id=None, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Get all the PCI requirements used in the rootchecks of the agent.

    :param agent_id: Agent ID.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    return _get_requirement(requirement='pci', agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search)


def get_cis(agent_id=None, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Get all the CIS requirements used in the rootchecks of the agent.

    :param agent_id: Agent ID.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    return _get_requirement(requirement='cis', agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search)


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """
    Agent(agent_id).get_basic_information()  # check if the agent exists
    # Connection
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
        data['end'] = tuple[0] if tuple[0] is not None else "ND"

    # start time
    query = "SELECT max(date_last) FROM pm_event WHERE log = 'Starting rootcheck scan.'"
    conn.execute(query)
    for tuple in conn:
        data['start'] = tuple[0] if tuple[0] is not None else "ND"

    return data
