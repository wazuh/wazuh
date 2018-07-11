#!/usr/bin/env python

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

    def __init__(self, agent_id, offset, limit, sort, search, select, filters, count, get_data, filter_operator='='):
        db_path = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_path:
            raise WazuhException(1600)

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='pm_event', sort=sort, search=search, select=select,
                              fields=fields, default_sort_field='date_last', default_sort_order='DESC', filters=filters,
                              db_path=db_path[0], min_select_fields=set(), count=count, get_data=get_data,
                              filter_operator=filter_operator)

    def filter_status(self):
        status = self.filters['status']

        partial = """SELECT {0} AS status, date_first, date_last, log, pci_dss, cis FROM pm_event AS t
                WHERE date_last {1} (SELECT datetime(date_last, '-86400 seconds') FROM pm_event WHERE log = 'Ending rootcheck scan.')"""

        if status == 'all':
            self.query = "SELECT {0} FROM (" + partial.format("'outstanding'", '>') + ' UNION ' + partial.format("'solved'",'<=') + \
                    ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"
        elif status == 'outstanding':
            self.query = "SELECT {0} FROM (" + partial.format("'outstanding'", '>') + \
                    ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"
        elif status == 'solved':
            self.query = "SELECT {0} FROM (" + partial.format("'solved'", '<=') + \
                    ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"
        else:
            raise WazuhException(1603, status)


    @staticmethod
    def pass_filter(db_filter):
        return False


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
        db_agents = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))

    if not db_agents:
        raise WazuhException(1600)

    for db_agent in db_agents:
        conn = Connection(db_agent)
        conn.begin()
        try:
            conn.execute('DELETE FROM pm_event')
        except Exception as exception:
            raise exception
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


def print_db(agent_id=None, filters={}, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Returns a list of events from the database.

    :param agent_id: Agent ID.
    :param status: Filters by status: outstanding, solved, all.
    :param pci: Filters by PCI DSS requirement.
    :param cis: Filters by CIS.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    select = {'fields':["status", "oldDay", "readDay", "log", "pci", "cis"]}
    if 'status' not in filters:
        filters['status'] = 'all'
    db_query = WazuhDBQueryRootcheck(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                     select=select, count=True, get_data=True, filters=filters)
    db_query.run()

    return {'totalItems': db_query.total_items, 'data':[{key:val for key,val in zip(db_query.select['fields'], tuple)
                                                         if val is not None} for tuple in db_query.conn]}


def _get_requirement(requirement, agent_id=None, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Get all requirements used in the rootcheck of the agent

    :param requirement: requirement to get
    :param agent_id: Agent ID
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
    if not db_agent:
        raise WazuhException(1600)
    else:
        db_agent = db_agent[0]

    db_query = WazuhDBQueryDistinct(offset=offset, limit=limit, table='pm_event', sort=sort, search=search,
                                    select={'fields':[requirement]}, db_path=db_agent, fields={requirement:fields[requirement]},
                                    default_sort_field=fields[requirement], count=True, get_data=True, filters={})
    db_query.run()

    return {'totalItems':db_query.total_items, 'items':[tuple[0] for tuple in db_query.conn]}


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
        data['end'] = tuple[0]

    # start time
    query = "SELECT max(date_last) FROM pm_event WHERE log = 'Starting rootcheck scan.'"
    conn.execute(query)
    for tuple in conn:
        data['start'] = tuple[0]

    return data
