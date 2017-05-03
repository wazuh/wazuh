#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute
from wazuh.agent import Agent
from wazuh.database import Connection
from wazuh.ossec_queue import OssecQueue
from wazuh import common
from glob import glob
from os import remove, path


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


def print_db(agent_id=None, status='all', pci=None, cis=None, offset=0, limit=common.database_limit, sort=None, search=None):
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

    # Connection
    db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
    if not db_agent:
        raise WazuhException(1600)
    else:
        db_agent = db_agent[0]

    conn = Connection(db_agent)

    request = {}
    fields = {'status': 'status', 'event': 'log', 'oldDay': 'date_first', 'readDay': 'date_last'}

    partial = """SELECT {0} AS status, date_first, date_last, log, pci_dss, cis
        FROM pm_event AS t
        WHERE date_last {1} (SELECT datetime(date_last, '-86400 seconds') FROM pm_event WHERE log = 'Ending rootcheck scan.')"""

    if status == 'all':
        query = "SELECT {0} FROM (" + partial.format("'outstanding'", '>') + ' UNION ' + partial.format("'solved'", '<=') + \
            ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"
    elif status == 'outstanding':
        query = "SELECT {0} FROM (" + partial.format("'outstanding'", '>') + \
            ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"
    elif status == 'solved':
        query = "SELECT {0} FROM (" + partial.format("'solved'", '<=') + \
            ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', 'Starting syscheck scan.', 'Ending syscheck scan.')"

    if pci:
        query += ' AND pci_dss = :pci'
        request['pci'] = pci

    if cis:
        query += ' AND cis = :cis'
        request['cis'] = cis

    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " (" + " OR ".join(x + ' LIKE :search' for x in ('status', 'date_first', 'date_last', 'log')) + ")"
        request['search'] = '%{0}%'.format(search['value'])

    # Total items

    conn.execute(query.format('COUNT(*)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting

    if sort:
        allowed_sort_fields = fields.keys()
        for sf in sort['fields']:
            if sf not in allowed_sort_fields:
                raise WazuhException(1403, 'Allowed sort fields: {0}. Field: {1}'.format(allowed_sort_fields, sf))
        query += ' ORDER BY ' + ','.join(['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']])
    else:
        query += ' ORDER BY date_last DESC'

    query += ' LIMIT :offset,:limit'
    request['offset'] = offset
    request['limit'] = limit

    select = ["status", "date_first", "date_last", "log", "pci_dss", "cis"]

    conn.execute(query.format(','.join(select)), request)

    data['items'] = []
    for tuple in conn:
        data_tuple = {}

        if tuple[0] != None:
            data_tuple['status'] = tuple[0]
        if tuple[1] != None:
            data_tuple['oldDay'] = tuple[1]
        if tuple[2] != None:
            data_tuple['readDay'] = tuple[2]
        if tuple[3] != None:
            data_tuple['event'] = tuple[3]
        if tuple[4] != None:
            data_tuple['pci'] = tuple[4]
        if tuple[5] != None:
            data_tuple['cis'] = tuple[5]

        data['items'].append(data_tuple)

    return data


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

    query = "SELECT {0} FROM pm_event WHERE pci_dss IS NOT NULL"
    fields = {}
    request = {}

    # Connection
    db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
    if not db_agent:
        raise WazuhException(1600)
    else:
        db_agent = db_agent[0]

    conn = Connection(db_agent)

    # Search
    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " pci_dss LIKE :search"
        request['search'] = '%{0}%'.format(search['value'])

    # Total items
    conn.execute(query.format('COUNT(DISTINCT pci_dss)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting
    if sort:
        allowed_sort_fields = fields.keys()
        for sf in sort['fields']:
            if sf not in allowed_sort_fields:
                raise WazuhException(1403, 'Allowed sort fields: {0}. Field: {1}'.format(allowed_sort_fields, sf))
        query += ' ORDER BY pci_dss ' + sort['order']
    else:
        query += ' ORDER BY pci_dss ASC'

    query += ' LIMIT :offset,:limit'
    request['offset'] = offset
    request['limit'] = limit


    conn.execute(query.format('DISTINCT pci_dss'), request)

    data['items'] = []
    for tuple in conn:
        data['items'].append(tuple[0])

    return data


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

    query = "SELECT {0} FROM pm_event WHERE cis IS NOT NULL"
    fields = {}
    request = {}

    # Connection
    db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
    if not db_agent:
        raise WazuhException(1600)
    else:
        db_agent = db_agent[0]

    conn = Connection(db_agent)

    # Search
    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " cis LIKE :search"
        request['search'] = '%{0}%'.format(search['value'])

    # Total items
    conn.execute(query.format('COUNT(DISTINCT cis)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting
    if sort:
        allowed_sort_fields = fields.keys()
        for sf in sort['fields']:
            if sf not in allowed_sort_fields:
                raise WazuhException(1403, 'Allowed sort fields: {0}. Field: {1}'.format(allowed_sort_fields, sf))
        query += ' ORDER BY cis ' + sort['order']
    else:
        query += ' ORDER BY cis ASC'

    query += ' LIMIT :offset,:limit'
    request['offset'] = offset
    request['limit'] = limit


    conn.execute(query.format('DISTINCT cis'), request)

    data['items'] = []
    for tuple in conn:
        data['items'].append(tuple[0])

    return data


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: rootcheckEndTime, rootcheckTime.
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
    query = "SELECT max(date_first) FROM pm_event WHERE log = 'Ending rootcheck scan.'"
    conn.execute(query)
    for tuple in conn:
        data['rootcheckEndTime'] = tuple[0]

    # start time
    query = "SELECT max(date_first) FROM pm_event WHERE log = 'Starting rootcheck scan.'"
    conn.execute(query)
    for tuple in conn:
        data['rootcheckTime'] = tuple[0]

    return data
