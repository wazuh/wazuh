#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.ossec_queue import OssecQueue
from wazuh import common
from datetime import datetime
from wazuh.wdb import WazuhDBConnection


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
    wdb_conn = WazuhDBConnection()
    table1 = "fim_entry"
    action1 = "delete"
    query1 = "agent {} sql {} from {}".format(agent_id, action1, table1)
    wdb_conn.execute(query1, delete=True)
    # update key fields which contains keys to value 000
    table2 = "metadata"
    action2 = "update"
    new_value = "000"
    keys = ["fim-db-start-first-scan", "fim-db-start-scan", "fim-db-end-first-scan",
                        "fim-db-end-scan"]
    for key in keys:
        query2 = "agent {} sql {} {} set value = '{}' where key = '{}'".format(agent_id, action2, table2, new_value,
                                                                               key)
        wdb_conn.execute(query2, update=True)
    return "Syscheck database deleted"


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """
    # if fim-db-start-scan or fim-db-end-scan is 000, fim-db-start-fist-scan and fim-db-end-first-scan are used
    start_timestamp = float(Agent(agent_id)._load_info_from_agent_db(table='metadata', select=['value'],
                                                                     filters={'key': 'fim-db-start-scan'})[0]['value'])
    if start_timestamp == 0:
        start_timestamp = float(Agent(agent_id)._load_info_from_agent_db(table='metadata', select=['value'],
                                                                         filters={'key': 'fim-db-start-first-scan'})[0]['value'])
    start = datetime.fromtimestamp(start_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    end_timestamp = float(Agent(agent_id)._load_info_from_agent_db(table='metadata', select=['value'],
                                                                   filters={'key': 'fim-db-end-scan'})[0]['value'])
    if end_timestamp == 0:
        end_timestamp = float(Agent(agent_id)._load_info_from_agent_db(table='metadata', select=['value'],
                                                                       filters={'key': 'fim-db-end-first-scan'})[0]['value'])
    end = datetime.fromtimestamp(end_timestamp).strftime('%Y-%m-%d %H:%M:%S')
    return {'start': start, 'end': end}


def files(agent_id=None, summary=False, offset=0, limit=common.database_limit, sort=None, search=None, select=None, q="", filters={}):
    """
    Return a list of files from the database that match the filters

    :param agent_id: Agent ID.
    :param filters: Fields to filter by
    :param summary: Returns a summary grouping by filename.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    select_fields = ["date", "mtime", "file", "size", "perm", "uname", "gname", "md5", "sha1", "sha256", "inode", "gid",
                     "uid", "type"]
    db_query = Agent(agent_id)._load_info_from_agent_db(table='fim_entry', select=select_fields, offset=offset,
                                                        limit=limit, sort=sort, search=search, count=True)
    for item in db_query[0]:
        item['mtime'] = datetime.fromtimestamp(float(item['mtime'])).strftime('%Y-%m-%d %H:%M:%S')
    return {'totalItems': db_query[1], 'items': db_query[0]}
