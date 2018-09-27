#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from operator import itemgetter
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
    agents = [agent_id] if not all_agents else map(itemgetter('id'), Agent.get_agents_overview(select={'fields': ['id']})['items'])

    wdb_conn = WazuhDBConnection()
    for agent in agents:
        wdb_conn.execute("agent {} sql delete from fim_entry".format(agent), delete=True)
        # update key fields which contains keys to value 000
        wdb_conn.execute("agent {} sql update metadata set value = '000' where key like 'fim_db%'".format(agent), update=True)

    return "Syscheck database deleted"


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """
    start_timestamp = Agent(agent_id)._load_info_from_agent_db(table='metadata', select={'fields': ['value']},
                                                               filters={'key': 'fim-db-start-scan'})[0]['value']
    if start_timestamp == "000":
        return {'start': 'ND', 'end': 'ND'}
    else:
        start = datetime.fromtimestamp(float(start_timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        end_timestamp = Agent(agent_id)._load_info_from_agent_db(table='metadata', select={'fields': ['value']},
                                                                 filters={'key': 'fim-db-end-scan'})[0]['value']
        if end_timestamp == "000":
            return {'start': start, 'end': 'ND'}
        else:
            end = datetime.fromtimestamp(float(end_timestamp)).strftime('%Y-%m-%d %H:%M:%S')
            return {'start': start, 'end': end}


def files(agent_id=None, summary=False, offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}):
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
    parameters = ["date", "mtime", "file", "size", "perm", "uname", "gname", "md5", "sha1", "sha256", "inode", "gid",
                  "uid", "type"]
    summary_parameters = ["date", "mtime", "file"]

    if select is None:
        if summary:
            select = {'fields': summary_parameters}
        else:
            select = {'fields': parameters}
    else:
        if not set(select['fields']).issubset(set(parameters)):
            raise WazuhException(1724, "Allowed select fields: {0}".format(', '.join(parameters)))

    db_query = Agent(agent_id)._load_info_from_agent_db(table='fim_entry', select=select, offset=offset, limit=limit,
                                                        sort=sort, search=search, filters=filters, count=True)
    if "mtime" in select['fields']:
        for item in db_query[0]:
            # if mtime field is 0, returns "ND"
            if item['mtime'] == 0:
                item['mtime'] = "ND"
            else:
                item['mtime'] = datetime.fromtimestamp(float(item['mtime'])).strftime('%Y-%m-%d %H:%M:%S')

    if "date" in select['fields']:
        for item in db_query[0]:
            # if mtime field is 0, returns "ND"
            if item['date'] == 0:
                item['date'] = "ND"
            else:
                item['date'] = datetime.fromtimestamp(float(item['date'])).strftime('%Y-%m-%d %H:%M:%S')

    return {'totalItems': db_query[1], 'items': db_query[0]}
