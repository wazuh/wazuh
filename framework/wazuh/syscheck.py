#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import filemode, WazuhDBQuery
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
            conn.execute('DELETE FROM fim_entry')
        except Exception as exception:
            raise exception
        finally:
            conn.commit()
            conn.vacuum()

    # Clear OSSEC info
    if int(all_agents):
        syscheck_files = glob('{0}/queue/syscheck/*'.format(common.ossec_path))
    else:
        if agent_id == "000":
            syscheck_files = ['{0}/queue/syscheck/syscheck'.format(common.ossec_path)]
        else:
            agent_info = Agent(agent_id).get_basic_information()
            syscheck_files = glob('{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, agent_info['name'], agent_info['ip']))

    for syscheck_file in syscheck_files:
        if path.exists(syscheck_file):
            remove(syscheck_file)

    return "Syscheck database deleted"


def last_scan(agent_id):
    """
    Gets the last scan of the agent.

    :param agent_id: Agent ID.
    :return: Dictionary: end, start.
    """
    data = {}
    data['start'] = Agent(agent_id)._load_info_from_agent_db(table='metadata', select=['value'],
                                                           filters={'key': 'fim-db-start-first-scan'})[0]['value']
    data['end'] = Agent(agent_id)._load_info_from_agent_db(table='metadata', select=['value'],
                                                             filters={'key': 'fim-db-end-first-scan'})[0]['value']
    return data


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
    if 'filetype' not in q:
        q = 'filetype=file' + ('' if not q else ';'+q)

    db_query = WazuhDBQuerySyscheck(offset=offset, limit=limit, sort=sort, search=search, count=True, get_data=True,
                                    query=q, agent_id=agent_id, summary=summary, select=select, filters=filters)
    data = db_query.run()
    if not summary:
        data['items'] = [dict(x, permissions=filemode(int(x['octalMode']))) for x in data['items']]
    return data


class WazuhDBQuerySyscheck(WazuhDBQuery):

    def __init__(self, agent_id, summary, offset, limit, sort, search, select, query, count, get_data, default_sort_order='ASC', filters={}, min_select_fields=set()):

        db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_agent:
            raise WazuhException(1600)
        else:
            db_agent = db_agent[0]

        self.summary = False if summary == 'no' or not summary else True
        if self.summary:
            select = {'fields':["modificationDate", "file", "scanDate"]} if not select else select
        else:
            select = {'fields':["scanDate", "modificationDate", "file", "size", "octalMode", "user", "group", "md5", "sha1",
                                "group", "inode", "gid", "uid"]} if not select else select  # sha256 field needs to be added

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, sort=sort, search=search, select=select, default_sort_field='date',
                              query=query, db_path=db_agent, count=count, get_data=get_data, default_sort_order=default_sort_order,
                              min_select_fields=min_select_fields, table='fim_entry', date_fields={'scanDate','modificationDate'},
                              fields={'scanDate': 'date', 'modificationDate': 'mtime', 'file': 'file', 'size': 'size', 'user': 'uname',
                                      'group': 'gname', 'md5':'md5', 'sha1':'sha1', 'sha256':'sha256',
                                      'inode':'inode','uid':'uid','gid':'gid', 'octalMode':'perm', 'filetype':'type'},
                              filters=filters)


    def _default_query(self):
        # return "SELECT {0} FROM " + self.table + " WHERE fim_event.id_file = fim_file.id"  #### OLD!
        return "SELECT {0} FROM " + self.table


    def _get_total_items(self):
        if self.summary:
            self.query += ' group by path'
            self.conn.execute("SELECT COUNT(*) FROM ({0}) AS TEMP".format(self.query.format("max(date)")), self.request)
            self.total_items = self.conn.fetch()[0]
        else:
            WazuhDBQuery._get_total_items(self)


    def _get_data(self):
        if self.summary:
            self.fields['scanDate'] = 'max(date)'
        WazuhDBQuery._get_data(self)


    def _parse_legacy_filters(self):
        if 'hash' in self.legacy_filters:
            self.q += (';' if self.q else '') + '(md5={0},sha1={0})'.format(self.legacy_filters['hash'])
            del self.legacy_filters['hash']
        WazuhDBQuery._parse_legacy_filters(self)


class WazuhDBQueryMetadata(WazuhDBQuery):

    def __init__(self, agent_id, summary, offset, limit, sort, search, select, query, count, get_data, default_sort_order='ASC', filters={}, min_select_fields=set()):

        db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
        if not db_agent:
            raise WazuhException(1600)
        else:
            db_agent = db_agent[0]

        self.summary = False if summary == 'no' or not summary else True

        select = {'fields': ["key", "value"]}

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, sort=sort, search=search, select=select, default_sort_field='date',
                              query=query, db_path=db_agent, count=count, get_data=get_data, default_sort_order=default_sort_order,
                              min_select_fields=min_select_fields, table='metadata', date_fields={},
                              fields={'key':'key', 'value':'value'},
                              filters=filters)
