#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh.utils import execute, filemode
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
            conn.execute('DELETE FROM fim_event')
            conn.execute('DELETE FROM fim_file')
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

    # Connection
    db_agent = glob('{0}/{1}-*.db'.format(common.database_path_agents, agent_id))
    if not db_agent:
        raise WazuhException(1600)
    else:
        db_agent = db_agent[0]

    conn = Connection(db_agent)

    data = {}
    # end time
    query = "SELECT max(date_last) FROM pm_event WHERE log = 'Ending syscheck scan.'"
    conn.execute(query)
    for tuple in conn:
        data['end'] = tuple[0]

    # start time
    query = "SELECT max(date_last) FROM pm_event WHERE log = 'Starting syscheck scan.'"
    conn.execute(query)
    for tuple in conn:
        data['start'] = tuple[0]

    return data


def files(agent_id=None, event=None, filename=None, filetype='file', md5=None, sha1=None, hash=None, summary=False, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Return a list of files from the database that match the filters

    :param agent_id: Agent ID.
    :param event: Filters by event: added, readded, modified, deleted.
    :param filename: Filters by filename.
    :param filetype: Filters by filetype: file or registry.
    :param md5: Filters by md5 hash.
    :param sha1: Filters by sha1 hash.
    :param hash: Filters by md5 or sha1 hash.
    :param summary: Returns a summary grouping by filename.
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

    agent_info = Agent(agent_id).get_basic_information()
    if 'os' in agent_info and 'platform' in agent_info['os']:
        if agent_info['os']['platform'].lower() == 'windows':
            windows_agent = True
        else:
            windows_agent = False
    else:
        # We do not know if it is a windows or linux agent.
        # It is set to windows agent in order to avoid wrong data (uid, gid, ...)
        windows_agent = True

    fields = {'scanDate': 'date', 'modificationDate': 'mtime', 'file': 'path', 'size': 'size', 'user': 'uname', 'group': 'gname'}

    # Query
    query = "SELECT {0} FROM fim_event, fim_file WHERE fim_event.id_file = fim_file.id AND fim_file.type = :filetype"
    request = {'filetype': filetype}

    if event:
        query += ' AND fim_event.type = :event'
        request['event'] = event

    if filename:
        query += ' AND path = :filename'
        request['filename'] = filename

    if md5:
        query += ' AND md5 = :md5'
        request['md5'] = md5

    if sha1:
        query += ' AND sha1 = :sha1'
        request['sha1'] = sha1

    if hash:
        query += ' AND (md5 = :hash OR sha1 = :hash)'
        request['hash'] = hash

    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " (" + " OR ".join(x + ' LIKE :search' for x in ('path', "date", 'size', 'md5', 'sha1', 'uname', 'gname', 'inode', 'perm')) + " )"
        request['search'] = '%{0}%'.format(search['value'])

    # Total items
    if summary:
        query += ' group by path'
        conn.execute("SELECT COUNT(*) FROM ({0}) AS TEMP".format(query.format("max(date)")), request)
    else:
        conn.execute(query.format('COUNT(*)'), request)

    data = {'totalItems': conn.fetch()[0]}

    # Sorting
    if sort:
        if sort['fields']:
            allowed_sort_fields = fields.keys()
             # Check if every element in sort['fields'] is in allowed_sort_fields
            if not set(sort['fields']).issubset(allowed_sort_fields):
                uncorrect_fields = list(map(lambda x: str(x), set(sort['fields']) - set(allowed_sort_fields)))
                raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, uncorrect_fields))

            query += ' ORDER BY ' + ','.join(['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']])
        else:
            query += ' ORDER BY date {0}'.format(sort['order'])
    else:
        query += ' ORDER BY date DESC'

    if limit:
        if limit > common.maximum_database_limit:
            raise WazuhException(1405, str(limit))
        query += ' LIMIT :offset,:limit'
        request['offset'] = offset
        request['limit'] = limit
    elif limit == 0:
        raise WazuhException(1406)

    if summary:
        select = ["max(date)", "mtime", "fim_event.type", "path"]
    else:
        select = ["date", "mtime", "fim_event.type", "path", "size", "perm", "uid", "gid", "md5", "sha1", "uname", "gname", "inode"]

    conn.execute(query.format(','.join(select)), request)

    data['items'] = []

    for tuple in conn:
        data_tuple = {}

        if tuple[0] != None:
            data_tuple['scanDate'] = tuple[0]
        if tuple[1] != None:
            data_tuple['modificationDate'] = tuple[1]  # modificationDate
        else:
            data_tuple['modificationDate'] = tuple[0]  # scanDate
        if tuple[2] != None:
            data_tuple['event'] = tuple[2]
        if tuple[3] != None:
            data_tuple['file'] = tuple[3]

        if not summary:
            try:
                permissions = filemode(int(tuple[5], 8))
            except TypeError:
                permissions = None

            if tuple[4] != None:
                data_tuple['size'] = tuple[4]
            if tuple[8] != None:
                data_tuple['md5'] = tuple[8]
            if tuple[9] != None:
                data_tuple['sha1'] = tuple[9]
            if tuple[12] != None:
                data_tuple['inode'] = tuple[12]

            if not windows_agent:
                if tuple[6] != None:
                    data_tuple['uid'] = tuple[6]
                if tuple[7] != None:
                    data_tuple['gid'] = tuple[7]

                if tuple[10] != None:
                    data_tuple['user'] = tuple[10]
                if tuple[11] != None:
                    data_tuple['group'] = tuple[11]

                if tuple[5] != None:
                    data_tuple['octalMode'] = tuple[5]
                if permissions:
                    data_tuple['permissions'] = permissions


        data['items'].append(data_tuple)

    return data
