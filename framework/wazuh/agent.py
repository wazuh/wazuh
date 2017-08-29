#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array, chmod_r, chown_r
from wazuh.exception import WazuhException
from wazuh.ossec_queue import OssecQueue
from wazuh.ossec_socket import OssecSocket
from wazuh.database import Connection
from wazuh import manager
from wazuh import common
from glob import glob
from datetime import date, datetime, timedelta
from hashlib import md5, sha1
from base64 import b64encode
from shutil import copyfile, move, copytree
from time import time
from platform import platform
from os import remove, chown, chmod, path, makedirs, rename, urandom, listdir, stat
from pwd import getpwnam
from grp import getgrnam
from time import time, sleep
import socket
from distutils.version import StrictVersion
try:
    from urllib2 import urlopen, URLError, HTTPError
except ImportError:
    from urllib.request import urlopen, URLError, HTTPError

def create_exception_dic(id, e):
    """
    Creates a dictionary with a list of agent ids and it's error codes.
    """
    exception_dic = {}
    exception_dic['id'] = id
    exception_dic['error'] = {'message': e.message, 'code': e.code}
    return exception_dic

class Agent:
    """
    OSSEC Agent object.
    """

    def __init__(self, id=None, name=None, ip=None, key=None, force=-1):
        """
        Initialize an agent.
        'id': When the agent exists
        'name' and 'ip': Add an agent (generate id and key automatically)
        'name', 'ip' and 'force': Add an agent (generate id and key automatically), removing old agent with same IP if disconnected since <force> seconds.
        'name', 'ip', 'id', 'key': Insert an agent with an existent id and key
        'name', 'ip', 'id', 'key', 'force': Insert an agent with an existent id and key, removing old agent with same IP if disconnected since <force> seconds.
        """
        self.id            = id
        self.name          = name
        self.ip            = ip
        self.internal_key  = key
        self.os            = {}
        self.version       = None
        self.dateAdd       = None
        self.lastKeepAlive = None
        self.status        = None
        self.key           = None
        self.configSum     = None
        self.mergedSum     = None
        self.group         = None

        # if the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name != None and ip != None:
            self._add(name=name, ip=ip, id=id, key=key, force=force)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os, 'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive, 'status': self.status, 'key': self.key, 'configSum': self.configSum, 'mergedSum': self.mergedSum, 'group': self.group }

        return dictionary

    @staticmethod
    def calculate_status(last_keep_alive):
        """
        Calculates state based on last keep alive
        """
        if last_keep_alive == 0:
            return "Never connected"
        else:
            limit_seconds = 600*3 + 30
            last_date = datetime.strptime(last_keep_alive, '%Y-%m-%d %H:%M:%S')
            difference = (datetime.now() - last_date).total_seconds()

            if difference < limit_seconds:
                return "Active"
            else:
                return "Disconnected"

    def _load_info_from_DB(self):
        """
        Gets attributes of existing agent.
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Query
        query = "SELECT {0} FROM agent WHERE id = :id"
        request = {'id': self.id}

        select = ["id", "name", "ip", "key", "version", "date_add", "last_keepalive", "config_sum", "merged_sum", "`group`", "os_name", "os_version", "os_major", "os_minor", "os_codename", "os_build", "os_platform", "os_uname"]

        conn.execute(query.format(','.join(select)), request)

        no_result = True
        for tuple in conn:
            no_result = False
            data_tuple = {}

            if tuple[0] != None:
                self.id = str(tuple[0]).zfill(3)
            if tuple[1] != None:
                self.name = tuple[1]
            if tuple[2] != None:
                self.ip = tuple[2]
            if tuple[3] != None:
                self.internal_key = tuple[3]
            if tuple[4] != None:
                self.version = tuple[4]
            if tuple[5] != None:
                self.dateAdd = tuple[5]
            if tuple[6] != None:
                self.lastKeepAlive = tuple[6]
            else:
                self.lastKeepAlive = 0
            if tuple[7] != None:
                self.configSum = tuple[7]
            if tuple[8] != None:
                self.mergedSum = tuple[8]
            if tuple[9] != None:
                self.group = tuple[9]
            if tuple[10] != None:
                self.os['name'] = tuple[10]
            if tuple[11] != None:
                self.os['version'] = tuple[11]
            if tuple[12] != None:
                self.os['major'] = tuple[12]
            if tuple[13] != None:
                self.os['minor'] = tuple[13]
            if tuple[14] != None:
                self.os['codename'] = tuple[14]
            if tuple[15] != None:
                self.os['build'] = tuple[15]
            if tuple[16] != None:
                self.os['platform'] = tuple[16]
            if tuple[17] != None:
                self.os['uname'] = tuple[17]
                if "x86_64" in self.os['uname']:
                    self.os['arch'] = "x86_64"
                elif "i386" in self.os['uname']:
                    self.os['arch'] = "i386"
                elif "i686" in self.os['uname']:
                    self.os['arch'] = "i686"
                elif "sparc" in self.os['uname']:
                    self.os['arch'] = "sparc"
                elif "amd64" in self.os['uname']:
                    self.os['arch'] = "amd64"
                elif "ia64" in self.os['uname']:
                    self.os['arch'] = "ia64"
                elif "AIX" in self.os['uname']:
                    self.os['arch'] = "AIX"
                elif "armv6" in self.os['uname']:
                    self.os['arch'] = "armv6"
                elif "armv7" in self.os['uname']:
                    self.os['arch'] = "armv7"

            if self.id != "000":
                self.status = Agent.calculate_status(self.lastKeepAlive)
            else:
                self.status = 'Active'
                self.ip = '127.0.0.1'

        if no_result:
            raise WazuhException(1701, self.id)

    def get_basic_information(self):
        """
        Gets public attributes of existing agent.
        """
        self._load_info_from_DB()

        info = {}

        if self.id:
            info['id'] = self.id
        if self.name:
            info['name'] = self.name
        if self.ip:
            info['ip'] = self.ip
        #if self.internal_key:
        #    info['internal_key'] = self.internal_key
        if self.os:
            os_no_empty = dict((k, v) for k, v in self.os.items() if v)
            if os_no_empty:
                info['os'] = os_no_empty
        if self.version:
            info['version'] = self.version
        if self.dateAdd:
            info['dateAdd'] = self.dateAdd
        if self.lastKeepAlive:
            info['lastKeepAlive'] = self.lastKeepAlive
        if self.status:
            info['status'] = self.status
        if self.configSum:
            info['configSum'] = self.configSum
        if self.mergedSum:
            info['mergedSum'] = self.mergedSum
        #if self.key:
        #    info['key'] = self.key
        if self.group:
            info['group'] = self.group

        return info

    def get_key(self):
        """
        Gets agent key.

        :return: Agent key.
        """

        self._load_info_from_DB()
        if self.id != "000":
            str_key = "{0} {1} {2} {3}".format(self.id, self.name, self.ip, self.internal_key)
            self.key = b64encode(str_key.encode()).decode()
        else:
            self.key = ""

        return self.key

    def restart(self):
        """
        Restarts the agent.

        :return: Message generated by OSSEC.
        """

        if self.id == "000":
            raise WazuhException(1703)
        else:
            # Check if agent exists and it is active
            agent_info = self.get_basic_information()

            if self.status.lower() != 'active':
                raise WazuhException(1707, '{0} - {1}'.format(self.id, self.status))

            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS, self.id)
            oq.close()

        return ret_msg

    def remove(self, backup=False):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :return: Message.
        """

        manager_status = manager.status()
        if 'ossec-authd' not in manager_status or manager_status['ossec-authd'] != 'running':
            data = self._remove_manual(backup)
        else:
            data = self._remove_authd()

        return data

    def _remove_authd(self):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :return: Message.
        """

        msg = { "function": "remove", "arguments": { "id": str(self.id) } }

        authd_socket = OssecSocket(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _remove_manual(self, backup=False):
        """
        Deletes the agent.
        :param backup: Create backup before removing the agent.
        :return: Message.
        """

        # Get info from DB
        self._load_info_from_DB()

        f_keys_temp = '{0}.tmp'.format(common.client_keys)

        f_tmp = open(f_keys_temp, 'w')
        agent_found = False
        with open(common.client_keys) as f_k:
            for line in f_k.readlines():
                line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                if self.id == line_data[0] and line_data[1][0] not in ('#!'):
                    f_tmp.write('{0} !{1} {2} {3}\n'.format(line_data[0], line_data[1], line_data[2], line_data[3]))
                    agent_found = True
                else:
                    f_tmp.write(line)
        f_tmp.close()

        if not agent_found:
            remove(f_keys_temp)
            raise WazuhException(1701, self.id)

        # Overwrite client.keys
        move(f_keys_temp, common.client_keys)
        root_uid = getpwnam("ossec").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
        chown(common.client_keys, root_uid, ossec_gid)
        chmod(common.client_keys, 0o640)

        # Remove rid file
        rids_file = '{0}/queue/rids/{1}'.format(common.ossec_path, self.id)
        if path.exists(rids_file):
            remove(rids_file)

        if not backup:
            # Remove agent files
            agent_files = []
            agent_files.append('{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/.({1}) {2}->syscheck.cpt'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/syscheck/.({1}) {2}->syscheck-registry.cpt'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.ip))
            agent_files.append('{0}/queue/agent-groups/{1}'.format(common.ossec_path, self.id))

            for agent_file in agent_files:
                if path.exists(agent_file):
                    remove(agent_file)
        else:
            # Create backup directory
            # /var/ossec/backup/agents/yyyy/Mon/dd/id-name-ip[tag]
            date_part = date.today().strftime('%Y/%b/%d')
            main_agent_backup_dir = '{0}/agents/{1}/{2}-{3}-{4}'.format(common.backup_path, date_part, self.id, self.name, self.ip)
            agent_backup_dir = main_agent_backup_dir

            not_agent_dir = True
            i = 0
            while not_agent_dir:
                if path.exists(agent_backup_dir):
                    i += 1
                    agent_backup_dir = '{0}-{1}'.format(main_agent_backup_dir, str(i).zfill(3))
                else:
                    makedirs(agent_backup_dir)
                    chmod_r(agent_backup_dir, 0o750)
                    not_agent_dir = False

            # Move agent file
            agent_files = []
            agent_files.append(['{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.ip), '{0}/agent-info'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/({1}) {2}->syscheck'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/.({1}) {2}->syscheck.cpt'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck.cpt'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/({1}) {2}->syscheck-registry'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck-registry'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/syscheck/.({1}) {2}->syscheck-registry.cpt'.format(common.ossec_path, self.name, self.ip), '{0}/syscheck-registry.cpt'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.ip), '{0}/rootcheck'.format(agent_backup_dir)])
            agent_files.append(['{0}/queue/agent-groups/{1}'.format(common.ossec_path, self.id), '{0}/agent-group'.format(agent_backup_dir)])

            for agent_file in agent_files:
                if path.exists(agent_file[0]) and not path.exists(agent_file[1]):
                    rename(agent_file[0], agent_file[1])

        return 'Agent deleted successfully.'

    def _add(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        manager_status = manager.status()
        if 'ossec-authd' not in manager_status or manager_status['ossec-authd'] != 'running':
            data = self._add_manual(name, ip, id, key, force)
        else:
            data = self._add_authd(name, ip, id, key, force)

        return data

    def _add_authd(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC using authd.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise WazuhException(1709)

        force = force if type(force) == int else int(force)

        msg = ""
        if name and ip:
            if id and key:
                msg = { "function": "add", "arguments": { "name": name, "ip": ip, "force": force } }
            else:
                msg = { "function": "add", "arguments": { "name": name, "ip": ip, "id": id, "key": key, "force": force } }

        authd_socket = OssecSocket(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        self.id = data['id']

    def _add_manual(self, name, ip, id=None, key=None, force=-1):
        """
        Adds an agent to OSSEC manually.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """

        # Check arguments
        if id:
            id = id.zfill(3)

        ip = ip.lower()

        if key and len(key) < 64:
            raise WazuhException(1709)

        force = force if type(force) == int else int(force)

        # Check if ip, name or id exist in client.keys
        last_id = 0
        with open(common.client_keys) as f_k:
            for line in f_k.readlines():
                if not line.strip():  # ignore empty lines
                    continue

                if line[0] in ('# '):  # starts with # or ' '
                    continue

                line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                line_id = int(line_data[0])
                if last_id < line_id:
                    last_id = line_id

                if line_data[1][0] in ('#!'):  # name starts with # or !
                    continue

                check_remove = 0
                if id and id == line_data[0]:
                    raise WazuhException(1708, id)
                if name == line_data[1]:
                    if force < 0:
                        raise WazuhException(1705, name)
                    else:
                        check_remove = 1
                if ip != 'any' and ip == line_data[2]:
                    if force < 0:
                        raise WazuhException(1706, ip)
                    else:
                        check_remove = 2

                if check_remove:
                    if force == 0 or Agent.check_if_delete_agent(line_data[0], force):
                        Agent.remove_agent(line_data[0], backup=True)
                    else:
                        if check_remove == 1:
                            raise WazuhException(1705, name)
                        else:
                            raise WazuhException(1706, ip)

        if not id:
            agent_id = str(last_id + 1).zfill(3)
        else:
            agent_id = id

        if not key:
            # Generate key
            epoch_time = int(time())
            str1 = "{0}{1}{2}".format(epoch_time, name, platform())
            str2 = "{0}{1}".format(ip, agent_id)
            hash1 = md5(str1.encode())
            hash1.update(urandom(64))
            hash2 = md5(str2.encode())
            hash1.update(urandom(64))
            agent_key = hash1.hexdigest() + hash2.hexdigest()
        else:
            agent_key = key

        # Tmp file
        f_keys_temp = '{0}.tmp'.format(common.client_keys)
        copyfile(common.client_keys, f_keys_temp)

        # Write key
        with open(f_keys_temp, 'a') as f_kt:
            f_kt.write('{0} {1} {2} {3}\n'.format(agent_id, name, ip, agent_key))

        # Overwrite client.keys
        move(f_keys_temp, common.client_keys)
        root_uid = getpwnam("ossec").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid
        chown(common.client_keys, root_uid, ossec_gid)
        chmod(common.client_keys, 0o640)

        self.id = agent_id

    @staticmethod
    def get_agents_overview(status="all", os_platform="all", os_version="all", offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of available agents with basic attributes.

        :param status: Filters by agent status: Active, Disconnected or Never connected.
        :param os_platform: Filters by OS platform.
        :param os_version: Filters by OS version.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Query
        query = "SELECT {0} FROM agent"
        fields = {'id': 'id', 'name': 'name', 'ip': 'ip', 'status': 'last_keepalive', 'os.name': 'os_name', 'os.version': 'os_version', 'os.platform': 'os_platform', 'version': 'version' }
        select = ["id", "name", "ip", "last_keepalive", "os_name", "os_version", "os_platform", "version"]
        search_fields = ["id", "name", "ip", "os_name", "os_version", "os_platform"]
        request = {}

        if status != "all":
            limit_seconds = 600*3 + 30
            result = datetime.now() - timedelta(seconds=limit_seconds)
            request['time_active'] = result.strftime('%Y-%m-%d %H:%M:%S')

            if status.lower() == 'active':
                query += ' AND (last_keepalive >= :time_active or id = 0)'
            elif status.lower() == 'disconnected':
                query += ' AND last_keepalive < :time_active'
            elif status.lower() == "never connected":
                query += ' AND last_keepalive IS NULL AND id != 0'

        if os_platform != "all":
            request['os_platform'] = os_platform
            query += ' AND os_platform = :os_platform'
        if os_version != "all":
            request['os_version'] = os_version
            query += ' AND os_version = :os_version'

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " (" + " OR ".join(x + ' LIKE :search' for x in search_fields) + " )"
            request['search'] = '%{0}%'.format(search['value'])

        if "FROM agent AND" in query:
            query = query.replace("FROM agent AND", "FROM agent WHERE")

        # Count
        conn.execute(query.format('COUNT(*)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = []
                for i in sort['fields']:
                    # Order by status ASC is the same that order by last_keepalive DESC.
                    if i == 'status':
                        str_order = "desc" if sort['order'] == 'asc' else "asc"
                        order_str_field = '{0} {1}'.format(fields[i], str_order)
                    # Order by version is order by major and minor
                    elif i == 'os.version':
                        order_str_field = "CAST(os_major AS INTEGER) {0}, CAST(os_minor AS INTEGER) {0}".format(sort['order'])
                    else:
                        order_str_field = '{0} {1}'.format(fields[i], sort['order'])

                    order_str_fields.append(order_str_field)

                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY id {0}'.format(sort['order'])
        else:
            query += ' ORDER BY id ASC'



        query += ' LIMIT :offset,:limit'
        request['offset'] = offset
        request['limit'] = limit

        conn.execute(query.format(','.join(select)), request)

        data['items'] = []

        for tuple in conn:
            data_tuple = {}
            os = {}

            if tuple[0] != None:
                data_tuple['id'] = str(tuple[0]).zfill(3)
            if tuple[1] != None:
                data_tuple['name'] = tuple[1]
            if tuple[2] != None:
                data_tuple['ip'] = tuple[2]

            if tuple[3] != None:
                lastKeepAlive = tuple[3]
            else:
                lastKeepAlive = 0

            if tuple[4] != None:
                os['name'] = tuple[4]
            if tuple[5] != None:
                os['version'] = tuple[5]
            if tuple[6] != None:
                os['platform'] = tuple[6]

            if tuple[7] != None:
                data_tuple['version'] = tuple[7]

            if os:
                os_no_empty = dict((k, v) for k, v in os.items() if v)
                if os_no_empty:
                    data_tuple['os'] = os_no_empty

            if data_tuple['id'] == "000":
                data_tuple['status'] = "Active"
                data_tuple['ip'] = '127.0.0.1'
            else:
                data_tuple['status'] = Agent.calculate_status(lastKeepAlive)

            data['items'].append(data_tuple)

        return data

    @staticmethod
    def get_agents_summary():
        """
        Counts the number of agents by status.

        :return: Dictionary with keys: total, Active, Disconnected, Never connected
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Query
        query_all = "SELECT COUNT(*) FROM agent"

        query = "SELECT COUNT(*) FROM agent WHERE {0}"
        request = {}
        query_active = query.format('(last_keepalive >= :time_active or id = 0)')
        query_disconnected = query.format('last_keepalive < :time_active')
        query_never = query.format('last_keepalive IS NULL AND id != 0')

        limit_seconds = 600*3 + 30
        result = datetime.now() - timedelta(seconds=limit_seconds)
        request['time_active'] = result.strftime('%Y-%m-%d %H:%M:%S')

        conn.execute(query_all)
        total = conn.fetch()[0]

        conn.execute(query_active, request)
        active = conn.fetch()[0]

        conn.execute(query_disconnected, request)
        disconnected = conn.fetch()[0]

        conn.execute(query_never, request)
        never = conn.fetch()[0]

        return {'Total': total, 'Active': active, 'Disconnected': disconnected, 'Never connected': never}

    @staticmethod
    def get_os_summary(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of available OS.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Init query
        query = "SELECT DISTINCT {0} FROM agent WHERE os_platform IS NOT null AND os_platform != ''"
        fields = {'os.platform': 'os_platform'}  # field: db_column
        select = ["os_platform"]
        request = {}

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " ( os_platform LIKE :search )"
            request['search'] = '%{0}%'.format(search['value'])

        # Count
        conn.execute(query.format('COUNT(DISTINCT os_platform)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = ['`{0}` {1}'.format(fields[i], sort['order']) for i in sort['fields']]
                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY os_platform {0}'.format(sort['order'])
        else:
            query += ' ORDER BY os_platform ASC'

        # OFFSET - LIMIT
        if limit:
            query += ' LIMIT :offset,:limit'
            request['offset'] = offset
            request['limit'] = limit

        conn.execute(query.format(','.join(select)), request)

        data['items'] = []
        for tuple in conn:
            if tuple[0] != None:
                data['items'].append(tuple[0])

        return data

    @staticmethod
    def restart_agents(agent_id=None, restart_all=False):
        """
        Restarts an agent or all agents.

        :param agent_id: Agent ID of the agent to restart. Can be a list of ID's.
        :param restart_all: Restarts all agents.

        :return: Message.
        """

        if restart_all:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS)
            oq.close()
            return ret_msg
        else:
            ids = list()
            if isinstance(agent_id, list):
                for id in agent_id:
                    try:
                        Agent(id).restart()
                    except Exception as e:
                        ids.append(create_exception_dic(id, e))
            else:
                try:
                    Agent(agent_id).restart()
                except Exception as e:
                    ids.append(create_exception_dic(agent_id, e))
            if not ids:
                message = 'All selected agents were restarted'
            else:
                message = 'Some agents were not restarted'

            final_dict = {}
            if ids:
                final_dict = {'msg': message, 'ids': ids}
            else:
                final_dict = {'msg': message}

            return final_dict

    @staticmethod
    def get_agent(agent_id):
        """
        Gets an existing agent.

        :param agent_id: Agent ID.
        :return: The agent.
        """

        return Agent(agent_id).get_basic_information()

    @staticmethod
    def get_agent_key(agent_id):
        """
        Get the key of an existing agent.

        :param agent_id: Agent ID.
        :return: Agent key.
        """

        return Agent(agent_id).get_key()

    @staticmethod
    def remove_agent(agent_id, backup=False):
        """
        Removes an existing agent.

        :param agent_id: Agent ID. Can be a list of ID's.
        :param backup: Create backup before removing the agent.
        :return: Message generated by OSSEC.
        """

        ids = []
        if isinstance(agent_id, list):
            for id in agent_id:
                try:
                    Agent(id).remove(backup)
                except Exception as e:
                    ids.append(create_exception_dic(id, e))
        else:
            try:
                Agent(agent_id).remove(backup)
            except Exception as e:
                ids.append(create_exception_dic(agent_id, e))

        if not ids:
            message = 'All selected agents were removed'
        else:
            message = 'Some agents were not removed'

        final_dict = {}
        if ids:
            final_dict = {'msg': message, 'ids': ids}
        else:
            final_dict = {'msg': message}

        return final_dict

    @staticmethod
    def add_agent(name, ip='any', force=-1):
        """
        Adds a new agent to OSSEC.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """

        return Agent(name=name, ip=ip, force=force).id

    @staticmethod
    def insert_agent(name, id, key, ip='any', force=-1):
        """
        Create a new agent providing the id, name, ip and key to the Manager.

        :param id: id of the new agent.
        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param key: name of the new agent.
        :param force: Remove old agent with same IP if disconnected since <force> seconds.
        :return: Agent ID.
        """

        return Agent(name=name, ip=ip, id=id, key=key, force=force).id

    @staticmethod
    def check_if_delete_agent(id, seconds):
        """
        Check if we should remove an agent: if time from last connection is greater thant <seconds>.

        :param id: id of the new agent.
        :param seconds: Number of seconds.
        :return: True if time from last connection is greater thant <seconds>.
        """
        remove_agent = False

        agent_info = Agent(id=id).get_basic_information()

        if 'lastKeepAlive' in agent_info:
            if agent_info['lastKeepAlive'] == 0:
                remove_agent = True
            else:
                last_date = datetime.strptime(agent_info['lastKeepAlive'], '%Y-%m-%d %H:%M:%S')
                difference = (datetime.now() - last_date).total_seconds()
                if difference >= seconds:
                    remove_agent = True

        return remove_agent

    @staticmethod
    def get_all_groups_sql(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets the existing groups.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Init query
        query = "SELECT DISTINCT {0} FROM agent WHERE `group` IS NOT null"
        fields = {'name': 'group'}  # field: db_column
        select = ["`group`"]
        request = {}

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " ( `group` LIKE :search )"
            request['search'] = '%{0}%'.format(search['value'])

        # Count
        conn.execute(query.format('COUNT(DISTINCT `group`)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = ['`{0}` {1}'.format(fields[i], sort['order']) for i in sort['fields']]
                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY `group` {0}'.format(sort['order'])
        else:
            query += ' ORDER BY `group` ASC'

        # OFFSET - LIMIT
        if limit:
            query += ' LIMIT :offset,:limit'
            request['offset'] = offset
            request['limit'] = limit

        # Data query
        conn.execute(query.format(','.join(select)), request)

        data['items'] = []

        for tuple in conn:
            if tuple[0] != None:
                data['items'].append(tuple[0])

        return data

    @staticmethod
    def get_all_groups(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets the existing groups.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        query = "SELECT {0} FROM agent WHERE `group` = :group_id"

        # Group names
        data = []
        for entry in listdir(common.shared_path):
            item = {}

            full_entry = path.join(common.shared_path, entry)
            if not path.isdir(full_entry):
                continue

            item['name'] = entry

            # Group count
            request = {'group_id': item['name']}
            conn.execute(query.format('COUNT(*)'), request)
            item['count'] = conn.fetch()[0]

            data.append(item)


        if search:
            data = search_array(data, search['value'], search['negation'])

        if sort:
            data = sort_array(data, sort['fields'], sort['order'])
        else:
            data = sort_array(data, ['name'])

        return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

    @staticmethod
    def group_exists_sql(group_id):
        """
        Checks if the group exists

        :param group_id: Group ID.
        :return: True if group exists, False otherwise
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        query = "SELECT `group` FROM agent WHERE `group` = :group_id LIMIT 1"
        request = {'group_id': group_id}

        conn.execute(query, request)

        for tuple in conn:

            if tuple[0] != None:
                return True
            else:
                return False

    @staticmethod
    def group_exists(group_id):
        """
        Checks if the group exists

        :param group_id: Group ID.
        :return: True if group exists, False otherwise
        """

        if path.exists("{0}/{1}".format(common.shared_path, group_id)):
            return True
        else:
            return False

    @staticmethod
    def get_agent_group(group_id, offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets the agents in a group

        :param group_id: Group ID.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Init query
        query = "SELECT {0} FROM agent WHERE `group` = :group_id"
        fields = {'id': 'id', 'name': 'name'}  # field: db_column
        select = ['id', 'name']
        request = {'group_id': group_id}

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " (" + " OR ".join(x + ' LIKE :search' for x in ('id', 'name')) + " )"
            request['search'] = '%{0}%'.format(search['value'])

        # Count
        conn.execute(query.format('COUNT(*)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = ['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']]
                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY id {0}'.format(sort['order'])
        else:
            query += ' ORDER BY id ASC'

        # OFFSET - LIMIT
        if limit:
            query += ' LIMIT :offset,:limit'
            request['offset'] = offset
            request['limit'] = limit

        # Data query
        conn.execute(query.format(','.join(select)), request)

        data['items'] = []

        for tuple in conn:
            data_tuple = {}

            if tuple[0] != None:
                data_tuple['id'] = str(tuple[0]).zfill(3)
            if tuple[1] != None:
                data_tuple['name'] = tuple[1]

            data['items'].append(data_tuple)

        return data

    @staticmethod
    def get_group_files(group_id=None, offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets the group files.

        :param group_id: Group ID.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        group_path = common.shared_path
        if group_id:
            if not Agent.group_exists(group_id):
                raise WazuhException(1710, group_id)
            group_path = "{0}/{1}".format(common.shared_path, group_id)

        if not path.exists(group_path):
            raise WazuhException(1006, group_path)

        data = []
        for entry in listdir(group_path):
            item = {}
            item['filename'] = entry
            with open("{0}/{1}".format(group_path, entry), 'rb') as f:
                item['hash'] = md5(f.read()).hexdigest()
            data.append(item)

        # ar.conf
        ar_path = "{0}/ar.conf".format(common.shared_path, entry)
        with open(ar_path, 'rb') as f:
            hash_ar = md5(f.read()).hexdigest()
        data.append({'filename': "../ar.conf", 'hash': hash_ar})

        if search:
            data = search_array(data, search['value'], search['negation'])

        if sort:
            data = sort_array(data, sort['fields'], sort['order'])
        else:
            data = sort_array(data, ["filename"])

        return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

    @staticmethod
    def create_group(group_id):
        """
        Creates a group.

        :param group_id: Group ID.
        :return: Confirmation message.
        """

        group_path = "{0}/{1}".format(common.shared_path, group_id)

        if group_id.lower() == "default" or path.exists(group_path):
            raise WazuhException(1711, group_id)

        ossec_uid = getpwnam("ossec").pw_uid
        ossec_gid = getgrnam("ossec").gr_gid

        # Create group in /etc/shared
        group_def_path = "{0}/default".format(common.shared_path)
        try:
            copytree(group_def_path, group_path)
            chown_r(group_path, ossec_uid, ossec_gid)
            chmod_r(group_path, 0o660)
            chmod(group_path, 0o770)
            msg = "Group '{0}' created.".format(group_id)
        except Exception as e:
            raise WazuhException(1005, str(e))

        return msg

    @staticmethod
    def remove_group(group_id):
        """
        Remove the group in every agent.

        :param group_id: Group ID.
        :return: Confirmation message.
        """

        if group_id.lower() == "default":
            raise WazuhException(1712)

        if not Agent.group_exists(group_id):
            raise WazuhException(1710, group_id)

        ids = []

        # Remove agent group
        agents = Agent.get_agent_group(group_id=group_id, limit=None)
        for agent in agents['items']:
            Agent.unset_group(agent['id'])
            ids.append(agent['id'])

        # Remove group directory
        group_path = "{0}/{1}".format(common.shared_path, group_id)
        group_backup = "{0}/groups/{1}_{2}".format(common.backup_path, group_id, int(time()))
        if path.exists(group_path):
            move(group_path, group_backup)

        msg = "Group '{0}' removed.".format(group_id)

        return {'msg': msg, 'affected_agents': ids}

    @staticmethod
    def set_group(agent_id, group_id, force=False):
        """
        Set a group to an agent.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: No check if agent exists
        :return: Confirmation message.
        """

        agent_id = agent_id.zfill(3)
        if agent_id == "000":
            raise WazuhException(1703)

        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        if group_id.lower() != "default":
            ossec_uid = getpwnam("ossec").pw_uid
            ossec_gid = getgrnam("ossec").gr_gid

            # Assign group in /queue/agent-groups
            agent_group_path = "{0}/{1}".format(common.groups_path, agent_id)
            try:
                new_file = False if path.exists(agent_group_path) else True

                f_group = open(agent_group_path, 'w')
                f_group.write(group_id)
                f_group.close()

                if new_file:
                    chown(agent_group_path, ossec_uid, ossec_gid)
                    chmod(agent_group_path, 0o660)
            except Exception as e:
                raise WazuhException(1005, str(e))

            # Create group in /etc/shared
            if not Agent.group_exists(group_id):
                Agent.create_group(group_id)

        else:
            Agent.unset_group(agent_id)

        return "Group '{0}' set to agent '{1}'.".format(group_id, agent_id)

    @staticmethod
    def unset_group(agent_id, force=False):
        """
        Unset the agent group. The group will be 'default'.

        :param agent_id: Agent ID.
        :param force: No check if agent exists
        :return: Confirmation message.
        """

        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        agent_group_path = "{0}/{1}".format(common.groups_path, agent_id)
        if path.exists(agent_group_path):
            remove(agent_group_path)

        return "Group unset. Current group for agent '{0}': 'default'.".format(agent_id)

    @staticmethod
    def get_outdated_agents(offset=0, limit=common.database_limit, sort=None):
        """
        Gets the outdated agents.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Get manager version
        manager = Agent(id=0)
        manager._load_info_from_DB()
        manager_ver = manager.version

        # Init query
        query = "SELECT {0} FROM agent WHERE version <> :manager_ver AND id <> 0"
        fields = {'id': 'id', 'name': 'name', 'version': 'version'}  # field: db_column
        select = ['id','name','version']
        request = {'manager_ver': manager_ver}

        # Count
        conn.execute(query.format('COUNT(`id`)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = fields.keys()
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = ['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']]
                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY id {0}'.format(sort['order'])
        else:
            query += ' ORDER BY id ASC'

        # OFFSET - LIMIT
        if limit:
            query += ' LIMIT :offset,:limit'
            request['offset'] = offset
            request['limit'] = limit

        # Data query
        conn.execute(query.format(','.join(select)), request)

        data['items'] = []

        for tuple in conn:
            data_tuple = {}

            if tuple[0] != None:
                data_tuple['id'] = str(tuple[0]).zfill(3)
            if tuple[1] != None:
                data_tuple['name'] = tuple[1]
            if tuple[2] != None:
                data_tuple['version'] = tuple[2]

            data['items'].append(data_tuple)

        return data


    def _get_versions(self, wpk_repo=common.wpk_repo_url):
        """
        Generates a list of available versions for its distribution and version.
        """
        if self.os['platform']=="windows":
            versions_url = wpk_repo + "windows/versions"
        else:
            if self.os['platform']=="ubuntu":
                versions_url = wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + self.os['minor'] + "/" + self.os['arch'] + "/versions"
            else:
                versions_url = wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + self.os['arch'] + "/versions"

        try:
            result = urlopen(versions_url)
        except HTTPError as e:
            raise WazuhException(1713, e.code)
        except URLError as e:
            if "SSL23_GET_SERVER_HELLO" in str(e.reason):
              error = "HTTPS requires Python 2.7.9 or newer. You may also run with Python 3."
            else:
              error = str(e.reason)
            raise WazuhException(1713, error)

        lines = result.readlines()
        lines = filter(None, lines)
        versions = []

        for line in lines:
            ver_readed = line.decode().split()
            version = ver_readed[0]
            sha1sum = ver_readed[1] if len(ver_readed) > 1 else ''
            versions.append([version, sha1sum])

        return versions


    def _get_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False):
        """
        Searchs latest Wazuh WPK file for its distribution and version. Downloads the WPK if it is not in the upgrade folder.
        """
        agent_new_ver = None
        if not version:
            versions = self._get_versions(wpk_repo)
            agent_new_ver = versions[0][0]
            agent_new_shasum = versions[0][1]
        else:
            for versions in self._get_versions(wpk_repo):
                if versions[0] == version:
                    agent_new_ver = versions[0]
                    agent_new_shasum = versions[1]
                    break
        if not agent_new_ver:
            raise WazuhException(1718, version)

        # Get manager version
        manager = Agent(id=0)
        manager._load_info_from_DB()
        manager_ver = manager.version
        if debug:
            print("Manager version: {0}".format(manager_ver.split(" ")[1]))

        # Comparing versions
        agent_ver = self.version
        if debug:
            print("Agent version: {0}".format(agent_ver.split(" ")[1]))
            print("Agent new version: {0}".format(agent_new_ver))

        r_manager_ver = manager_ver.split(" ")[1].replace("v","").replace("-","").replace("alpha","a").replace("beta","b")
        r_agent_ver = agent_ver.split(" ")[1].replace("v","").replace("-","").replace("alpha","a").replace("beta","b")
        r_agent_new_ver = agent_new_ver.replace("v","").replace("-","").replace("alpha","a").replace("beta","b")

        if StrictVersion(r_manager_ver) < StrictVersion(r_agent_new_ver):
            raise WazuhException(1717, "Manager: {0} / Agent: {1} -> {2}".format(manager_ver.split(" ")[1], agent_ver.split(" ")[1], agent_new_ver))

        if (StrictVersion(r_agent_ver) >= StrictVersion(r_agent_new_ver) and not force):
            raise WazuhException(1716, "Agent ver: {0} / Agent new ver: {1}".format(agent_ver.split(" ")[1], agent_new_ver))

        if self.os['platform']=="windows":
            wpk_file = "wazuh_agent_{0}_{1}.wpk".format(agent_new_ver, self.os['platform'])
        else:
            if self.os['platform']=="ubuntu":
                wpk_file = "wazuh_agent_{0}_{1}_{2}.{3}_{4}.wpk".format(agent_new_ver, self.os['platform'], self.os['major'], self.os['minor'], self.os['arch'])
            else:
                wpk_file = "wazuh_agent_{0}_{1}_{2}_{3}.wpk".format(agent_new_ver, self.os['platform'], self.os['major'], self.os['arch'])

        wpk_file_path = "{0}/var/upgrade/{1}".format(common.ossec_path, wpk_file)

        # If WPK is already downloaded
        if path.isfile(wpk_file_path):
            # Get SHA1 file sum
            sha1hash = sha1(open(wpk_file_path, 'rb').read()).hexdigest()
            # Comparing SHA1 hash
            if not sha1hash == agent_new_shasum:
                if debug:
                    print("Downloaded file SHA1 does not match (downloaded: {0} / repository: {1})".format(sha1hash, agent_new_shasum))
            else:
                if debug:
                    print("WPK file already downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))
                return [wpk_file, sha1hash]

        # Download WPK file
        if self.os['platform']=="windows":
            wpk_url = wpk_repo + "windows/" + wpk_file
        else:
            if self.os['platform']=="ubuntu":
                wpk_url = wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + self.os['minor'] + "/" + self.os['arch'] + "/" + wpk_file
            else:
                wpk_url = wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + self.os['arch'] + "/" + wpk_file

        if debug:
            print("Downloading WPK file from: {0}".format(wpk_url))
        else:
            print("Downloading WPK file...")

        try:
            result = urlopen(wpk_url)
            with open(wpk_file_path, "wb") as local_file:
                local_file.write(result.read())
        except HTTPError as e:
            raise WazuhException(1714, e.code)
        except URLError as e:
            if "SSL23_GET_SERVER_HELLO" in str(e.reason):
              error = "HTTPS requires Python 2.7.9 or newer. You may also run with Python 3."
            else:
              error = str(e.reason)
            raise WazuhException(1714, error)

        # Get SHA1 file sum
        sha1hash = sha1(open(wpk_file_path, 'rb').read()).hexdigest()

        # Comparing SHA1 hash
        if not sha1hash == agent_new_shasum:
            raise WazuhException(1714)

        if debug:
            print("WPK file downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))
        else:
            print("WPK file downloaded.")

        return [wpk_file, sha1hash]


    def _send_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, show_progress=None):
        """
        Sends WPK file to agent.
        """
        # Check WPK file
        _get_wpk = self._get_wpk_file(wpk_repo, debug, version, force)
        wpk_file = _get_wpk[0]
        file_sha1 = _get_wpk[1]
        wpk_file_size = stat("{0}/var/upgrade/{1}".format(common.ossec_path, wpk_file)).st_size
        if debug:
            print("Upgrade PKG: {0} ({1} KB)".format(wpk_file, wpk_file_size/1024))
        # Open file on agent
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if data != 'ok':
            raise WazuhException(1715, data.replace("err ",""))

        # Sending file to agent
        file = open(common.ossec_path + "/var/upgrade/" + wpk_file, "rb")
        if not file:
            raise WazuhException(1715, data.replace("err ",""))
        if debug:
            print("Sending: {0}".format(common.ossec_path + "/var/upgrade/" + wpk_file))
        try:
            start_time = time()
            bytes_read = file.read(512)
            bytes_read_acum = 0
            while bytes_read:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(common.ossec_path + "/queue/ossec/request")
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.recv(1024).decode()
                s.close()
                if data != 'ok':
                    raise WazuhException(1715, data.replace("err ",""))
                bytes_read = file.read(512)
                if show_progress:
                    bytes_read_acum = bytes_read_acum + len(bytes_read)
                    show_progress(int(bytes_read_acum * 100 / wpk_file_size) + (bytes_read_acum * 100 % wpk_file_size > 0))
            elapsed_time = time() - start_time
        finally:
            file.close()

        # Close file on agent
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com close {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if data != 'ok':
            raise WazuhException(1715, data.replace("err ",""))

        # Get file SHA1 from agent and compare
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com sha1 {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok '):
            raise WazuhException(1715, data.replace("err ",""))
        rcv_sha1 = data.split(' ')[1]
        if rcv_sha1 == file_sha1:
            return ["WPK file sent", wpk_file]
        else:
            raise WazuhException(1715, data.replace("err ",""))


    def upgrade(self, wpk_repo=None, debug=False, version=None, force=False, show_progress=None):
        """
        Upgrade agent using a WPK file.
        """
        if int(self.id) == 0:
            raise WazuhException(1703)

        self._load_info_from_DB()

        ver = self.version.split(" ")[1].replace("v","").replace("-","").replace("alpha","a").replace("beta","b")

        try:
            if not StrictVersion(ver) >= '3.0.0a4':
                raise WazuhException(1719, self.version)
        except ValueError:
            raise WazuhException(1719, self.version)

        if self.os['platform']=="windows" and int(self.os['major']) < 6:
            raise WazuhException(1721, self.os['name'])

        if wpk_repo == None:
            wpk_repo = common.wpk_repo_url

        if not wpk_repo.endswith('/'):
            wpk_repo = wpk_repo + '/'

        # Check if agent is active.
        if not self.status == 'Active':
            raise WazuhException(1720)

        # Send file to agent
        sending_result = self._send_wpk_file(wpk_repo, debug, version, force, show_progress)
        if debug:
            print(sending_result[0])

        # Send upgrading command
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        if self.os['platform']=="windows":
            msg = "{0} com upgrade {1} upgrade.bat".format(str(self.id).zfill(3), sending_result[1])
        else:
            msg = "{0} com upgrade {1} upgrade.sh".format(str(self.id).zfill(3), sending_result[1])
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): started. Current version: {2}".format(str(self.id).zfill(3), self.name, self.version)).encode(), common.ossec_path + "/queue/ossec/queue")
            return "Upgrade procedure started"
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): aborted: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            raise WazuhException(1716, data.replace("err ",""))
        s.close()


    @staticmethod
    def upgrade_agent(agent_id, wpk_repo=None, version=None, force=False):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :return: Upgrade message.
        """

        return Agent(agent_id).upgrade(wpk_repo=wpk_repo, version=version, force=True if int(force)==1 else False)


    def upgrade_result(self, debug=False, timeout=60):
        """
        Read upgrade result output from agent.
        """
        sleep(1)
        self._load_info_from_DB()
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com upgrade_result".format(str(self.id).zfill(3))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(1)
            counter = counter + 1
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(common.ossec_path + "/queue/ossec/request")
            msg = str(self.id).zfill(3) + " com upgrade_result"
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.recv(1024).decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok 0'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): succeeded. New version: {2}".format(str(self.id).zfill(3), self.name, self.version)).encode(), common.ossec_path + "/queue/ossec/queue")
            return "Agent upgraded successfully"
        elif data.startswith('ok 2'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): failed: restored to previous version".format(str(self.id).zfill(3), self.name)).encode(), common.ossec_path + "/queue/ossec/queue")
            raise WazuhException(1716, "Agent restored to previous version")
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): lost: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            raise WazuhException(1716, data.replace("err ",""))
        s.close()


    @staticmethod
    def get_upgrade_result(agent_id, timeout=3):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :return: Upgrade result.
        """

        return Agent(agent_id).upgrade_result(timeout=int(timeout))


    def _send_custom_wpk_file(self, file_path, debug=False, show_progress=None):
        """
        Sends custom WPK file to agent.
        """
        # Check WPK file
        if not path.isfile(file_path):
            raise WazuhException(1006)

        wpk_file = path.basename(file_path)
        wpk_file_size = stat(file_path).st_size
        if debug:
            print("Custom WPK file: {0} ({1} KB)".format(wpk_file, wpk_file_size/1024))

        # Open file on agent
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com open w {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if data != 'ok':
            raise WazuhException(1715, data.replace("err ",""))

        # Sending file to agent
        file = open(file_path, "rb")
        if not file:
            raise WazuhException(1715, data.replace("err ",""))
        try:
            start_time = time()
            bytes_read = file.read(512)
            file_sha1=sha1(bytes_read)
            bytes_read_acum = 0
            while bytes_read:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(common.ossec_path + "/queue/ossec/request")
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.recv(1024).decode()
                s.close()
                bytes_read = file.read(512)
                file_sha1.update(bytes_read)
                if show_progress:
                    bytes_read_acum = bytes_read_acum + len(bytes_read)
                    show_progress(int(bytes_read_acum * 100 / wpk_file_size) + (bytes_read_acum * 100 % wpk_file_size > 0))
            elapsed_time = time() - start_time
            calc_sha1 = file_sha1.hexdigest()
            if debug:
                print("FILE SHA1: {0}".format(calc_sha1))
        finally:
            file.close()

        # Close file on agent
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com close {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if data != 'ok':
            raise WazuhException(1715, data.replace("err ",""))

        # Get file SHA1 from agent and compare
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com sha1 {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok '):
            raise WazuhException(1715, data.replace("err ",""))
        rcv_sha1 = data.split(' ')[1]
        if calc_sha1 == rcv_sha1:
            return ["WPK file sent", wpk_file]
        else:
            raise WazuhException(1715, data.replace("err ",""))


    def upgrade_custom(self, file_path, installer, debug=False, show_progress=None):
        """
        Upgrade agent using a custom WPK file.
        """
        self._load_info_from_DB()

        # Check if agent is active.
        if not self.status == 'Active':
            raise WazuhException(1720)

        # Send file to agent
        sending_result = self._send_custom_wpk_file(file_path, debug, show_progress)
        if debug:
            print(sending_result[0])

        # Send installing command
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com upgrade {1} {2}".format(str(self.id).zfill(3), sending_result[1], installer)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok'):
            s.sendto(("1:wazuh-upgrade:wazuh: Custom installation on agent {0} ({1}): started.".format(str(self.id).zfill(3), self.name)).encode(), common.ossec_path + "/queue/ossec/queue")
            return "Installation started"
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Custom installation on agent {0} ({1}): aborted: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            raise WazuhException(1716, data.replace("err ",""))
        s.close()


    @staticmethod
    def upgrade_agent_custom(agent_id, file_path=None, installer=None):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :return: Upgrade message.
        """
        if not file_path or not installer:
            raise WazuhException(1307)

        return Agent(agent_id).upgrade_custom(file_path=file_path, installer=installer)
