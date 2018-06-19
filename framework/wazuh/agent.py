#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array, chmod_r, chown_r, WazuhVersion, plain_dict_to_nested_dict, get_fields_to_nest
from wazuh.exception import WazuhException
from wazuh.ossec_queue import OssecQueue
from wazuh.ossec_socket import OssecSocket
from wazuh.database import Connection
from wazuh.wdb import WazuhDBConnection
from wazuh.InputValidator import InputValidator
from wazuh import manager
from wazuh import common
from glob import glob
from datetime import date, datetime, timedelta
from base64 import b64encode
from shutil import copyfile, move, copytree
from platform import platform
from os import remove, chown, chmod, path, makedirs, rename, urandom, listdir, stat
from time import time, sleep
import socket
import hashlib
from operator import setitem
import re
import fcntl
from json import loads

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
    exception_dic['error'] = {'message': e.message}

    if isinstance(e, WazuhException):
        exception_dic['error']['code'] = e.code
    else:
        exception_dic['error']['code'] = 1000


    return exception_dic


def get_timeframe_in_seconds(timeframe):
    """
    Gets number of seconds from a timeframe.
    :param timeframe: Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s".

    :return: Time in seconds.
    """
    if not timeframe.isdigit():
        regex = re.compile('(\d*)(\w)$')
        g = regex.findall(timeframe)
        number = int(g[0][0])
        unit = g[0][1]
        time_equivalence_seconds = {'d': 86400, 'h': 3600, 'm': 60, 's':1}
        seconds = number * time_equivalence_seconds[unit]
    else:
        seconds = int(timeframe)

    return seconds


class Agent:
    """
    OSSEC Agent object.
    """

    fields = {'id': 'id', 'name': 'name', 'ip': 'ip', 'status': 'status',
              'os.name': 'os_name', 'os.version': 'os_version', 'os.platform': 'os_platform',
              'version': 'version', 'manager_host': 'manager_host', 'dateAdd': 'date_add',
              'group': '`group`', 'mergedSum': 'merged_sum', 'configSum': 'config_sum',
              'os.codename': 'os_codename', 'os.major': 'os_major', 'os.minor': 'os_minor',
              'os.uname': 'os_uname', 'os.arch': 'os_arch', 'os.build':'os_build',
              'node_name': 'node_name', 'lastKeepAlive': 'last_keepalive', 'key':'key'}


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
        self.manager_host  = None

        # if the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name != None and ip != None:
            self._add(name=name, ip=ip, id=id, key=key, force=force)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os, 'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive, 'status': self.status, 'key': self.key, 'configSum': self.configSum, 'mergedSum': self.mergedSum, 'group': self.group, 'manager_host': self.manager_host }

        return dictionary

    @staticmethod
    def calculate_status(last_keep_alive, pending, today=datetime.today()):
        """
        Calculates state based on last keep alive
        """
        if not last_keep_alive:
            return "Never connected"
        else:
            limit_seconds = 1830 # 600*3 + 30
            # divide date in format YY:mm:dd HH:MM:SS to create a datetime object.
            last_date = datetime(year=int(last_keep_alive[:4]), month=int(last_keep_alive[5:7]), day=int(last_keep_alive[8:10]),
                                hour=int(last_keep_alive[11:13]), minute=int(last_keep_alive[14:16]), second=int(last_keep_alive[17:19]))
            difference = (today - last_date).total_seconds()

            return "Disconnected" if difference > limit_seconds else ("Pending" if pending else "Active")


    def _load_info_from_DB(self, select=None):
        """
        Gets attributes of existing agent.
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        pending = True

        # Query
        query = "SELECT {0} FROM agent WHERE id = :id"
        request = {'id': self.id}

        valid_select_fields = set(self.fields.values())

        # Select
        if select:
            select['fields'] = list(map(lambda x: self.fields[x] if x in self.fields else x, select['fields']))
            select_fields_set = set(select['fields'])
            if not select_fields_set.issubset(valid_select_fields):
                incorrect_fields = list(map(lambda x: str(x), select_fields_set - valid_select_fields))
                raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                        format(self.fields.keys(), incorrect_fields))

            # to compute the status field, lastKeepAlive and version are necessary
            select_fields = {'id'} | select_fields_set if 'status' not in select_fields_set \
                                                       else select_fields_set | {'id', 'last_keepalive', 'version'}
        else:
            select_fields = valid_select_fields

        select_fields = list(select_fields)
        try:
            select_fields[select_fields.index("group")] = "`group`"
        except ValueError as e:
            pass

        conn.execute(query.format(','.join(select_fields)), request)
        db_data = conn.fetch()
        if db_data is None:
            raise WazuhException(1701)

        no_result = True
        for field,value in zip(select_fields, db_data):
            no_result = False

            if field == 'id' and value != None:
                self.id = str(value).zfill(3)
            if field == 'name' and value != None:
                self.name = value
            if field == 'ip' and value != None:
                self.ip = value
            if field == 'key' and value != None:
                self.internal_key = value
            if field == 'version' and value != None:
                self.version = value
                pending = False if self.version != "" else True
            if field == 'date_add' and value != None:
                self.dateAdd = value
            if field == 'last_keepalive':
                if value != None:
                    self.lastKeepAlive = value
                else:
                    self.lastKeepAlive = 0
            if field == 'config_sum' and value != None:
                self.configSum = value
            if field == 'merged_sum' and value != None:
                self.mergedSum = value
            if field == '`group`' and value != None:
                self.group = value
            if field == 'manager_host' and value != None:
                self.manager_host = value
            if field == 'os_name' and value != None:
                self.os['name'] = value
            if field == 'os_version' and value != None:
                self.os['version'] = value
            if field == 'os_major' and value != None:
                self.os['major'] = value
            if field == 'os_minor' and value != None:
                self.os['minor'] = value
            if field == 'os_codename' and value != None:
                self.os['codename'] = value
            if field == 'os_build' and value != None:
                self.os['build'] = value
            if field == 'os_platform' and value != None:
                self.os['platform'] = value
            if field == 'os_uname' and value != None:
                self.os['uname'] = value
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
            self.status = Agent.calculate_status(self.lastKeepAlive, pending)
        else:
            self.status = 'Active'
            self.ip = '127.0.0.1' if 'ip' in select_fields else None

        if no_result:
            raise WazuhException(1701, self.id)


    def _load_info_from_agent_db(self, table, select, filters={}, count=False, offset=0, limit=common.database_limit, sort={}, search={}):
        """
        Make a request to agent's database using Wazuh DB

        :param table: DB table to retrieve data from
        :param select: DB fields to retrieve
        :param filters: filter conditions
        :param sort: Dictionary of form {'fields':[], 'order':'asc'}/{'fields':[], 'order':'desc'}
        :param search: Dictionary of form {'value': '', 'negation':false, 'fields': []}
        """
        wdb_conn = WazuhDBConnection()

        query = "agent {} sql select {} from {}".format(self.id, ','.join(select), table)

        if filters:
            for key, value in filters.items():
                query += " and {} = '{}'".format(key, value)

        if search:
            query += " and not" if bool(search['negation']) else " and"
            query += '(' + " or ".join("{} like '%{}%'".format(x, search['value']) for x in search['fields']) + ')'

        if "from {} and".format(table) in query:
            query = query.replace("from {} and".format(table), "from {} where".format(table))

        if limit:
            query += ' limit {} offset {}'.format(limit, offset)

        if sort and sort['fields']:
            str_order = "desc" if sort['order'] == 'asc' else "asc"
            order_str_fields = []
            for field in sort['fields']:
                order_str_field = '{0} {1}'.format(field, str_order)
                order_str_fields.append(order_str_field)
            query += ' order by ' + ','.join(order_str_fields)

        return wdb_conn.execute(query, count)


    def get_basic_information(self, select=None):
        """
        Gets public attributes of existing agent.
        """
        self._load_info_from_DB(select)

        select_fields = {'id', 'last_keepalive', 'status', 'version'} if select is None else select['fields']

        info = {}

        if self.id and 'id' in select_fields:
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
        if self.version and 'version' in select_fields:
            info['version'] = self.version
        if self.dateAdd:
            info['dateAdd'] = self.dateAdd
        if self.lastKeepAlive and 'last_keepalive' in select_fields:
            info['lastKeepAlive'] = self.lastKeepAlive
        if self.status and 'status' in select_fields:
            info['status'] = self.status
        if self.configSum:
            info['configSum'] = self.configSum
        if self.mergedSum:
            info['mergedSum'] = self.mergedSum
        #if self.key:
        #    info['key'] = self.key
        if self.group:
            info['group'] = self.group
        if self.manager_host:
            info['manager_host'] = self.manager_host

        return info

    def compute_key(self):
        str_key = "{0} {1} {2} {3}".format(self.id, self.name, self.ip, self.internal_key)
        return b64encode(str_key.encode()).decode()


    def get_key(self):
        """
        Gets agent key.

        :return: Agent key.
        """

        self._load_info_from_DB()
        if self.id != "000":
            self.key = self.compute_key()
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

    def use_only_authd(self):
        """
        Function to know the value of the option "use_only_authd" in API configuration
        """
        try:
            with open(common.api_config_path) as f:
                data = f.readlines()

            use_only_authd = list(filter(lambda x: x.strip().startswith('config.use_only_authd'), data))

            return loads(use_only_authd[0][:-2].strip().split(' = ')[1]) if use_only_authd != [] else False
        except IOError:
            return False

    def remove(self, backup=False, purge=False):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        manager_status = manager.status()
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if self.use_only_authd():
            if not is_authd_running:
                raise WazuhException(1726)

        if not is_authd_running:
            data = self._remove_manual(backup, purge)
        else:
            data = self._remove_authd(purge)

        return data

    def _remove_authd(self, purge=False):
        """
        Deletes the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        msg = { "function": "remove", "arguments": { "id": str(self.id).zfill(3), "purge": purge } }

        authd_socket = OssecSocket(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _remove_manual(self, backup=False, purge=False):
        """
        Deletes the agent.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """

        # Get info from DB
        self._load_info_from_DB()

        f_keys_temp = '{0}.tmp'.format(common.client_keys)
        open(f_keys_temp, 'a').close()

        f_keys_st = stat(common.client_keys)
        chown(f_keys_temp, common.ossec_uid, common.ossec_gid)
        chmod(f_keys_temp, f_keys_st.st_mode)

        f_tmp = open(f_keys_temp, 'w')
        agent_found = False
        with open(common.client_keys) as f_k:
            for line in f_k.readlines():
                line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                if self.id == line_data[0] and line_data[1][0] not in ('#!'):
                    if not purge:
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
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if self.use_only_authd():
            if not is_authd_running:
                raise WazuhException(1726)

        if not is_authd_running:
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

        self.id  = data['id']
        self.internal_key = data['key']
        self.key = self.compute_key()


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

        # Check manager name
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        conn.execute("SELECT name FROM agent WHERE (id = 0)")
        manager_name = str(conn.fetch()[0])

        if name == manager_name:
            raise WazuhException(1705, name)

        # Check if ip, name or id exist in client.keys
        last_id = 0
        lock_file = open("{}/var/run/.api_lock".format(common.ossec_path), 'a+')
        fcntl.lockf(lock_file, fcntl.LOCK_EX)
        with open(common.client_keys) as f_k:
            try:
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
                    hash1 = hashlib.md5(str1.encode())
                    hash1.update(urandom(64))
                    hash2 = hashlib.md5(str2.encode())
                    hash1.update(urandom(64))
                    agent_key = hash1.hexdigest() + hash2.hexdigest()
                else:
                    agent_key = key

                # Tmp file
                f_keys_temp = '{0}.tmp'.format(common.client_keys)
                open(f_keys_temp, 'a').close()

                f_keys_st = stat(common.client_keys)
                chown(f_keys_temp, common.ossec_uid, common.ossec_gid)
                chmod(f_keys_temp, f_keys_st.st_mode)

                copyfile(common.client_keys, f_keys_temp)


                # Write key
                with open(f_keys_temp, 'a') as f_kt:
                    f_kt.write('{0} {1} {2} {3}\n'.format(agent_id, name, ip, agent_key))

                # Overwrite client.keys
                move(f_keys_temp, common.client_keys)
            except WazuhException as ex:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise ex
            except Exception as ex:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise WazuhException(1725, str(ex))


            fcntl.lockf(lock_file, fcntl.LOCK_UN)
            lock_file.close()

        self.id = agent_id
        self.internal_key = agent_key
        self.key = self.compute_key()


    def _remove_single_group(self, group_id):
        """
        Remove the group in every agent.

        :param group_id: Group ID.
        :return: Confirmation message.
        """

        if group_id.lower() == "default":
            raise WazuhException(1712)

        if not self.group_exists(group_id):
            raise WazuhException(1710, group_id)

        ids = []

        # Remove agent group
        agents = self.get_agent_group(group_id=group_id, limit=None)
        for agent in agents['items']:
            self.unset_group(agent['id'])
            ids.append(agent['id'])

        # Remove group directory
        group_path = "{0}/{1}".format(common.shared_path, group_id)
        group_backup = "{0}/groups/{1}_{2}".format(common.backup_path, group_id, int(time()))
        if path.exists(group_path):
            move(group_path, group_backup)

        msg = "Group '{0}' removed.".format(group_id)

        return {'msg': msg, 'affected_agents': ids}


    def get_agent_attr(self, attr):
        """
        Returns a string with an agent's os name
        """
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        query = "SELECT :attr FROM agent WHERE id = :id"
        request = {'attr':attr, 'id': self.id}
        conn.execute(query, request)
        query_value = str(conn.fetch()[0])

        return query_value


    @staticmethod
    def get_agents_dict(conn, select_fields, user_select_fields):
        db_api_name = {v:k for k,v in Agent.fields.items()}
        fields_to_nest, non_nested = get_fields_to_nest(db_api_name.values(), ['os'], '.')

        agent_items = [{db_api_name[field]:value for field,value in zip(select_fields, db_tuple) if value is not None} for db_tuple in conn]

        if 'status' in user_select_fields:
            today = datetime.today()
            agent_items = [dict(item, id=str(item['id']).zfill(3), status=Agent.calculate_status(item.get('lastKeepAlive'), item.get('version') is None, today)) for item in agent_items]
        else:
            agent_items = [dict(item, id=str(item['id']).zfill(3)) for item in agent_items]

        if len(agent_items) > 0 and agent_items[0]['id'] == '000' and 'ip' in user_select_fields:
            agent_items[0]['ip'] = '127.0.0.1'

        agent_items = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['os'], '.') for d in agent_items]

        return agent_items


    @staticmethod
    def filter_agents_by_status(status, request, query):
        limit_seconds = 1830  # 600*3 + 30
        result = datetime.now() - timedelta(seconds=limit_seconds)
        request['time_active'] = result.strftime('%Y-%m-%d %H:%M:%S')
        list_status = status.split(',')
        query += ' AND ('

        for status in list_status:
            status = status.lower()
            if status == 'active':
                query += '((last_keepalive >= :time_active AND version IS NOT NULL) or id = 0) OR '
            elif status == 'disconnected':
                query += 'last_keepalive < :time_active OR '
            elif status == "never connected" or status == "neverconnected":
                query += 'last_keepalive IS NULL AND id != 0 OR '
            elif status == 'pending':
                query += 'last_keepalive IS NOT NULL AND version IS NULL OR '
            else:
                raise WazuhException(1729, status)
        query = query[:-3] + ")"  # Remove the last OR from query

        return query


    @staticmethod
    def filter_agents_by_timeframe(older_than, request, query):
        request['older_than'] = get_timeframe_in_seconds(older_than)
        query += " AND ("
        # If the status is not neverconnected, compare older_than with the last keepalive:
        query += "(last_keepalive IS NOT NULL AND CAST(strftime('%s', last_keepalive) AS INTEGER) < CAST(strftime('%s', 'now', 'localtime') AS INTEGER) - :older_than) "
        query += "OR "
        # If the status is neverconnected, compare older_than with the date add:
        query += "(last_keepalive IS NULL AND id != 0 AND CAST(strftime('%s', date_Add) AS INTEGER) < CAST(strftime('%s', 'now', 'localtime') AS INTEGER) - :older_than) "
        query += ")"
        return query


    @staticmethod
    def filter_query(filters, request, query):
        """
        Add filters to a database query

        :param filters: Dictionary which key is the name of the field and the value is the value to filter.
        :param request: Request dictionary for sqlite3
        :param query: Database query
        :return: Updated database query
        """
        for filter_name, db_filter in filters.items():
            if db_filter == "all":
                continue

            if filter_name == "status":
                # doesn't do += because query is a parameter of the function
                query = Agent.filter_agents_by_status(db_filter, request, query)
            elif filter_name == "older_than":
                # doesn't do += because query is a parameter of the function
                query = Agent.filter_agents_by_timeframe(db_filter, request, query)
            else:
                main_filter_name = filter_name if filter_name != "group" else "`group`"
                if isinstance(db_filter, list):
                    filter_list = [name.lower() if filter_name != "version"
                                                else re.sub( r'([a-zA-Z])([v])', r'\1 \2', name)
                                  for name in db_filter]
                    query += ' AND {} COLLATE NOCASE IN ({})'.format(main_filter_name,
                        ','.join([":{}{}".format(filter_name, x) for x in range(len(filter_list))]))
                    key_list = [":{}{}".format(filter_name, x) for x in range(len(filter_list))]
                    request.update({x[1:]: y for x, y in zip(key_list, filter_list)})
                else: # str
                    request[filter_name] = db_filter if filter_name != "version" else re.sub( r'([a-zA-Z])([v])', r'\1 \2', db_filter)
                    query += ' AND {} = :{}'.format(main_filter_name, filter_name)

        return query


    @staticmethod
    def get_agents_overview(offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}):
        """
        Gets a list of available agents with basic attributes.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}

        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])

        # Query
        query = "SELECT {0} FROM agent"

        valid_select_fields = set(Agent.fields.values()) | {'status'}
        # at least, we should retrieve those fields since other fields depending on those
        search_fields = {"id", "name", "ip", "os_name", "os_version", "os_platform", "manager_host", "version",
                         "`group`", "node_name"}
        request = {}
        if select:
            select['fields'] = list(map(lambda x: Agent.fields[x] if x in Agent.fields else x, select['fields']))

            if not set(select['fields']).issubset(valid_select_fields):
                incorrect_fields = list(map(lambda x: str(x), set(select['fields']) - valid_select_fields))
                raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                                    format(Agent.fields.keys(), incorrect_fields))

            select_fields_set = set(select['fields'])
            min_select_fields = {'id'} | select_fields_set if 'status' not in select_fields_set\
                                        else select_fields_set | {'id', 'last_keepalive', 'version'}
        else:
            min_select_fields = valid_select_fields

        # save the fields that the user has selected
        user_select_fields = (set(select['fields']) if select else min_select_fields.copy()) | {'id'}

        # add special filters to the database query
        query = Agent.filter_query(filters, request, query)

        # Search
        if search:
            search['value'] = re.sub( r'([Wazuh])([v])', r'\1 \2', search['value'] )
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " (" + " id LIKE :search_id"
            query += " OR " + " OR ".join(x + ' LIKE :search' for x in (search_fields - {"id"})) + " )"
            request['search'] = '%{0}%'.format(search['value'])
            request['search_id'] = '%{0}%'.format(int(search['value']) if search['value'].isdigit()
                                                                    else search['value'])

        if "FROM agent AND" in query:
            query = query.replace("FROM agent AND", "FROM agent WHERE")

        # Count
        conn.execute(query.format('COUNT(*)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = set(Agent.fields.keys())
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

                order_str_fields = []
                for i in sort['fields']:
                    # Order by status ASC is the same that order by last_keepalive DESC.
                    if i == 'status':
                        str_order = "desc" if sort['order'] == 'asc' else "asc"
                        order_str_field = '{0} {1}'.format(Agent.fields[i], str_order)
                    # Order by version is order by major and minor
                    elif i == 'os.version':
                        order_str_field = "CAST(os_major AS INTEGER) {0}, CAST(os_minor AS INTEGER) {0}".format(sort['order'])
                    else:
                        order_str_field = '{0} {1}'.format(Agent.fields[i], sort['order'])

                    order_str_fields.append(order_str_field)

                query += ' ORDER BY ' + ','.join(order_str_fields)
            else:
                query += ' ORDER BY id {0}'.format(sort['order'])
        else:
            query += ' ORDER BY id ASC'


        if limit:
            query += ' LIMIT :offset,:limit'
            request['offset'] = offset
            request['limit'] = limit

        conn.execute(query.format(','.join(min_select_fields)), request)

        data['items'] = Agent.get_agents_dict(conn, min_select_fields, user_select_fields)

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
            failed_ids = list()
            affected_agents = list()
            if isinstance(agent_id, list):
                for id in agent_id:
                    try:
                        Agent(id).restart()
                        affected_agents.append(id)
                    except Exception as e:
                        failed_ids.append(create_exception_dic(id, e))
            else:
                try:
                    Agent(agent_id).restart()
                    affected_agents.append(agent_id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(agent_id, e))
            if not failed_ids:
                message = 'All selected agents were restarted'
            else:
                message = 'Some agents were not restarted'

            final_dict = {}
            if failed_ids:
                final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
            else:
                final_dict = {'msg': message, 'affected_agents': affected_agents}

            return final_dict

    @staticmethod
    def get_agent_by_name(agent_name, select=None):
        """
        Gets an existing agent called agent_name.

        :param agent_name: Agent name.
        :return: The agent.
        """
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        conn.execute("SELECT id FROM agent WHERE name = :name", {'name': agent_name})
        try:
            agent_id = str(conn.fetch()[0]).zfill(3)
        except TypeError as e:
            raise WazuhException(1701, agent_name)

        return Agent(agent_id).get_basic_information(select)

    @staticmethod
    def get_agent(agent_id, select=None):
        """
        Gets an existing agent.

        :param agent_id: Agent ID.
        :return: The agent.
        """

        return Agent(agent_id).get_basic_information(select)

    @staticmethod
    def get_agent_key(agent_id):
        """
        Get the key of an existing agent.

        :param agent_id: Agent ID.
        :return: Agent key.
        """

        return Agent(agent_id).get_key()

    @staticmethod
    def remove_agent(agent_id, backup=False, purge=False):
        """
        Removes an existing agent.

        :param agent_id: Agent ID.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Dictionary with affected_agents (agents removed), failed_ids if it necessary (agents that cannot been removed), and a message.
        """

        failed_ids = []
        affected_agents = []
        try:
            Agent(agent_id).remove(backup, purge)
            affected_agents.append(agent_id)
        except Exception as e:
            failed_ids.append(create_exception_dic(agent_id, e))

        if not failed_ids:
            message = 'All selected agents were removed'
        else:
            message = 'Some agents were not removed'

        final_dict = {}
        if failed_ids:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids}
        else:
            final_dict = {'msg': message, 'affected_agents': affected_agents}

        return final_dict

    @staticmethod
    def remove_agents(list_agent_ids="all", backup=False, purge=False, status="all", older_than="7d"):
        """
        Removes an existing agent.

        :param list_agent_ids: List of agents ID's.
        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :param older_than:  Filters out disconnected agents for longer than specified. Time in seconds | "[n_days]d" | "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s". For never connected agents, uses the register date.
        :param status: Filters by agent status: Active, Disconnected or Never connected. Multiples statuses separated by commas.
        :return: Dictionary with affected_agents (agents removed), timeframe applied, failed_ids if it necessary (agents that cannot been removed), and a message.
        """


        agents = Agent.get_agents_overview(filters={'status':status, 'older_than': older_than}, limit = None)

        id_purgeable_agents = [agent['id'] for agent in agents['items']]

        failed_ids = []
        affected_agents = []

        if list_agent_ids != "all":
            for id in list_agent_ids:
                try:
                    if id not in id_purgeable_agents:
                        raise WazuhException(1731, "The agent has a status different to '{}' or the specified time frame 'older_than {}' does not apply.".format(status, older_than))
                    Agent(id).remove(backup, purge)
                    affected_agents.append(id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))
        else:
            for id in id_purgeable_agents:
                try:
                    Agent(id).remove(backup, purge)
                    affected_agents.append(id)
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))

        if not failed_ids:
            message = 'All selected agents were removed'
        else:
            message = 'Some agents were not removed'

        if failed_ids:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'failed_ids': failed_ids,
                          'older_than': older_than, 'total_affected_agents':len(affected_agents),
                          'total_failed_ids':len(failed_ids)}
        else:
            final_dict = {'msg': message, 'affected_agents': affected_agents, 'older_than': older_than,
                          'total_affected_agents':len(affected_agents)}

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

        new_agent = Agent(name=name, ip=ip, force=force)
        return {'id': new_agent.id, 'key': new_agent.key}

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

        new_agent = Agent(name=name, ip=ip, id=id, key=key, force=force)
        return {'id': new_agent.id, 'key': key}

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
    def get_all_groups(offset=0, limit=common.database_limit, sort=None, search=None, hash_algorithm='md5'):
        """
        Gets the existing groups.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        def get_hash(file, hash_algorithm='md5'):
            filename = "{0}/{1}".format(common.shared_path, file)

            # check hash algorithm
            try:
                algorithm_list = hashlib.algorithms_available
            except Exception as e:
                algorithm_list = hashlib.algorithms

            if not hash_algorithm in algorithm_list:
                raise WazuhException(1723, "Available algorithms are {0}.".format(algorithm_list))

            hashing = hashlib.new(hash_algorithm)

            try:
                with open(filename, 'rb') as f:
                    hashing.update(f.read())
            except IOError:
                return None

            return hashing.hexdigest()

        # Connect DB
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhException(1600)

        conn = Connection(db_global[0])
        query = "SELECT {0} FROM agent WHERE `group` = :group_id"

        # Group names
        data = []
        for entry in listdir(common.shared_path):
            full_entry = path.join(common.shared_path, entry)
            if not path.isdir(full_entry):
                continue

            # Group count
            request = {'group_id': entry}
            conn.execute(query.format('COUNT(*)'), request)

            # merged.mg and agent.conf sum
            merged_sum = get_hash(entry + "/merged.mg", hash_algorithm)
            conf_sum   = get_hash(entry + "/agent.conf", hash_algorithm)

            item = {'count':conn.fetch()[0], 'name': entry}

            if merged_sum:
                item['merged_sum'] = merged_sum

            if conf_sum:
                item['conf_sum'] = conf_sum

            data.append(item)


        if search:
            data = search_array(data, search['value'], search['negation'], fields=['name'])

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
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

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
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        if path.exists("{0}/{1}".format(common.shared_path, group_id)):
            return True
        else:
            return False

    @staticmethod
    def get_agent_group(group_id, offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}):
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
        valid_select_fiels = set(Agent.fields.values()) | {'status'}
        search_fields = {"id", "name", "os_name", "ip", "status", "version", "os_platform", "manager_host"}

        # Init query
        query = "SELECT {0} FROM agent WHERE `group` = :group_id" if group_id is not None else "SELECT {0} FROM agent WHERE `group` IS NULL AND id != 0"
        request = {'group_id': group_id}

        # Select
        if select:
            select['fields'] = list(map(lambda x: Agent.fields[x] if x in Agent.fields else x, select['fields']))
            select_fields_param = set(select['fields'])

            if not select_fields_param.issubset(valid_select_fiels):
                uncorrect_fields = select_fields_param - valid_select_fiels
                raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                        format(', '.join(list(valid_select_fiels)), ', '.join(uncorrect_fields)))

            select_fields = {'id'} | select_fields_param if 'status' not in select_fields_param \
                                                         else select_fields_param | {'id', 'last_keepalive', 'version'}
        else:
            select_fields = valid_select_fiels

        # save the fields that the user has selected
        user_select_fields = (set(select['fields']) if select else select_fields.copy()) | {'id'}

        query = Agent.filter_query(filters, request, query)

        # Search
        if search:
            query += " AND NOT" if bool(search['negation']) else ' AND'
            query += " (" + " OR ".join(x + ' LIKE :search' for x in search_fields) + " )"
            request['search'] = '%{0}%'.format(int(search['value']) if search['value'].isdigit()
                                                                    else search['value'])

        # Count
        conn.execute(query.format('COUNT(*)'), request)
        data = {'totalItems': conn.fetch()[0]}

        # Sorting
        if sort:
            if sort['fields']:
                allowed_sort_fields = set(Agent.fields.keys())
                # Check if every element in sort['fields'] is in allowed_sort_fields.
                if not set(sort['fields']).issubset(allowed_sort_fields):
                    raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.\
                        format(allowed_sort_fields, sort['fields']))

                order_str_fields = ['{0} {1}'.format(Agent.fields[i], sort['order']) for i in sort['fields']]
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

        if 'group' in select_fields:
            select_fields.remove('group')
            select_fields.add('`group`')

        # Data query
        conn.execute(query.format(','.join(select_fields)), request)

        data['items'] = Agent.get_agents_dict(conn, select_fields, user_select_fields)

        return data


    @staticmethod
    def get_agents_without_group(offset=0, limit=common.database_limit, sort=None, search=None, select=None, filters={}):
        """
        Gets the agents in a group

        :param group_id: Group ID.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Agent.get_agent_group(group_id=None, offset=offset, limit=limit, sort=sort, search=search, select=select,
                                     filters=filters)


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

        try:
            data = []
            for entry in listdir(group_path):
                item = {}
                try:
                    item['filename'] = entry
                    with open("{0}/{1}".format(group_path, entry), 'rb') as f:
                        item['hash'] = hashlib.md5(f.read()).hexdigest()
                    data.append(item)
                except (OSError, IOError) as e:
                    pass

            try:
                # ar.conf
                ar_path = "{0}/ar.conf".format(common.shared_path, entry)
                with open(ar_path, 'rb') as f:
                    hash_ar = hashlib.md5(f.read()).hexdigest()
                data.append({'filename': "ar.conf", 'hash': hash_ar})
            except (OSError, IOError) as e:
                pass

            if search:
                data = search_array(data, search['value'], search['negation'])

            if sort:
                data = sort_array(data, sort['fields'], sort['order'])
            else:
                data = sort_array(data, ["filename"])

            return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}
        except Exception as e:
            raise WazuhException(1727, str(e))


    @staticmethod
    def create_group(group_id):
        """
        Creates a group.

        :param group_id: Group ID.
        :return: Confirmation message.
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        group_path = "{0}/{1}".format(common.shared_path, group_id)

        if group_id.lower() == "default" or path.exists(group_path):
            raise WazuhException(1711, group_id)

        # Create group in /etc/shared
        group_def_path = "{0}/default".format(common.shared_path)
        try:
            copytree(group_def_path, group_path)
            chown_r(group_path, common.ossec_uid, common.ossec_gid)
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

        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)


        failed_ids = []
        ids = []
        affected_agents = []
        if isinstance(group_id, list):
            for id in group_id:

                if id.lower() == "default":
                    raise WazuhException(1712)

                try:
                    removed = Agent()._remove_single_group(id)
                    ids.append(id)
                    affected_agents += removed['affected_agents']
                except Exception as e:
                    failed_ids.append(create_exception_dic(id, e))
        else:
            if group_id.lower() == "default":
                raise WazuhException(1712)

            try:
                removed = Agent()._remove_single_group(group_id)
                ids.append(group_id)
                affected_agents += removed['affected_agents']
            except Exception as e:
                failed_ids.append(create_exception_dic(group_id, e))

        final_dict = {}
        if not failed_ids:
            message = 'All selected groups were removed'
            final_dict = {'msg': message, 'ids': ids, 'affected_agents': affected_agents}
        else:
            message = 'Some groups were not removed'
            final_dict = {'msg': message, 'failed_ids': failed_ids, 'ids': ids, 'affected_agents': affected_agents}

        return final_dict


    @staticmethod
    def set_group(agent_id, group_id, force=False):
        """
        Set a group to an agent.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: No check if agent exists
        :return: Confirmation message.
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhException(1722)

        agent_id = agent_id.zfill(3)
        if agent_id == "000":
            raise WazuhException(1703)

        # Check if agent exists
        if not force:
            Agent(agent_id).get_basic_information()

        # Assign group in /queue/agent-groups
        agent_group_path = "{0}/{1}".format(common.groups_path, agent_id)
        try:
            new_file = False if path.exists(agent_group_path) else True

            f_group = open(agent_group_path, 'w')
            f_group.write(group_id)
            f_group.close()

            if new_file:
                chown(agent_group_path, common.ossec_uid, common.ossec_gid)
                chmod(agent_group_path, 0o660)
        except Exception as e:
            raise WazuhException(1005, str(e))

        # Create group in /etc/shared
        if not Agent.group_exists(group_id):
            Agent.create_group(group_id)

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
            with open(agent_group_path, "w+") as fo:
                fo.write("default")

        return "Group unset for agent '{0}'.".format(agent_id)

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

        if WazuhVersion(manager_ver.split(" ")[1]) < WazuhVersion(agent_new_ver):
            raise WazuhException(1717, "Manager: {0} / Agent: {1} -> {2}".format(manager_ver.split(" ")[1], agent_ver.split(" ")[1], agent_new_ver))

        if (WazuhVersion(agent_ver.split(" ")[1]) >= WazuhVersion(agent_new_ver) and not force):
            raise WazuhException(1716, "Agent ver: {0} / Agent new ver: {1}".format(agent_ver.split(" ")[1], agent_new_ver))

        # Generating file name
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
            sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
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
        sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()

        # Comparing SHA1 hash
        if not sha1hash == agent_new_shasum:
            raise WazuhException(1714)

        if debug:
            print("WPK file downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))

        return [wpk_file, sha1hash]


    def _send_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, show_progress=None, chunk_size=None, rl_timeout=-1, timeout=common.open_retries):
        """
        Sends WPK file to agent.
        """
        if not chunk_size:
            chunk_size = common.wpk_chunk_size
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
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.open_sleep)
            counter = counter + 1
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

        # Sending reset lock timeout
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
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
        if debug:
            print("Chunk size: {0} bytes".format(chunk_size))
        file = open(common.ossec_path + "/var/upgrade/" + wpk_file, "rb")
        if not file:
            raise WazuhException(1715, data.replace("err ",""))
        if debug:
            print("Sending: {0}".format(common.ossec_path + "/var/upgrade/" + wpk_file))
        try:
            start_time = time()
            bytes_read = file.read(chunk_size)
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
                bytes_read = file.read(chunk_size)
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


    def upgrade(self, wpk_repo=None, debug=False, version=None, force=False, show_progress=None, chunk_size=None, rl_timeout=-1):
        """
        Upgrade agent using a WPK file.
        """
        if int(self.id) == 0:
            raise WazuhException(1703)

        self._load_info_from_DB()

        # Check if agent is active.
        if not self.status == 'Active':
            raise WazuhException(1720)

        # Check if remote upgrade is available for the selected agent version
        if WazuhVersion(self.version.split(' ')[1]) < WazuhVersion("3.0.0-alpha4"):
            raise WazuhException(1719, version)

        if self.os['platform']=="windows" and int(self.os['major']) < 6:
            raise WazuhException(1721, self.os['name'])

        if wpk_repo == None:
            wpk_repo = common.wpk_repo_url

        if not wpk_repo.endswith('/'):
            wpk_repo = wpk_repo + '/'

        # Send file to agent
        sending_result = self._send_wpk_file(wpk_repo, debug, version, force, show_progress, chunk_size, rl_timeout)
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
            s.close()
            return "Upgrade procedure started"
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): aborted: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716, data.replace("err ",""))


    @staticmethod
    def upgrade_agent(agent_id, wpk_repo=None, version=None, force=False, chunk_size=None):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :return: Upgrade message.
        """

        return Agent(agent_id).upgrade(wpk_repo=wpk_repo, version=version, force=True if int(force)==1 else False, chunk_size=chunk_size)


    def upgrade_result(self, debug=False, timeout=common.upgrade_result_retries):
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
            sleep(common.upgrade_result_sleep)
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
            s.close()
            return "Agent upgraded successfully"
        elif data.startswith('ok 2'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): failed: restored to previous version".format(str(self.id).zfill(3), self.name)).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716, "Agent restored to previous version")
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): lost: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716, data.replace("err ",""))


    @staticmethod
    def get_upgrade_result(agent_id, timeout=3):
        """
        Read upgrade result output from agent.

        :param agent_id: Agent ID.
        :return: Upgrade result.
        """

        return Agent(agent_id).upgrade_result(timeout=int(timeout))


    def _send_custom_wpk_file(self, file_path, debug=False, show_progress=None, chunk_size=None, rl_timeout=-1, timeout=common.open_retries):
        """
        Sends custom WPK file to agent.
        """
        if not chunk_size:
            chunk_size = common.wpk_chunk_size

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
        msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.recv(1024).decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.open_sleep)
            counter = counter + 1
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

        # Sending reset lock timeout
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(common.ossec_path + "/queue/ossec/request")
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
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
        if debug:
            print("Chunk size: {0} bytes".format(chunk_size))
        file = open(file_path, "rb")
        if not file:
            raise WazuhException(1715, data.replace("err ",""))
        try:
            start_time = time()
            bytes_read = file.read(chunk_size)
            file_sha1=hashlib.sha1(bytes_read)
            bytes_read_acum = 0
            while bytes_read:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(common.ossec_path + "/queue/ossec/request")
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.recv(1024).decode()
                s.close()
                bytes_read = file.read(chunk_size)
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


    def upgrade_custom(self, file_path, installer, debug=False, show_progress=None, chunk_size=None, rl_timeout=-1):
        """
        Upgrade agent using a custom WPK file.
        """
        self._load_info_from_DB()

        # Check if agent is active.
        if not self.status == 'Active':
            raise WazuhException(1720)

        # Send file to agent
        sending_result = self._send_custom_wpk_file(file_path, debug, show_progress, chunk_size, rl_timeout)
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
            s.close()
            return "Installation started"
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Custom installation on agent {0} ({1}): aborted: {2}".format(str(self.id).zfill(3), self.name, data.replace("err ",""))).encode(), common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhException(1716, data.replace("err ",""))


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
