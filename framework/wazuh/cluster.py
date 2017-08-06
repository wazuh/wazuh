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
    from urllib import urlopen, urlretrieve
except ImportError:
    from urllib.request import urlopen, urlretrieve

class Node:
    """
    Wazuh node object
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize an node.
        'id': Node id when it exists
        'node', 'ip', 'user', 'password': Insert a new node

        :param args:   [id | node, ip, user, password].
        :param kwargs: [id | node, ip, user, password].
        """
        self.id = None
        self.node = None
        self.ip = None
        self.password = None
        self.user = None
        self.status = None
        self.last_check = None

        if args:
            if len(args) == 1:
                self.id = args[0]
            elif len(args) == 4:
                self._add(node=args[0], ip=args[1], user=args[2], password=args[3])
            else:
                raise WazuhException(1700)
        elif kwargs:
            if len(kwargs) == 1:
                self.id = kwargs['id']
            elif len(kwargs) == 4:
                self._add(node=kwargs['node'], ip=kwargs['ip'], user=kwargs['user'], password=kwargs['password'])
            else:
                raise WazuhException(1700)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'node': self.node, 'ip': self.ip, 'user': self.user, 'password': self.password, 'status': self.status, 'last_check': self.last_check }

        return dictionary

    @staticmethod
    def add_node(node, ip, user, password):
        """
        Adds a new node to Wazuh Cluster

        :param node: name of the node
        :param ip: IP.
        :param user: User for API
        :param password: Password for API
        :return: Node ID.
        """

        return Node(node=node, ip=ip, user=user, password=password).id

    def _add(self, node, ip, user, password):
        """
        Adds a new node to Wazuh Cluster

        :param node: name of the node
        :param ip: IP.
        :param user: User for API
        :param password: Password for API
        :return: Node ID.
        """

        conn = Connection(common.database_path_cluster)
        # Check if cluster DB exists
        if not path.exists(common.database_path_cluster):
            # Create DB
            conn.execute('''CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY,node TEXT NOT NULL,ip TEXT,user TEXT,password TEXT,status TEXT,last_check TEXT)''')
            conn.commit()

        db_cluster = glob(common.database_path_cluster)
        if not db_cluster:
            raise WazuhException(1600)

        request = {"id": None, "last_check": None, "status": None, "node": node, "ip": ip, "user": user, "password": password}
        request = (None, node, ip, user, password, None, None)
        id = conn.execute('''INSERT INTO nodes(id,node,ip,user,password,last_check,status) VALUES(?,?,?,?,?,?,?)''', request)
        conn.commit()
        self.id = id
        return self

    @staticmethod
    def cluster_nodes(id="all", node="all", ip="all", offset=0, limit=common.database_limit, sort=None, search=None):

        conn = Connection(common.database_path_cluster)
        # Check if cluster DB exists
        if not path.exists(common.database_path_cluster):
            # Create DB
            conn.execute('''CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY,node TEXT NOT NULL,ip TEXT,user TEXT,password TEXT,status TEXT,last_check TEXT)''')
            conn.commit()

        db_cluster = glob(common.database_path_cluster)
        if not db_cluster:
            raise WazuhException(1600)

        # Query
        query = "SELECT {0} FROM nodes"
        fields = {'id': 'id', 'node': 'node', 'ip': 'ip', 'user': 'user', 'password': 'password', 'status': 'status', 'last_check': 'last_check' }
        select = ["id", "node", "ip", "user", "status", "last_check"]
        search_fields = ["id", "node", "ip", "user", "status", "last_check"]
        request = {}

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

            if tuple[0] != None:
                data_tuple['id'] = str(tuple[0])
            if tuple[1] != None:
                data_tuple['node'] = tuple[1]
            if tuple[2] != None:
                data_tuple['ip'] = tuple[2]
            if tuple[3] != None:
                data_tuple['user'] = tuple[3]
            if tuple[4] != None:
                data_tuple['status'] = tuple[4]
            if tuple[5] != None:
                data_tuple['last_check'] = tuple[5]

            data['items'].append(data_tuple)

        return data

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
                elif "sparc" in self.os['uname']:
                    self.os['arch'] = "sparc"
                elif "amd64" in self.os['uname']:
                    self.os['arch'] = "amd64"
                elif "AIX" in self.os['uname']:
                    self.os['arch'] = "AIX"

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
            os_no_empty = dict((k, v) for k, v in self.os.iteritems() if v)
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
