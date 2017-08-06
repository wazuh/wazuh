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
import requests
import json
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
        conn.execute('''CREATE TABLE IF NOT EXISTS nodes (id INTEGER PRIMARY KEY,node TEXT NOT NULL,ip TEXT,user TEXT,password TEXT,status TEXT,last_check TEXT)''')
        conn.commit()

        db_cluster = glob(common.database_path_cluster)
        if not db_cluster:
            raise WazuhException(1600)

        # Query
        query = "SELECT {0} FROM nodes"
        fields = {'id': 'id', 'node': 'node', 'ip': 'ip', 'user': 'user', 'password': 'password', 'status': 'status', 'last_check': 'last_check' }
        select = ["id", "node", "ip", "user", "password", "status", "last_check"]
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
                data_tuple['password'] = tuple[4]
            if tuple[5] != None:
                data_tuple['status'] = tuple[5]
            if tuple[6] != None:
                data_tuple['last_check'] = tuple[6]

            data['items'].append(data_tuple)

        return data

    @staticmethod
    def sync():
        """
        Sync this node with others
        :return: Files synced.
        """

        #Get its own files status
        own_files = manager.get_files()

        cluster = Node()
        #Get other nodes files
        nodes_list = cluster.cluster_nodes()
        output = []
        for node in nodes_list["items"]:
                # Configuration
                base_url = node["ip"]
                auth = requests.auth.HTTPBasicAuth(node["user"], node["password"])
                verify = False


                # Request
                url = '{0}{1}'.format(base_url, "/manager/files")
                try:
                    r = requests.get(url, auth=auth, params=None, verify=verify)
                except requests.exceptions.Timeout as e:
                    error = str(e)
                    continue
                except requests.exceptions.TooManyRedirects as e:
                    error =  str(e)
                    continue
                except requests.exceptions.RequestException as e:
                    error =  str(e)
                    continue

                response = json.loads(r.text)

                #Compare each file with node own files
                for local_file_item in own_files:
                    local_file = {}
                    local_file["name"] = local_file_item
                    local_file["md5"] = own_files[local_file_item]["md5"]
                    local_file["modification_time"] = own_files[local_file_item]["modification_time"]
                    local_file_time = datetime.strptime(local_file["modification_time"], "%Y-%m-%d %H:%M:%S.%f")
                    remote_file_time = datetime.strptime(response["data"][local_file["name"]]["modification_time"], "%Y-%m-%d %H:%M:%S.%f")
                    if response["data"][local_file["name"]]["md5"] != local_file["md5"] and remote_file_time > local_file_time:
                            file_output = {}
                            file_output["node"] = node["node"]
                            file_output["file_name"] = local_file["name"]
                            file_output["modification_time"] = response["data"][local_file["name"]]["modification_time"]
                            file_output["format"] = response["data"][local_file["name"]]["format"]
                            file_output["md5"] = response["data"][local_file["name"]]["md5"]
                            output.append(file_output)

                            # Downloading files from each node and update
                            for file in output:
                                # Configuration
                                auth = requests.auth.HTTPBasicAuth(node["user"], node["password"])
                                verify = False
                                # Request
                                url = '{0}{1}'.format(node["ip"], "/manager/files?download="+file_output["file_name"])
                                try:
                                    r = requests.get(url, auth=auth, params=None, verify=verify)
                                except requests.exceptions.Timeout as e:
                                    error = str(e)
                                    continue
                                except requests.exceptions.TooManyRedirects as e:
                                    error =  str(e)
                                    continue 
                                except requests.exceptions.RequestException as e:
                                    error =  str(e)
                                    continue

                                dest_file = open(common.ossec_path+file_output["file_name"],"w")
                                dest_file.write(r.text)
                                dest_file.close()

        return output
