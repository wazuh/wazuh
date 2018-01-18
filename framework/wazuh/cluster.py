#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import cut_array, sort_array, search_array, md5
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.manager import status
from wazuh.manager import ossec_log
from wazuh.manager import ossec_log_summary
from wazuh.configuration import get_ossec_conf
from wazuh.InputValidator import InputValidator
from wazuh import common
import sqlite3
from datetime import datetime
from hashlib import sha512
from time import time, mktime, sleep
from os import path, listdir, rename, utime, environ, umask, stat, mkdir, chmod, devnull, strerror
from subprocess import check_output
from shutil import rmtree
from io import BytesIO
from itertools import compress, chain
from operator import itemgetter, eq
from ast import literal_eval
import socket
import json
import threading
from stat import S_IRWXG, S_IRWXU
from sys import version
from difflib import unified_diff
import re
import socket
import asyncore
import asynchat

# import the C accelerated API of ElementTree
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import logging

is_py2 = version[0] == '2'
if is_py2:
    from Queue import Queue as queue
else:
    from queue import Queue as queue

import zipfile

try:
    import zlib
    compression = zipfile.ZIP_DEFLATED
except:
    compression = zipfile.ZIP_STORED

# API Messages
list_request_type = []
RESTART_AGENTS = "restart"
list_request_type.append(RESTART_AGENTS)
AGENTS_UPGRADE_RESULT = "agents_upg_result"
list_request_type.append(AGENTS_UPGRADE_RESULT)
AGENTS_UPGRADE = "agents_upg"
list_request_type.append(AGENTS_UPGRADE)
AGENTS_UPGRADE_CUSTOM = "agents_upg_custom"
list_request_type.append(AGENTS_UPGRADE_CUSTOM)
SYSCHECK_LAST_SCAN = "syscheck_last"
list_request_type.append(SYSCHECK_LAST_SCAN)
SYSCHECK_RUN = "syscheck_run"
list_request_type.append(SYSCHECK_RUN)
SYSCHECK_CLEAR = "syscheck_clear"
list_request_type.append(SYSCHECK_CLEAR)
ROOTCHECK_PCI = "rootcheck_pci"
list_request_type.append(ROOTCHECK_PCI)
ROOTCHECK_CIS = "rootcheck_cis"
list_request_type.append(ROOTCHECK_CIS)
ROOTCHECK_LAST_SCAN = "rootcheck_last"
list_request_type.append(ROOTCHECK_LAST_SCAN)
ROOTCHECK_RUN = "rootcheck_run"
list_request_type.append(ROOTCHECK_RUN)
ROOTCHECK_CLEAR = "rootcheck_clear"
list_request_type.append(ROOTCHECK_CLEAR)
MANAGERS_STATUS = "manager_status"
list_request_type.append(MANAGERS_STATUS)
MANAGERS_LOGS = "manager_logs"
list_request_type.append(MANAGERS_LOGS)
MANAGERS_LOGS_SUMMARY = "manager_logs_sum"
list_request_type.append(MANAGERS_LOGS_SUMMARY)


def check_cluster_status():
    """
    Function to check if cluster is enabled
    """
    with open("/etc/ossec-init.conf") as f:
        # the osec directory is the first line of ossec-init.conf
        directory = f.readline().split("=")[1][:-1].replace('"', "")

    try:
        # wrap the data
        with open("{0}/etc/ossec.conf".format(directory)) as f:
            txt_data = f.read()

        txt_data = re.sub("(<!--.*?-->)", "", txt_data, flags=re.MULTILINE | re.DOTALL)
        txt_data = txt_data.replace(" -- ", " -INVALID_CHAR ")
        txt_data = '<root_tag>' + txt_data + '</root_tag>'

        conf = ET.fromstring(txt_data)

        return conf.find('ossec_config').find('cluster').find('disabled').text == 'no'
    except:
        return False

# import python-cryptography lib only if cluster is enabled
if check_cluster_status():
    try:
        from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
    except ImportError as e:
        raise WazuhException(3008, str(e))


class WazuhClusterClient(asynchat.async_chat):
    def __init__(self, host, port, key, data, file):
        asynchat.async_chat.__init__(self)
        self.can_read = False
        self.can_write = True
        self.received_data = []
        self.response = ""
        self.f = key
        self.data = data
        self.file = file
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(common.cluster_timeout)
        try:
            self.connect((host, port))
        except socket.error as e:
            self.close()
            raise WazuhException(3010, strerror(e[0]))
        self.set_terminator('\n')

    def handle_close(self):
        self.close()

    def readable(self):
        return self.can_read

    def writable(self):
        return self.can_write

    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()
        self.close()
        if InvalidToken == t or InvalidSignature == t:
            raise WazuhException(3010, "Could not decrypt message from {0}".format(self.addr[0]))
        else:
            raise WazuhException(3010, str(v))

    def collect_incoming_data(self, data):
        self.received_data.append(data)

    def found_terminator(self):
        self.response = json.loads(self.f.decrypt(''.join(self.received_data)))
        self.close()

    def handle_write(self):
        if self.file is not None:
            msg = self.f.encrypt(self.data.encode()) + self.f.encrypt(self.file) + '\n\t\t\n'
        else:
            msg = self.f.encrypt(self.data.encode()) + '\n\t\t\n'

        i = 0
        while i < len(msg):
            next_i = i+4096 if i+4096 < len(msg) else len(msg)
            sent = self.send(msg[i:next_i])
            i += sent


        self.can_read=True
        self.can_write=False


def send_request(host, port, key, data, file=None):
    error = 0
    try:
        fernet_key = Fernet(key.encode('base64','strict'))
        client = WazuhClusterClient(host, int(port), fernet_key, data, file)
        asyncore.loop()
        data = client.response

    except NameError as e:
        data = "Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography)"
        error = 1

    except WazuhException as e:
        error = 1
        data = str(e)

    return error, data

def get_status_json():
    return {"enabled": "yes" if check_cluster_status() else "no",
            "running": "yes" if status()['wazuh-clusterd'] == 'running' else "no"}


def check_cluster_cmd(cmd, node_type):
    # cmd must be a list
    if not isinstance(cmd, list):
        return False

    # check cmd len list
    if len(cmd) != 2 and len(cmd) != 3:
        return False

    # check cmd len
    if len(' '.join(cmd)) != common.cluster_protocol_plain_size:
        return False

    # 'ready' cmd can only be sent by a master node to a client node
    if cmd[0] == 'ready' and node_type == 'client':
        return True

    # 'data' cmd can only be sent by a master node to another master node
    if cmd[0] == 'data' and node_type == 'master':
        return True

    # check command type
    if not cmd[0] in ['zip', 'node'] and not cmd[0] in list_request_type:
        return False

    # second argument of zip is a number
    if cmd[0] == 'zip' and not re.compile('\d+').match(cmd[1]):
        return False

    return True


def check_cluster_config(config):
    iv = InputValidator()

    if not 'key' in config.keys():
        raise WazuhException(3004, 'Unspecified key')
    elif not iv.check_name(config['key']) or not iv.check_length(config['key'], 32, eq):
        raise WazuhException(3004, 'Key must be 32 characters long and only have alphanumeric characters')

    if config['node_type'] != 'master' and config['node_type'] != 'client':
        raise WazuhException(3004, 'Invalid node type {0}. Correct values are master and client'.format(config['node_type']))
    if not re.compile("\d+[m|s]").match(config['interval']):
        raise WazuhException(3004, 'Invalid interval specification. Please, specify it with format <number>s or <number>m')
    if config['nodes'][0] == 'localhost' and len(config['nodes']) == 1:
        raise WazuhException(3004, 'Please specify IPs of all cluster nodes')


def get_cluster_items():
    try:
        cluster_items = json.load(open('{0}/framework/wazuh/cluster.json'.format(common.ossec_path)))
        return cluster_items
    except Exception as e:
        raise WazuhException(3005, str(e))

def get_file_info(filename, cluster_items):
    def is_synced_file(mtime, node_type):
        if node_type == 'master':
            return False
        else:
            return (datetime.now() - datetime.fromtimestamp(mtime)).seconds / 60 > 30

    node_type = read_config()['node_type']
    fullpath = common.ossec_path + filename

    if not path.isfile(fullpath):
        raise WazuhException(3000, "Could not open file {0}".format(filename))

    stat_obj = stat(fullpath)
    st_mtime = stat_obj.st_mtime
    st_size = stat_obj.st_size

    directory = path.dirname(filename)+'/'
    new_item = cluster_items[directory] if directory in cluster_items.keys() else cluster_items['/etc/']

    file_item = {
        "umask" : new_item['umask'],
        "format" : new_item['format'],
        "write_mode" : new_item['write_mode'],
        "md5": md5(fullpath),
        "modification_time" : str(datetime.utcfromtimestamp(st_mtime)),
        'timestamp': st_mtime,
        "size" : st_size,
        'is_synced': is_synced_file(st_mtime, node_type)
    }

    return file_item


def compress_files(list_path, node_type):
    zipped_file = BytesIO()
    with zipfile.ZipFile(zipped_file, 'w') as zf:
        # write files
        for f in list_path:
            try:
                zf.write(filename = common.ossec_path + f, arcname = f, compress_type=compression)
            except Exception as e:
                logging.error(str(WazuhException(3001, str(e))))

        # write a file with the name of all the groups only if the node type is master
        if node_type == 'master':
            try:
                local_groups = [x['name'] for x in Agent.get_all_groups(limit=None)['items']]
                zf.writestr("remote_groups.txt", '\n'.join(local_groups), compression)
            except Exception as e:
                raise WazuhException(3001, str(e))

    return zipped_file.getvalue()

def read_config():
    # Get api/configuration/config.js content
    try:
        config_cluster = get_ossec_conf('cluster')

    except WazuhException as e:
        if e.code == 1102:
            raise WazuhException(3006, "Cluster configuration not present in ossec.conf")
        else:
            raise WazuhException(3006, e.message)
    except Exception as e:
        raise WazuhException(3006, str(e))

    return config_cluster


get_localhost_ips = lambda: check_output(['hostname', '--all-ip-addresses']).split(" ")[:-1]

def get_actual_master(csocket=None):
    if not csocket:
        cluster_socket = connect_to_db_socket()
    else:
        cluster_socket = csocket

    send_to_socket(cluster_socket, "selactual")
    name = receive_data_from_db_socket(cluster_socket)

    if not csocket:
        cluster_socket.close()

    return name


def get_actual_master_json():
    return {'name':get_actual_master(), 'url':get_ip_from_name(get_actual_master())}

def insert_actual_master(node_name, csocket=None):
    if not csocket:
        cluster_socket = connect_to_db_socket()
    else:
        cluster_socket = csocket

    send_to_socket(cluster_socket, "insertactual {0}".format(node_name))
    receive_data_from_db_socket(cluster_socket)

    if not csocket:
        cluster_socket.close()

def select_actual_master(nodes, cluster_socket=None):
    # check if there's already one actual master
    if len(list(filter(lambda x: x == 'master(*)', map(itemgetter('type'), nodes)))) > 0:
        return nodes

    # if there's no actual master, select one
    for node in nodes:
        if node['type'] == 'master':
            logging.info("The new elected master is {0}.".format(node['node']))
            node['type'] = 'master(*)'
            insert_actual_master(node['node'], cluster_socket)
            break

    return nodes


def get_nodes(updateDBname=False, cluster_socket=None, get_localhost=False):
    """
    Function to get information about all nodes in the cluster.

    :param updateDBname: Flag to decide if update cluster nodes name database or not
    """
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()
    data = []
    error_response = False

    for url in sorted(config_cluster["nodes"]):
        if not url in localhost_ips:
            error, response = send_request(host=url, port=config_cluster["port"], key=config_cluster['key'],
                                data="node {0}".format('a'*(common.cluster_protocol_plain_size - len("node "))))
            if error == 0:
                if response['error'] == 0:
                    response = response['data']
                    if get_localhost:
                        response['localhost'] = False
                else:
                    logging.warning("Received an error response from {0}: {1}".format(url, response))
                    error_response = True
        else:
            error = 0
            response = get_node(cluster_socket=cluster_socket)
            response['localhost'] = True

        if error == 1:
            logging.warning("Error connecting with {0}: {1}".format(url, response))
            error_response = True

        if error_response:
            res_dict = {'error': response, 'node':'unknown', 'status':'disconnected', 'url':url, 'type':'unknown'}
            if get_localhost:
                res_dict['localhost'] = False
            data.append(res_dict)
            error_response = False
            continue

        if 'master' in config_cluster['node_type'] or \
            'master' in response['type'] or (get_localhost and response['localhost']):
            res_dict = {'url':url, 'node':response['node'], 'type': response['type'],
                         'status':'connected', 'cluster':response['cluster']}
            if get_localhost:
                res_dict['localhost'] = response['localhost']
            data.append(res_dict)

            if updateDBname:
                if not cluster_socket:
                    csocket = connect_to_db_socket()
                else:
                    csocket = cluster_socket

                query = "insertname " +response['node'] + " " + url
                send_to_socket(csocket, query)
                receive_data_from_db_socket(csocket)

                if not cluster_socket:
                    csocket.close()

    select_actual_master(data, cluster_socket)

    return {'items': data, 'totalItems': len(data)}



def get_node(name=None, cluster_socket=None):
    data = {}
    if not name:
        config_cluster = read_config()

        if not config_cluster:
            raise WazuhException(3000, "No config found")

        data["node"]    = config_cluster["node_name"]
        data["cluster"] = config_cluster["name"]
        if get_actual_master(cluster_socket) == data['node']:
            data["type"] = "master(*)"
        else:
            data["type"] = config_cluster["node_type"]

    return data


def scan_for_new_files_one_node(node, cluster_items, cluster_config, cluster_socket=None, own_items=None):
    if not own_items:
        own_items = list_files_from_filesystem(cluster_config['node_type'], cluster_items)
    own_items_names = own_items.keys()

    # check files in database
    count_query = "count {0}".format(node)
    send_to_socket(cluster_socket, count_query)
    n_files = int(filter(lambda x: x != '\x00', cluster_socket.recv(10000)))

    if n_files == 0:
        logging.info("New manager found: {0}".format(node))
        logging.debug("Adding {0}'s files to database".format(node))

        # if the manager is not in the database, add it with all files
        for files in divide_list(own_items_names):

            insert_sql = "insert"
            for file in files:
                insert_sql += " {0} {1}".format(node, file)

            send_to_socket(cluster_socket, insert_sql)
            data = cluster_socket.recv(10000)

    else:
        logging.debug("Retrieving {0}'s files from database".format(node))
        all_files = get_file_status(node, cluster_socket)
        # if there are missing files that are not being controled in database
        # add them as pending
        for missing in divide_list(set(own_items_names) - set(all_files.keys())):
            insert_sql = "insert"
            for m in missing:
                all_files[m] = 'pending'
                insert_sql += " {0} {1}".format(node,m)

            send_to_socket(cluster_socket, insert_sql)
            data = receive_data_from_db_socket(cluster_socket)


def connect_to_db_socket(retry=False):
    if not  check_cluster_status():
        raise WazuhException(3013)

    cluster_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    max_retries = 100 if retry else 1
    n_retries = 0
    while n_retries <= max_retries:
        try:
            cluster_socket.connect("{0}/queue/ossec/cluster_db".format(common.ossec_path))
        except socket.error as e:
            error_msg = str(e)
            n_retries += 1
            sleep(1)
            continue
        break

    if n_retries >= max_retries:
        raise WazuhException(3009, error_msg)

    return cluster_socket

def receive_data_from_db_socket(cluster_socket):
    return ''.join(filter(lambda x: x != '\x00', cluster_socket.recv(10000).decode()))

def send_to_socket(cluster_socket, query):
    cluster_socket.send(query.encode())

def scan_for_new_files():
    cluster_socket = connect_to_db_socket()

    cluster_items = get_cluster_items()
    cluster_config = read_config()
    own_items = list_files_from_filesystem(cluster_config['node_type'], cluster_items)

    for node in get_remote_nodes():
        scan_for_new_files_one_node(node[0], cluster_items, cluster_config, cluster_socket, own_items)

    cluster_socket.close()


def list_files_from_filesystem(node_type, cluster_items, get_all=False):
    def get_files_from_dir(dirname, recursive, files, cluster_items):
        items = []
        for entry in listdir(dirname):
            if entry in cluster_items['excluded_files'] or entry[-1] == '~':
                continue

            if entry in files or files == ["all"]:

                full_path = path.join(dirname, entry)
                if not path.isdir(full_path):
                    items.append(full_path.replace(common.ossec_path, ""))
                elif recursive:
                    items.extend(get_files_from_dir(full_path, recursive, files, cluster_items))

        return items

    # Expand directory
    expanded_items = []
    for file_path, item in cluster_items.items():
        if file_path == "excluded_files":
            continue
        if item['source'] == node_type or \
           item['source'] == 'all' or get_all:
            fullpath = common.ossec_path + file_path
            expanded_items.extend(get_files_from_dir(fullpath, item['recursive'],item['files'], cluster_items))

    final_items = {}
    for new_item in expanded_items:
        try:
            final_items[new_item] = get_file_info(new_item, cluster_items)
        except Exception as e:
            continue

    return dict(filter(lambda x: not x[1]['is_synced'], final_items.items()))

def get_file_status(manager, cluster_socket):
    count_query = "count {0}".format(manager)
    send_to_socket(cluster_socket, count_query)
    n_files = int(receive_data_from_db_socket(cluster_socket))

    query = "select {0} 100 ".format(manager)
    file_status = ""
    # limit = 100
    for offset in range(0,n_files,100):
        send_to_socket(cluster_socket, query + str(offset))
        file_status += receive_data_from_db_socket(cluster_socket)

    # retrieve all files for a node in database with its status
    all_files = {f[0]:f[1] for f in map(lambda x: x.split('*'), filter(lambda x: x != '', file_status.split(' ')))}

    return all_files

def get_file_status_all_managers(file_list, manager):
    """
    Return a nested list where each element has the following structure
    [manager, filename, status]
    """
    fix_manager = []
    cluster_socket = connect_to_db_socket()
    if manager:
        for m in manager:
            if re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").match(m):
                fix_manager.append(m)
            elif re.compile(r"\w+").match(m):
                send_to_socket(cluster_socket, "getip {0}".format(m))
                fix_manager.append(receive_data_from_db_socket(cluster_socket))
            else:
                raise WazuhException(3014, m)

        manager = fix_manager
    cluster_socket.close()

    files = []

    nodes = get_remote_nodes(connected=False, return_info_for_masters=True)
    if manager:
        remote_nodes = filter(lambda x: x in manager, map(itemgetter(0), nodes))
    else:
        remote_nodes = map(itemgetter(0), nodes)

    cluster_socket = connect_to_db_socket()
    for node in remote_nodes:
        all_files = get_file_status(node, cluster_socket)
        if file_list == []:
            filenames = all_files.keys()
        else:
            filenames = file_list

        files.extend([[node, file, all_files[file]] for file in filenames])

    cluster_socket.close()
    return files


def get_last_sync():
    """
    Function to retrieve information about the last synchronization
    """
    cluster_socket = connect_to_db_socket()

    send_to_socket(cluster_socket, "sellast")

    date, duration = receive_data_from_db_socket(cluster_socket).split(" ")

    cluster_socket.close()

    return str(datetime.fromtimestamp(int(date))), float(duration)


def clear_file_status_one_node(manager, cluster_socket):
    """
    Function to set the status of all manager's files to pending
    """
    files = get_file_status(manager, cluster_socket).keys()

    update_sql = "update2"
    for file in files:
        update_sql += " pending {0} {1}".format(manager, file)

        send_to_socket(cluster_socket, update_sql)
        received = receive_data_from_db_socket(cluster_socket)


def update_file_info_bd(cluster_socket, files):
    """
    Function to update the files' information in database
    """
    query = "insertfile "
    for file in divide_list(files.items()):
        for fname, finfo in file:
            query += "{} {} {} ".format(fname, finfo['md5'], finfo['timestamp'])

        send_to_socket(cluster_socket, query)
        received = receive_data_from_db_socket(cluster_socket)


def clear_file_status():
    """
    Function to set all database files' status to pending

    Cleans actual_master table
    """
    cluster_socket = connect_to_db_socket(retry=True)
    # clean last actual master node
    send_to_socket(cluster_socket, "delactual");
    receive_data_from_db_socket(cluster_socket)

    # Get information of files from filesystem
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")
    own_items = list_files_from_filesystem(config_cluster['node_type'], get_cluster_items())

    # n files DB
    send_to_socket(cluster_socket, "countfiles")
    n_files_db = int(receive_data_from_db_socket(cluster_socket))

    # Only update status for modified files
    if n_files_db > 0:
        # Get information of files from DB (limit = 100)
        query = "selfiles 100 "
        file_status = ""
        for offset in range(0, n_files_db, 100):
            query += str(offset)
            send_to_socket(cluster_socket, query)
            file_status += receive_data_from_db_socket(cluster_socket)

        db_items = {filename:{'md5': md5, 'timestamp': timestamp} for filename,
                    md5, timestamp in map(lambda x: x.split('*'),
                    filter(lambda x: x != '', file_status.split(' ')))}

        # Update status
        query = "update1 "
        new_items = {}
        for files_slice in divide_list(own_items.items()):
            local_items = dict(filter(lambda x: db_items[x[0]]['md5'] != x[1]['md5']
                            or int(db_items[x[0]]['timestamp']) < int(x[1]['timestamp']), files_slice))
            query += ' '.join(local_items.keys())
            send_to_socket(cluster_socket, query)
            received = receive_data_from_db_socket(cluster_socket)
            new_items.update(local_items)
    else:
        new_items = own_items


    update_file_info_bd(cluster_socket, new_items)
    cluster_socket.close()


def get_file_status_json(file_list = {'fields':[]}, manager = {'fields':[]}):
    """
    Return a nested list where each element has the following structure
    {
        manager: {
            status: [
                files
            ]
        }
    }
    """
    files = get_file_status_all_managers(file_list['fields'], manager['fields'])
    cluster_dict = {}
    for manager, file, status in files:
        try:
            cluster_dict[manager][status].append(file)
        except KeyError:
            cluster_dict[manager] = {}
            cluster_dict[manager][status] = [file]

    return cluster_dict

def get_agents_status():
    """
    Return a nested list where each element has the following structure
    [agent_id, agent_name, agent_status, manager_hostname]
    """
    agent_list = []
    for agent in Agent.get_agents_overview(select={'fields':['id','ip','name','status','node_name']}, limit=None)['items']:
        if int(agent['id']) == 0:
            continue
        try:
            agent_list.append([agent['id'], agent['ip'], agent['name'], agent['status'], agent['node_name']])
        except KeyError:
            agent_list.append([agent['id'], agent['ip'], agent['name'], agent['status'], "None"])

    return agent_list


def get_agent_status_json():
    """
    Return a nested list where each element has the following structure
    {
        manager: {
            status: [
                id: name
            ]
        }
    }
    """
    agents = get_agents_status()
    cluster_dict = {}
    for agent_id, agent_ip, name, status, manager in agents:
        try:
            cluster_dict[manager].append({
                'id': agent_id,
                'ip': agent_ip,
                'name': name,
                'status': status
            })
        except KeyError:
            cluster_dict[manager] = [{
                'id': agent_id,
                'ip': agent_ip,
                'name': name,
                'status': status
            }]

    return cluster_dict


def get_token():
    config_cluster = read_config()

    if not config_cluster:
        raise WazuhException(3000, "No config found")

    raw_key = config_cluster["key"]
    token = sha512(raw_key).hexdigest()
    return token


def _check_token(other_token):
    my_token = get_token()
    if my_token == other_token:
        return True
    else:
        return False

def _check_removed_agents(new_client_keys):
    """
    Function to delete agents that have been deleted in a synchronized
    client.keys.

    It makes a diff of the old client keys and the new one and search for
    deleted or changed lines (in the diff those lines start with -).

    If a line starting with - matches the regex structure of a client.keys line
    that agent is deleted.
    """
    with open("{0}/etc/client.keys".format(common.ossec_path)) as ck:
        # can't use readlines function since it leaves a \n at the end of each item of the list
        client_keys = ck.read().split('\n')

    regex = re.compile('-\d{3} \w+ (any|\d+.\d+.\d+.\d+|\d+.\d+.\d+.\d+\/\d+) \w+')
    for removed_line in filter(lambda x: x.startswith('-'), unified_diff(client_keys, new_client_keys)):
        if regex.match(removed_line):
            agent_id, _, _, _, = removed_line[1:].split(" ")

            try:
                Agent(agent_id).remove()
                logging.info("Agent {0} deleted successfully".format(agent_id))
            except WazuhException as e:
                logging.error("Error deleting agent {0}: {1}".format(agent_id, str(e)))


def _update_file(fullpath, new_content, umask_int=None, mtime=None, w_mode=None, node_type='master', node_name=''):
    # Set Timezone to epoch converter
    # environ['TZ']='UTC'
    if path.basename(fullpath) == 'client.keys':
        if node_type=='client':
            _check_removed_agents(new_content.split('\n'))
        elif node_name == get_actual_master():
            logging.warning("Client.keys file received in a elected master node.")
            raise WazuhException(3007)

    if 'agent-info' in fullpath:
        if node_type=='master':
            # check if the date is older than the manager's date
            if path.isfile(fullpath) and datetime.fromtimestamp(int(stat(fullpath).st_mtime)) > mtime:
                logging.warning("Receiving an old agent-info file ({})".format(path.basename(fullpath)))
                raise WazuhException(3012)
        else:
            logging.warning("Agent-info received in a client node.")
            raise WazuhException(3011)

    # Write
    if w_mode == "atomic":
        f_temp = '{0}.tmp.cluster'.format(fullpath)
    else:
        f_temp = '{0}'.format(fullpath)

    if umask_int:
        oldumask = umask(umask_int)

    try:
        dest_file = open(f_temp, "w")
    except IOError:
        dirpath = path.dirname(fullpath)
        mkdir(dirpath)
        chmod(dirpath, S_IRWXU | S_IRWXG)
        dest_file = open(f_temp, "a+")

    dest_file.write(new_content)

    if umask_int:
        umask(oldumask)

    dest_file.close()

    mtime_epoch = int(mktime(mtime.timetuple()))
    utime(f_temp, (mtime_epoch, mtime_epoch)) # (atime, mtime)

    # Atomic
    if w_mode == "atomic":
        rename(f_temp, fullpath)


def extract_zip(zip_bytes):
    zip_json = {}
    with zipfile.ZipFile(BytesIO(zip_bytes)) as zipf:
        zip_json = {name:{'data':zipf.open(name).read(),
                          'time':datetime(*zipf.getinfo(name).date_time)}
                    for name in zipf.namelist()}

    return receive_zip(zip_json)

def receive_zip(zip_file):
    def check_groups(remote_group_set):
        """
        Function to remove the groups that are on the local node and not in the remote node
        """
        local_groups = {x['name'] for x in Agent.get_all_groups(limit=None)['items']}
        for removed_group in local_groups - remote_group_set:
            try:
                Agent.remove_group(removed_group)
                logging.info("Group {0} removed successfully".format(removed_group))
            except Exception as e:
                logging.error("Error deleting group {0}: {1}".format(removed_group, str(e)))


    cluster_items = get_cluster_items()
    config = read_config()
    logging.info("Receiving package with {0} files".format(len(zip_file)))

    final_dict = {'error':[], 'updated': [], 'invalid': []}

    if 'remote_groups.txt' in zip_file.keys():
        check_groups(set(zip_file['remote_groups.txt']['data'].split('\n')))
        del zip_file['remote_groups.txt']

    for name,content in zip_file.items():
        try:
            fixed_name = '/' + name
            dir_name = path.dirname(fixed_name) + '/'
            file_path = common.ossec_path + fixed_name
            try:
                remote_umask = int(cluster_items[dir_name]['umask'], base=0)
                remote_write_mode = cluster_items[dir_name]['write_mode']
            except KeyError:
                remote_umask = int(cluster_items['/etc/']['umask'], base=0)
                remote_write_mode = cluster_items['/etc/']['write_mode']

            _update_file(file_path, new_content=content['data'],
                            umask_int=remote_umask,
                            mtime=content['time'],
                            w_mode=remote_write_mode,
                            node_type=config['node_type'],
                            node_name=config['name'])

        except Exception as e:
            logging.error("Error extracting zip file: {0}".format(str(e)))
            final_dict['error'].append({'item': name, 'reason': str(e)})
            continue

        final_dict['updated'].append(name)

    return final_dict


def divide_list(l, size=1000):
    return map(lambda x: filter(lambda y: y is not None, x), map(None, *([iter(l)] * size)))

def get_remote_nodes(connected=True, updateDBname=False, return_info_for_masters=False, cluster_socket=None):
    all_nodes = get_nodes(updateDBname=updateDBname, cluster_socket=cluster_socket, get_localhost=True)['items']

    # Get connected nodes in the cluster
    if connected:
        cluster = [(n['url'], n['type'], n['localhost'], n['node']) for n in
                    filter(lambda x: x['status'] == 'connected', all_nodes)]
    else:
        cluster = [(n['url'], n['type'], n['localhost'], n['node']) for n in all_nodes]
    # search the index of the localhost in the cluster
    try:
        localhost_index = next (x[0] for x in enumerate(cluster) if x[1][2])
    except StopIteration:
        logging.error("Cluster nodes are not correctly configured at ossec.conf.")
        raise WazuhException(3004, "Cluster nodes are not correctly configured at ossec.conf.")

    if not return_info_for_masters and cluster[localhost_index][1] == 'master':
        return [] # if the master is no the actual one, it doesnt send any messages

    return list(map(itemgetter(0,1,3), compress(cluster, map(lambda x: x != localhost_index, range(len(cluster))))))

def get_file_status_of_one_node(node, own_items_names, cluster_socket, all_items=None):
    # check files in database
    node_url, node_type, _ = node

    own_items = own_items_names if node_type == 'client' or not all_items else all_items

    count_query = "count {0}".format(node_url)
    send_to_socket(cluster_socket, count_query)
    n_files = int(receive_data_from_db_socket(cluster_socket))
    if n_files == 0:
        logging.info("New manager found: {0}".format(node_url))
        logging.debug("Adding {0}'s files to database".format(node_url))

        # if the manager is not in the database, add it with all files
        for files in divide_list(own_items):

            insert_sql = "insert"
            for file in files:
                insert_sql += " {0} {1}".format(node_url, file)

            send_to_socket(cluster_socket, insert_sql)
            data = receive_data_from_db_socket(cluster_socket)

        all_files = {file:'pending' for file in own_items}

    else:
        logging.debug("Retrieving {0}'s files from database".format(node_url))
        all_files = get_file_status(node_url, cluster_socket)
        # if there are missing files that are not being controled in database
        # add them as pending
        for missing in divide_list(set(own_items) - set(all_files.keys())):
            insert_sql = "insert"
            for m in missing:
                all_files[m] = 'pending'
                insert_sql += " {0} {1}".format(node_url,m)

            send_to_socket(cluster_socket, insert_sql)
            data = receive_data_from_db_socket(cluster_socket)

    return all_files


def push_updates_single_node(all_files, node_dest, node_dest_name, config_cluster, result_queue):
    # filter to send only pending files
    pending_files = filter(lambda x: x[1] != 'synchronized', all_files.items())
    if len(pending_files) > 0:
        logging.info("Sending {} ({}) {} files".format(node_dest_name, node_dest, len(pending_files)))
        zip_file = compress_files(list_path=set(map(itemgetter(0), pending_files)),
                                  node_type=config_cluster['node_type'])

        error, response = send_request(host=node_dest, port=config_cluster['port'],
                                       data="zip {0}".format(str(len(zip_file)).
                                        zfill(common.cluster_protocol_plain_size - len("zip "))),
                                       file=zip_file, key=config_cluster['key'])

        try:
            res = literal_eval(response)
        except Exception as e:
            res = response

    else:
        logging.info("No pending files to send to {0} ".format(node_dest))
        res = {'error': 0, 'data':{'updated':[], 'error':[], 'invalid':[]}}
        error = 0


    if res['error'] != 0:
        logging.debug(res)
        result_queue.put({'node': node_dest, 'reason': "{0} - {1}".format(error, response),
                          'error': 1, 'files':{'updated':[], 'invalid':[],
                                        'error':list(map(itemgetter(0), pending_files))}})
    else:
        logging.debug({'updated': len(res['data']['updated']),
                      'error': res['data']['error'],
                      'invalid': res['data']['invalid']})
        result_queue.put({'node': node_dest, 'files': res['data'], 'error': 0, 'reason': ""})


def update_node_db_after_sync(data, node, node_name, cluster_socket):
    logging.info("Updating {}'s ({}) file status in DB".format(node_name, node))
    for updated in divide_list(data['files']['updated']):
        update_sql = "update2"
        for u in updated:
            update_sql += " synchronized {0} /{1}".format(node, u)

        send_to_socket(cluster_socket, update_sql)
        received = receive_data_from_db_socket(cluster_socket)

    for failed in divide_list(data['files']['error']):
        delete_sql = "delete1"
        update_sql = "update2"
        for f in failed:
            if isinstance(f, dict):
                if f['reason'] == 'Error 3012 - Received an old agent-info file.':
                    delete_sql += " /{0}".format(f['item'])
                else:
                    update_sql += " failed {0} /{1}".format(node, f['item'])
            else:
                update_sql += " failed {0} {1}".format(node, f)

        send_to_socket(cluster_socket, update_sql)
        received = receive_data_from_db_socket(cluster_socket)
        if len(delete_sql) > len("delete1"):
            send_to_socket(cluster_socket, delete_sql)
            received = receive_data_from_db_socket(cluster_socket)

    for invalid in divide_list(data['files']['invalid']):
        update_sql = "update2"
        for i in invalid:
            update_sql += " invalid {0} {1}".format(node, i)

        send_to_socket(cluster_socket, update_sql)
        received = receive_data_from_db_socket(cluster_socket)


def save_actual_master_data_on_db(data):
    logging.info("Updating database with information received from elected master.")
    cluster_socket = connect_to_db_socket()
    localhost_ips = get_localhost_ips()
    for node_ip, node_data in data.items():
        if not node_ip in localhost_ips:
            get_file_status_of_one_node((node_ip, 'client', ''), list_files_from_filesystem('master', get_cluster_items()).keys(), cluster_socket)
            update_node_db_after_sync(node_data, node_ip, node_data['name'], cluster_socket)
        else:
            # save files status received from master in database
            master_name = get_actual_master(csocket=cluster_socket)
            send_to_socket(cluster_socket, "getip {0}".format(master_name))
            actual_master_ip = receive_data_from_db_socket(cluster_socket)
            get_file_status_of_one_node((actual_master_ip, 'master', ''), list_files_from_filesystem('master', get_cluster_items()).keys(), cluster_socket)
            update_node_db_after_sync(node_data, actual_master_ip, master_name, cluster_socket)

    cluster_socket.close()


def sync_one_node(debug, node, node_name, force=False):
    """
    Sync files with only one node. This function is only called from client nodes
    """
    synchronization_date = time()
    synchronization_duration = 0.0

    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    cluster_items = get_cluster_items()

    before = time()
    # Get own items status
    own_items = list_files_from_filesystem(config_cluster['node_type'], cluster_items)
    own_items_names = own_items.keys()

    cluster_socket = connect_to_db_socket()
    logging.debug("Connected to cluster database socket")

    if force:
        clear_file_status_one_node(node, cluster_socket)
    all_files = get_file_status_of_one_node((node, 'master', ''), own_items_names, cluster_socket)

    after = time()
    synchronization_duration += after-before
    logging.debug("Time retrieving info from DB: {0}".format(after-before))

    before = time()
    result_queue = queue()
    push_updates_single_node(all_files, node, node_name, config_cluster, result_queue)

    after = time()
    synchronization_duration += after-before
    logging.debug("Time sending info: {0}".format(after-before))
    before = time()

    result = result_queue.get()
    update_node_db_after_sync(result, node, node_name, cluster_socket)
    after = time()
    synchronization_duration += after-before

    send_to_socket(cluster_socket, "clearlast")
    received = receive_data_from_db_socket(cluster_socket)
    send_to_socket(cluster_socket, "updatelast {0} {1}".format(synchronization_date, int(synchronization_duration)))
    received = receive_data_from_db_socket(cluster_socket)

    cluster_socket.close()
    logging.debug("Time updating DB: {0}".format(after-before))

    if debug:
        return result
    else:
        return {'updated': len(result['files']['updated']),
                  'error': result['files']['error'],
                  'invalid': result['files']['invalid'],
                  'error': result['error'],
                  'reason': result['reason']}


def sync(debug, force=False):
    """
    Sync this node with others
    :return: Files synced.
    """
    synchronization_date = time()
    synchronization_duration = 0.0

    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    cluster_items = get_cluster_items()
    before = time()
    # Get own items status
    own_items = list_files_from_filesystem(config_cluster['node_type'], cluster_items)
    if config_cluster['node_type'] == 'master':
        all_items = list_files_from_filesystem(config_cluster['node_type'], cluster_items, True).keys()
    else:
        all_items = None
    own_items_names = own_items.keys()

    remote_nodes = get_remote_nodes(True, True)

    # if there's no remote nodes, stop synchronization
    if remote_nodes == []:
        return {}

    logging.info("Starting synchronization process...")

    cluster_socket = connect_to_db_socket()
    logging.debug("Connected to cluster database socket")

    # for each connected manager, check its files. If the manager is not on database add it
    # with all files marked as pending
    all_nodes_files = {}

    logging.debug("Nodes to sync: {0}".format(str(remote_nodes)))
    logging.info("Found {0} connected nodes".format(len(remote_nodes)))

    for node in remote_nodes:
        if force:
            clear_file_status_one_node(node[0], cluster_socket)
        all_nodes_files[node[0]] = get_file_status_of_one_node(node, own_items_names, cluster_socket, all_items)

    after = time()
    synchronization_duration += after-before
    logging.debug("Time retrieving info from DB: {0}".format(after-before))

    before = time()
    result_queue = queue()
    threads = []
    thread_results = {}
    for node in remote_nodes:
        t = threading.Thread(target=push_updates_single_node, args=(all_nodes_files[node[0]],
                                                                    node[0], node[2],
                                                                    config_cluster,
                                                                    result_queue))
        threads.append(t)
        t.start()
        result = result_queue.get()
        thread_results[result['node']] = {'files': result['files'], 'error': result['error'],
                                          'reason': result['reason'], 'name': node[2]}

    for t in threads:
        t.join()
    after = time()
    synchronization_duration += after-before
    logging.debug("Time sending info: {0}".format(after-before))

    before = time()
    for node,data in thread_results.items():
        update_node_db_after_sync(data, node, data['name'], cluster_socket)

    after = time()
    synchronization_duration += after-before

    send_to_socket(cluster_socket, "clearlast")
    received = receive_data_from_db_socket(cluster_socket)
    send_to_socket(cluster_socket, "updatelast {0} {1}".format(int(synchronization_date), synchronization_duration))
    received = receive_data_from_db_socket(cluster_socket)

    cluster_socket.close()
    logging.debug("Time updating DB: {0}".format(after-before))

    if debug:
        return thread_results
    else:
        return {node:{'updated': len(data['files']['updated']),
                      'error': data['files']['error'],
                      'invalid': data['files']['invalid'],
                      'error': data['error'],
                      'reason': data['reason']}
                      for node,data in thread_results.items()}


def get_ip_from_name(name):
    cluster_socket = connect_to_db_socket()
    try:
        send_to_socket(cluster_socket, "getip {0}".format(name))
        data = receive_data_from_db_socket(cluster_socket)
        if data == "":
            data = None
    except:
        data = None
    if data == None:
        logging.warning("Can't get ip of {0}".format(name))
    cluster_socket.close()
    return data


def get_name_from_ip(addr):
    cluster_socket = connect_to_db_socket()
    try:
        send_to_socket(cluster_socket, "getname {0}".format(addr))
        data = receive_data_from_db_socket(cluster_socket)
        if data == "":
            data = None
    except:
        data = None
    if data == None:
        logging.warning("Can't get ip of {0}".format(addr))
    cluster_socket.close()
    return data


def get_node_agent(agent_id):
    try:
        node_name = Agent(agent_id).get_basic_information()['node_name']
        data = get_ip_from_name(node_name)
    except:
        logging.warning("Can't find agent {0}".format(agent_id))
        data = None
    return data


def get_agents_by_node(agent_id):
    # Return remote_nodes[addr_node] = {agent_id_0, agent_id_1, ...}
    node_agents = {}
    if isinstance(agent_id, list):
        for id in agent_id:
            addr = get_node_agent(id)
            if node_agents.get(addr) is None:
                node_agents[addr] = []
            node_agents[addr].append(str(id).zfill(3))
    else:
        if agent_id is not None:
            node_agents[get_node_agent(agent_id)] = [str(agent_id).zfill(3)]
    return node_agents


def send_request_to_node(node, config_cluster, request_type, args, cluster_depth, result_queue):
    error, response = send_request(host=node, port=config_cluster["port"], key=config_cluster['key'],
                        data="{1} {2} {0}".format('a'*(common.cluster_protocol_plain_size - len(request_type + " " + str(cluster_depth) + " ")), request_type, str(cluster_depth)),
                         file=args)

    if error != 0 or response['error'] != 0:
        logging.debug(response)
        result_queue.put({'node': node, 'reason': "{0} - {1}".format(error, response), 'error': 1})
    else:
        result_queue.put(response)


def append_node_result_by_type(node, result_node, request_type, current_result=None):
    if current_result == None:
        current_result = {}
    if request_type == RESTART_AGENTS:
        if isinstance(result_node.get('data'), dict):
            if result_node.get('data').get('affected_agents') != None:
                if current_result.get('affected_agents') is None:
                    current_result['affected_agents'] = []
                current_result['affected_agents'].extend(result_node['data']['affected_agents'])

            if result_node.get('data').get('failed_ids'):
                if current_result.get('failed_ids') is None:
                    current_result['failed_ids'] = []
                current_result['failed_ids'].extend(result_node['data']['failed_ids'])

            if result_node.get('data').get('failed_ids') != None and result_node.get('data').get('msg') != None:
                current_result['msg'] = result_node['data']['msg']
            if current_result.get('failed_ids') == None and result_node.get('data').get('msg') != None:
                current_result['msg'] = result_node['data']['msg']
            if current_result.get('failed_ids') != None and current_result.get('affected_agents') != None:
                current_result['msg'] = "Some agents were not restarted"
        else:
            if current_result.get('data') == None:
                current_result = result_node
    elif request_type == MANAGERS_STATUS or request_type == MANAGERS_LOGS or request_type == MANAGERS_LOGS_SUMMARY :
        current_result[get_name_from_ip(node)] = result_node
    else:
        if result_node.get('data') != None:
            current_result = result_node['data']
        elif result_node.get('message') != None:
            current_result['message'] = result_node['message']
            current_result['error'] = result_node['error']
        #current_result[node] = result_node
    return current_result


def send_request_to_nodes(remote_nodes, config_cluster, request_type, args, cluster_depth=1):
    threads = []
    result = {}
    result_node = {}
    result_nodes = {}
    result_queue = queue()
    local_node = get_node()['node']
    remote_nodes_addr = []
    msg = None
    if len(remote_nodes) == 0:
        remote_nodes_addr = list(map(lambda x: x['url'], get_nodes()['items']))
    else:
        remote_nodes_addr = remote_nodes.keys()

    args_str = " ".join(args)

    for node_id in remote_nodes_addr:
        if node_id != None:
            logging.info("Sending {2} request from {0} to {1}".format(local_node, node_id, request_type))

            # Push agents id
            if remote_nodes.get(node_id) != None and len(remote_nodes[node_id]) > 0:
                agents = "-".join(remote_nodes[node_id])
                msg = agents
                if args_str > 0:
                    msg = msg + " " + args_str
            else:
                msg = args_str

            t = threading.Thread(target=send_request_to_node, args=(str(node_id), config_cluster, request_type, msg, cluster_depth, result_queue))
            threads.append(t)
            t.start()
            result_node = result_queue.get()
        else:
            result_node['data'] = {}
            result_node['data']['failed_ids'] = []
            for id in remote_nodes[node_id]:
                node = {}
                node['id'] = id
                node['error'] = {'message':"Agent not found",'code':-1}
                result_node['data']['failed_ids'].append(node)
        result_nodes[node_id] = result_node

    for t in threads:
        t.join()
    for node, result_node in result_nodes.iteritems():
        result = append_node_result_by_type(node, result_node, request_type, result)
    return result


def is_a_local_request():
    config_cluster = read_config()
    return not config_cluster or not check_cluster_status() or config_cluster['node_type'] == 'client'


def is_cluster_running():
    return status()['wazuh-clusterd'] == 'running'


def distributed_api_request(request_type, agent_id=None, args=[], cluster_depth=1, affected_nodes=None):
    config_cluster = read_config()
    node_agents = get_agents_by_node(agent_id)

    if affected_nodes != None and len(affected_nodes) > 0:
        if not isinstance(affected_nodes, list):
            affected_nodes = [affected_nodes]
        affected_nodes_addr = []
        for node in affected_nodes:
            if not re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").match(node):
                addr = get_ip_from_name(node)
                if addr != None:
                    affected_nodes_addr.append(addr)
            else:
                affected_nodes_addr.append(node)
        if len(affected_nodes_addr) == 0:
            return {}
        if node_agents != None and len(node_agents) > 0: #filter existing dict
            node_agents = {node: node_agents[node] for node in affected_nodes_addr}
        else: #make nodes dict
            node_agents = {node: [] for node in affected_nodes_addr}

    return send_request_to_nodes(node_agents, config_cluster, request_type, args, cluster_depth)


# agent.py

def restart_agents(agent_id=None, restart_all=False, cluster_depth=1):
    if is_a_local_request() or cluster_depth <= 0:
        return Agent.restart_agents(agent_id, restart_all)
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = RESTART_AGENTS
        args = [str(restart_all)]
        return distributed_api_request(request_type, agent_id, args, cluster_depth)


def get_upgrade_result(agent_id, timeout=3):
    if is_a_local_request():
        return Agent.get_upgrade_result(agent_id, timeout)
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = AGENTS_UPGRADE_RESULT
        args = [str(timeout)]
        return distributed_api_request(request_type, agent_id, args)


def upgrade_agent(agent_id, wpk_repo=None, version=None, force=False, chunk_size=None):
    if is_a_local_request():
        return Agent.upgrade_agent(agent_id, wpk_repo, version, force, chunk_size)
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = AGENTS_UPGRADE
        args = [str(wpk_repo), str(version), str(force), str(chunk_size)]
        return distributed_api_request(request_type, agent_id, args)


def upgrade_agent_custom(agent_id, file_path=None, installer=None):
    if is_a_local_request():
        return Agent.upgrade_agent_custom(agent_id, file_path, installer)
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = AGENTS_UPGRADE_CUSTOM
        args = [str(wpk_repo), str(version), str(force), str(chunk_size)]
        return distributed_api_request(request_type, agent_id, args)


# manager.py

def managers_status(node_id=None, cluster_depth=1):
    if is_a_local_request() or cluster_depth <= 0 :
        return status()
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = MANAGERS_STATUS
        return distributed_api_request(request_type=request_type, cluster_depth=cluster_depth, affected_nodes=node_id)


def managers_ossec_log(type_log='all', category='all', months=3, offset=0, limit=common.database_limit, sort=None, search=None, node_id=None, cluster_depth=1):
    if is_a_local_request() or cluster_depth <= 0 :
        return ossec_log(type_log, category, months, offset, limit, sort, search)
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = MANAGERS_LOGS
        args = [str(type_log), str(category), str(months), str(offset), str(limit), str(sort), str(search)]
        return distributed_api_request(request_type=request_type, args=args, cluster_depth=cluster_depth, affected_nodes=node_id)


def managers_ossec_log_summary(months=3, node_id=None, cluster_depth=1):
    if is_a_local_request() or cluster_depth <= 0 :
        return ossec_log_summary(months)
    else:
        if not is_cluster_running():
            raise WazuhException(3015)

        request_type = MANAGERS_LOGS_SUMMARY
        args = [str(months)]
        return distributed_api_request(request_type=request_type, args=args, cluster_depth=cluster_depth, affected_nodes=node_id)
