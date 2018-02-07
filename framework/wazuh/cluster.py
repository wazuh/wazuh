#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import cut_array, sort_array, search_array, md5
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.manager import status
from wazuh.configuration import get_ossec_conf
from wazuh.InputValidator import InputValidator
from wazuh import common
import sqlite3
from datetime import datetime
from hashlib import sha512
from time import time, mktime, sleep
from os import path, listdir, rename, utime, environ, umask, stat, mkdir, chmod, devnull, strerror, remove
from subprocess import check_output, check_call, CalledProcessError
from shutil import rmtree
from io import BytesIO
from itertools import compress, chain
from operator import itemgetter, eq, or_
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
import errno

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
            self.socket.connect((host, port))
        except socket.error as e:
            self.close()
            # raise WazuhException(3010, strerror(e[0]))
            raise WazuhException(3010, str(e))
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
        msg_len = len(msg)
        while i < msg_len:
            next_i = i+4096 if i+4096 < msg_len else msg_len
            sent = self.send(msg[i:next_i])
            if sent == 4096 or next_i == msg_len:
                i = next_i
            logging.debug("CLIENT: Sending {} of {}".format(i, msg_len))


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
    if len(cmd) != 2:
        return False

    # check cmd len
    if len(' '.join(cmd)) != common.cluster_protocol_plain_size:
        return False

    # 'ready' cmd can only be sent by a master node to a client node
    if cmd[0] == 'ready' and node_type == 'client':
        return True

    if cmd[0] == 'finished' and node_type == 'master':
        return True

    # check command type
    if not cmd[0] in ['zip', 'node']:
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

def get_file_info(filename, cluster_items, node_type):
    def is_synced_file(mtime, node_type):
        if node_type == 'master':
            return False
        else:
            return (datetime.now() - datetime.fromtimestamp(mtime)).seconds / 60 > 30

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


def compress_files(list_path, node_type, tobedeleted_files):
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

                if len(tobedeleted_files) > 0:
                    zf.writestr("remote_deleted.txt", '\n'.join(tobedeleted_files), compression)

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

def get_nodes(updateDBname=False):
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    cluster_socket = connect_to_db_socket()
    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()
    data = []
    error_response = False

    for url in config_cluster["nodes"]:
        if not url in localhost_ips:
            error, response = send_request(host=url, port=config_cluster["port"], key=config_cluster['key'],
                                data="node {0}".format('-'*(common.cluster_protocol_plain_size - len("node "))))
            if error == 0:
                if response['error'] == 0:
                    response = response['data']
                else:
                    logging.warning("Received an error response from {0}: {1}".format(url, response))
                    error_response = True
        else:
            error = 0
            url = "localhost"
            response = get_node()

        if error == 1:
            logging.warning("Error connecting with {0}: {1}".format(url, response))
            error_response = True

        if error_response:
            data.append({'error': response, 'node':'unknown', 'status':'disconnected', 'url':url})
            error_response = False
            continue

        if config_cluster['node_type'] == 'master' or \
           response['type'] == 'master' or url == "localhost":
            data.append({'url':url, 'node':response['node'],
                         'status':'connected', 'cluster':response['cluster']})

            if updateDBname:
                query = "insertname " +response['node'] + " " + url
                send_to_socket(cluster_socket, query)
                receive_data_from_db_socket(cluster_socket)

    cluster_socket.close()
    return {'items': data, 'totalItems': len(data)}



def get_node(name=None):
    data = {}
    if not name:
        config_cluster = read_config()

        if not config_cluster:
            raise WazuhException(3000, "No config found")

        data["node"]    = config_cluster["node_name"]
        data["cluster"] = config_cluster["name"]
        data["type"]    = config_cluster["node_type"]

    return data


def scan_for_new_files_one_node(node, cluster_items, cluster_config, cluster_socket=None, own_items=None, remove_rows=False):
    if not own_items:
        own_items = list_files_from_filesystem(cluster_config['node_type'], cluster_items)
    own_items_names = own_items.keys()

    # check files in database
    count_query = "count {0}".format(node)
    send_to_socket(cluster_socket, count_query)
    n_files = int(filter(lambda x: x != '\x00', cluster_socket.recv(10000)))
    removed = False

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

        all_files = {file:'pending' for file in own_items_names}

    else:
        logging.debug("Retrieving {0}'s files from database".format(node))
        all_files = get_file_status(node, cluster_socket)
        # if there are missing files that are not being controled in database
        # add them as pending
        set_own_items = set(own_items_names)
        set_all_files = set(all_files.keys())
        for missing in divide_list(set_own_items - set_all_files):
            insert_sql = "insert"
            for m in missing:
                all_files[m] = 'pending'
                insert_sql += " {0} {1}".format(node,m)

            send_to_socket(cluster_socket, insert_sql)
            data = receive_data_from_db_socket(cluster_socket)

        # remove files that are not present in the filesystem but present in the database
        # and have not been marked as deleted
        files_in_db = set_all_files - set_own_items
        for missing in divide_list(filter(lambda x: all_files[x] != "tobedeleted"
                                    and all_files[x] != 'deleted', files_in_db)):
            delete_sql = "update2"
            removed = True
            for m in missing:
                delete_sql += " tobedeleted {} {}".format(node, m)

            send_to_socket(cluster_socket, delete_sql)
            data = receive_data_from_db_socket(cluster_socket)

        if remove_rows:
            for deleted in divide_list(filter(lambda x: all_files[x] == 'deleted', set_all_files)):
                delete_sql = "delete2"
                for d in deleted:
                    delete_sql += " {} {}".format(node,d)
                send_to_socket(cluster_socket, delete_sql)
                data = receive_data_from_db_socket(cluster_socket)

    return all_files, removed


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
        scan_for_new_files_one_node(node, cluster_items, cluster_config, cluster_socket, own_items)

    cluster_socket.close()


def list_files_from_filesystem(node_type, cluster_items):
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
           item['source'] == 'all':
            fullpath = common.ossec_path + file_path
            expanded_items.extend(get_files_from_dir(fullpath, item['recursive'],item['files'], cluster_items))

    final_items = {}
    for new_item in expanded_items:
        try:
            final_items[new_item] = get_file_info(new_item, cluster_items, node_type)
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


    files = []

    nodes = get_remote_nodes(False)
    if manager:
        remote_nodes = filter(lambda x: x in manager, nodes)
    else:
        remote_nodes = nodes

    for node in remote_nodes:
        all_files = get_file_status(node, cluster_socket)
        if file_list == []:
            file_list = all_files.keys()

        try:
            files.extend([[node, file, all_files[file]] for file in file_list])
        except KeyError as e:
            logging.debug("File {} not found for node {}".format(file, node))

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
    for file in divide_list(files.items()):
        query = "insertfile "
        for fname, finfo in file:
            query += "{} {} {} ".format(fname, finfo['md5'], finfo['timestamp'])

        send_to_socket(cluster_socket, query)
        received = receive_data_from_db_socket(cluster_socket)


def clear_file_status():
    """
    Function to set all database files' status to pending
    """
    # Get information of files from filesystem
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")
    own_items = list_files_from_filesystem(config_cluster['node_type'], get_cluster_items())

    cluster_socket = connect_to_db_socket(retry=True)

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
            try:
                local_items = dict(filter(lambda x: db_items[x[0]]['md5'] != x[1]['md5']
                                or int(db_items[x[0]]['timestamp']) < int(x[1]['timestamp']), files_slice))
            except KeyError as e:
                new_items[e.args[0]] = {'md5': own_items[e.args[0]]['md5'],
                                        'timestamp': own_items[e.args[0]]['timestamp']}
                logging.debug("File not found in database: {0}".format(e.args[0]))
                continue
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


def _update_file(fullpath, new_content, umask_int=None, mtime=None, w_mode=None, node_type='master'):
    # Set Timezone to epoch converter
    # environ['TZ']='UTC'

    if path.basename(fullpath) == 'client.keys':
        if node_type=='client':
            _check_removed_agents(new_content.split('\n'))
        else:
            logging.warning("Client.keys file received in a master node.")
            raise WazuhException(3007)

    is_agent_info   = 'agent-info' in fullpath
    is_agent_groups = 'agent-groups' in fullpath
    if is_agent_info or is_agent_groups:
        if node_type=='master':
            # check if the date is older than the manager's date
            if path.isfile(fullpath) and datetime.fromtimestamp(int(stat(fullpath).st_mtime)) >= mtime:
                logging.warning("Receiving an old file ({})".format(fullpath))
                raise WazuhException(3012)
        elif is_agent_info:
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
    except IOError as e:
        if e.errno == errno.ENOENT:
            dirpath = path.dirname(fullpath)
            mkdir(dirpath)
            chmod(dirpath, S_IRWXU | S_IRWXG)
            dest_file = open(f_temp, "a+")
        else:
            raise e

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


def check_removed_files(removed_files):
    """
    Function to remove files not present in the remote node
    """
    deleted_files, failed_files = [], []
    for file_name in removed_files:
        try:
            full_path = common.ossec_path + file_name
            if path.exists(full_path):
                remove(full_path)
                logging.info("The file {0} has been deleted".format(full_path))
            else:
                logging.debug("The file {0} is not in the filesystem. Skipping.".format(full_path))
            deleted_files.append(file_name)
        except Exception as e:
            logging.error("Error deleting the file {0}: {1}".format(file_name, str(e)))
            failed_files.append({'item': file_name, 'reason': str(e)})

    return deleted_files, failed_files


def receive_zip(zip_file):
    cluster_items = get_cluster_items()
    config = read_config()
    logging.info("Receiving package with {0} files".format(len(zip_file)))

    final_dict = {'error':[], 'updated': [], 'deleted': []}
    restart = [False]

    if 'remote_groups.txt' in zip_file.keys():
        check_groups(set(zip_file['remote_groups.txt']['data'].split('\n')))
        del zip_file['remote_groups.txt']


    if 'remote_deleted.txt' in zip_file.keys():
        final_dict['deleted'], final_dict['error'] = check_removed_files(zip_file['remote_deleted.txt']['data'].split('\n'))
        del zip_file['remote_deleted.txt']

    for name,content in zip_file.items():
        try:
            fixed_name = '/' + name
            dir_name = path.dirname(fixed_name) + '/'
            file_path = common.ossec_path + fixed_name
            try:
                remote_umask = int(cluster_items[dir_name]['umask'], base=0)
                remote_write_mode = cluster_items[dir_name]['write_mode']
                restart.append(cluster_items[dir_name]['restart'])
            except KeyError:
                # cluster_items entries with the flag recursive = true will make
                # some paths to not match directly in this loop.
                key = path.split(dir_name[:-1])[0] + '/'

                remote_umask = int(cluster_items[key]['umask'], base=0)
                remote_write_mode = cluster_items[key]['write_mode']
                restart.append(cluster_items[key]['restart'])

            _update_file(file_path, new_content=content['data'],
                            umask_int=remote_umask,
                            mtime=content['time'],
                            w_mode=remote_write_mode,
                            node_type=config['node_type'])

        except Exception as e:
            logging.error("Error extracting zip file: {0}".format(str(e)))
            final_dict['error'].append({'item': name, 'reason': str(e)})
            continue

        final_dict['updated'].append(name)

    final_dict['restart'] = reduce(or_, restart)

    return final_dict


def divide_list(l, size=1000):
    return map(lambda x: filter(lambda y: y is not None, x), map(None, *([iter(l)] * size)))

def get_remote_nodes(connected=True, updateDBname=False):
    all_nodes = get_nodes(updateDBname)['items']

    # Get connected nodes in the cluster
    if connected:
        cluster = [n['url'] for n in filter(lambda x: x['status'] == 'connected',
                    all_nodes)]
    else:
        cluster = [n['url'] for n in all_nodes]
    # search the index of the localhost in the cluster
    try:
        localhost_index = cluster.index('localhost')
    except ValueError as e:
        logging.error("Cluster nodes are not correctly configured at ossec.conf.")
        exit(1)

    return list(compress(cluster, map(lambda x: x != localhost_index, range(len(cluster)))))


def run_logtest(synchronized=False):
    log_msg_start = "Synchronized r" if synchronized else "R"
    try:
        # check synchronized rules are correct before restarting the manager
        check_call(['{0}/bin/ossec-logtest -t'.format(common.ossec_path)], shell=True)
        logging.debug("{}ules are correct.".format(log_msg_start))
        return True
    except CalledProcessError as e:
        logging.warning("{}ules are not correct. Manager not restarted: {}.".format(log_msg_start, str(e)))
        return False


def check_files_to_restart(pending_files, cluster_items):
    restart_items = filter(lambda x: x[0] != 'excluded_files' and x[1]['restart'],
                            cluster_items.items())
    restart_files = {path.dirname(x[0])+'/' for x in pending_files} & {x[0] for x in restart_items}
    logging.debug("restart_files = {}".format(restart_files))
    if restart_files and not run_logtest():
        return {x for x in pending_files if path.dirname(x[0]) in restart_files}
    else:
        return set()


def push_updates_single_node(all_files, node_dest, config_cluster, removed, cluster_items, result_queue):
    # filter to send only pending files
    pending_files = set(filter(lambda x: x[1] != 'synchronized' and x[1] != 'tobedeleted' and x[1] != 'deleted', all_files.items()))
    tobedeleted_files = filter(lambda x: x[1] == 'tobedeleted', all_files.items())
    restart_files = check_files_to_restart(pending_files, cluster_items)
    pending_files -= restart_files

    if len(pending_files) > 0 or removed or len(tobedeleted_files) > 0:
        logging.info("Sending {0} {1} files".format(node_dest, len(pending_files)))
        zip_file = compress_files(list_path=set(map(itemgetter(0), pending_files)),
                                  node_type=config_cluster['node_type'],
                                  tobedeleted_files=map(itemgetter(0), tobedeleted_files))

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
        res = {'error': 0, 'data':{'updated':[], 'error':[], 'deleted':[], 'restart': False}}
        error = 0


    if error != 0:
        logging.error(res)
        result_queue.put({'node': node_dest, 'reason': "{0} - {1}".format(error, response),
                          'error': 1, 'files':{'updated':[], 'deleted':[],
                                        'error':list(map(itemgetter(0), pending_files))}})

    elif res['error'] != 0:
        logging.debug(res)
        result_queue.put({'node': node_dest, 'reason': "{0} - {1}".format(error, response),
                          'error': 1, 'files':{'updated':[], 'deleted':[],
                                        'error':list(map(itemgetter(0), pending_files)), 'restart': False}})
    else:
        logging.debug({'updated': len(res['data']['updated']),
                      'error': res['data']['error'],
                      'deleted': res['data']['deleted']})
        result_queue.put({'node': node_dest, 'files': res['data'], 'error': 0, 'reason': ""})


def update_node_db_after_sync(data, node, cluster_socket):
    logging.info("Updating {0}'s file status in DB".format(node))
    for updated in divide_list(data['files']['updated']):
        update_sql = "update2"
        for u in updated:
            update_sql += " synchronized {0} /{1}".format(node, u)

        send_to_socket(cluster_socket, update_sql)
        received = receive_data_from_db_socket(cluster_socket)

    for failed in divide_list(data['files']['error']):
        # delete_sql = "delete1"
        update_sql = "update2"
        for f in failed:
            if isinstance(f, dict):
                if f['reason'].startswith('Error 3012'):
                    if 'agent-info' in f['item']:
                        pass
                        #delete_sql += " /{0}".format(f['item'])
                    else:
                        # set old files as synchronized so the node doesn't send them anymore
                        update_sql += " synchronized {} /{}".format(node, f['item'])
                else:
                    update_sql += " failed {0} /{1}".format(node, f['item'])
            else:
                update_sql += " failed {0} {1}".format(node, f)

        send_to_socket(cluster_socket, update_sql)
        received = receive_data_from_db_socket(cluster_socket)
        # if len(delete_sql) > len("delete1"):
        #     send_to_socket(cluster_socket, delete_sql)
        #     received = receive_data_from_db_socket(cluster_socket)

    for deleted in divide_list(data['files']['deleted']):
        update_sql = "update2"
        for d in deleted:
            update_sql += " deleted {0} {1}".format(node, d)

        send_to_socket(cluster_socket, update_sql)
        received = receive_data_from_db_socket(cluster_socket)


def sync_one_node(debug, node, force=False, config_cluster=None, cluster_items=None):
    """
    Sync files with only one node
    """
    synchronization_date = time()
    synchronization_duration = 0.0

    if not config_cluster:
        config_cluster = read_config()

        if not config_cluster:
            raise WazuhException(3000, "No config found")

    if not cluster_items:
        cluster_items = get_cluster_items()

    before = time()
    # Get own items status
    own_items = list_files_from_filesystem(config_cluster['node_type'], cluster_items)
    own_items_names = own_items.keys()

    cluster_socket = connect_to_db_socket()
    logging.debug("Connected to cluster database socket")

    if force:
        clear_file_status_one_node(node, cluster_socket)
    all_files, removed = scan_for_new_files_one_node(node, cluster_items, config_cluster, cluster_socket, own_items, True)

    after = time()
    synchronization_duration += after-before
    logging.debug("Time retrieving info from DB: {0}".format(after-before))

    before = time()
    result_queue = queue()
    push_updates_single_node(all_files, node, config_cluster, removed, cluster_items, result_queue)

    after = time()
    synchronization_duration += after-before
    logging.debug("Time sending info: {0}".format(after-before))
    before = time()

    result = result_queue.get()
    update_node_db_after_sync(result, node, cluster_socket)
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
                  'deleted': result['files']['deleted'],
                  'error': result['error'],
                  'reason': result['reason']}


def sync(debug, force=False, config_cluster=None, cluster_items=None):
    """
    Sync this node with others
    :return: Files synced.
    """
    synchronization_date = time()
    synchronization_duration = 0.0

    if not config_cluster:
        config_cluster = read_config()
        if not config_cluster:
            raise WazuhException(3000, "No config found")

    if not cluster_items:
        cluster_items = get_cluster_items()

    before = time()
    # Get own items status
    own_items = list_files_from_filesystem(config_cluster['node_type'], cluster_items)
    own_items_names = own_items.keys()

    remote_nodes = get_remote_nodes(True, True)
    local_node = get_node()['node']
    logging.info("Starting to sync {0}'s files".format(local_node))

    cluster_socket = connect_to_db_socket()
    logging.debug("Connected to cluster database socket")

    # for each connected manager, check its files. If the manager is not on database add it
    # with all files marked as pending
    all_nodes_files = {}

    logging.debug("Nodes to sync: {0}".format(str(remote_nodes)))
    logging.info("Found {0} connected nodes".format(len(remote_nodes)))

    for node in remote_nodes:
        if force:
            clear_file_status_one_node(node, cluster_socket)
        all_nodes_files[node], removed = scan_for_new_files_one_node(node, cluster_items, config_cluster, cluster_socket, own_items, True)

    after = time()
    synchronization_duration += after-before
    logging.debug("Time retrieving info from DB: {0}".format(after-before))

    before = time()
    result_queue = queue()
    threads = []
    thread_results = {}
    for node in remote_nodes:
        t = threading.Thread(target=push_updates_single_node, args=(all_nodes_files[node],node,
                                                                    config_cluster, removed,
                                                                    cluster_items, result_queue))
        threads.append(t)
        t.start()
        result = result_queue.get()
        thread_results[result['node']] = {'files': result['files'], 'error': result['error'],
                                          'reason': result['reason']}

    for t in threads:
        t.join()
    after = time()
    synchronization_duration += after-before
    logging.debug("Time sending info: {0}".format(after-before))

    before = time()
    for node,data in thread_results.items():
        update_node_db_after_sync(data, node, cluster_socket)

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
                      'deleted': data['files']['deleted'],
                      'error': data['error'],
                      'reason': data['reason']}
                      for node,data in thread_results.items()}
