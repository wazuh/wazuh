#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh import common
from wazuh.InputValidator import InputValidator
from wazuh.configuration import get_ossec_conf
from wazuh.cluster.protocol_messages import all_list_requests
import socket
import asyncore
import asynchat
from operator import eq
import re
from time import sleep
import json
from subprocess import check_output
import logging
from glob import glob
from datetime import datetime
from os import strerror

# import the C accelerated API of ElementTree
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


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
        data = "Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography): {}".format(str(e))
        error = 1

    except WazuhException as e:
        error = 1
        data = str(e)

    return error, data


def get_status_json():
    def check_if_the_cluster_is_running():
        return glob("{0}/var/run/{1}-*.pid".format(common.ossec_path, 'wazuh-clusterd')) != []

    return {"enabled": "yes" if check_cluster_status() else "no",
            "running": "yes" if check_if_the_cluster_is_running() else "no"}


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
    if not cmd[0] in ['zip', 'node'] and not cmd[0] in all_list_requests.values():
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
    if config['node_type'] == 'master' and not re.compile("\d+[m|s]").match(config['interval']):
        raise WazuhException(3004, 'Invalid interval specification. Please, specify it with format <number>s or <number>m')
    if config['nodes'][0] == 'localhost' and len(config['nodes']) == 1:
        raise WazuhException(3004, 'Please specify IPs of all cluster nodes')


def get_cluster_items():
    try:
        cluster_items = json.load(open('{0}/framework/wazuh/cluster.json'.format(common.ossec_path)))
        return cluster_items
    except Exception as e:
        raise WazuhException(3005, str(e))


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


def get_ip_from_name(name, csocket=None):
    if csocket is None:
        cluster_socket = connect_to_db_socket()
    else:
        cluster_socket = csocket

    try:
        send_to_socket(cluster_socket, "getip {0}".format(name))
        data = receive_data_from_db_socket(cluster_socket)
        if data == "":
            data = None
    except Exception as e:
        logging.warning("Error getting IP of node {}: {}".format(name, str(e)))
        data = None

    if not data:
        logging.warning("Error getting IP of node: Received empty name")

    if csocket is None:
        cluster_socket.close()

    return data


def get_name_from_ip(addr, csocket=None):
    if csocket is None:
        cluster_socket = connect_to_db_socket()
    else:
        cluster_socket = csocket

    try:
        send_to_socket(cluster_socket, "getname {0}".format(addr))
        data = receive_data_from_db_socket(cluster_socket)
        if data == "":
            data = None
    except Exception as e:
        data = None

    if data == None:
        logging.warning("Error getting name of node {}: {}".format(addr, str(e)))

    if csocket is None:
        cluster_socket.close()

    return data


def get_actual_master(csocket=None):
    if csocket is None:
        cluster_socket = connect_to_db_socket()
    else:
        cluster_socket = csocket

    send_to_socket(cluster_socket, "selactual")
    url = receive_data_from_db_socket(cluster_socket)

    if url != " ":
        name = get_name_from_ip(url, cluster_socket)
        final_dict = {'name': name, 'url': url}
    else:
        final_dict = {'name': None, 'url': None}

    if csocket is None:
        cluster_socket.close()

    return final_dict


def insert_actual_master(node_name, csocket=None):
    if csocket is None:
        cluster_socket = connect_to_db_socket()
    else:
        cluster_socket = csocket

    send_to_socket(cluster_socket, "insertactual {0}".format(node_name))
    receive_data_from_db_socket(cluster_socket)

    if csocket is None:
        cluster_socket.close()


def select_actual_master(nodes):
    # check if there's already one actual master
    number_of_masters = len(list(filter(lambda x: x['type'] == 'master(*)', nodes)))
    if number_of_masters == 1:
        insert_actual_master(next (x['url'] for x in nodes if x['type'] == 'master(*)'))
        return nodes
    elif number_of_masters > 1:
        logging.info("Found {} elected masters. Restarting lection process...".format(number_of_masters))
        for node in nodes:
            if node['type'] == 'master(*)':
                node['type'] = 'master'

    # if there's no actual master, select one
    for node in nodes:
        if node['type'] == 'master':
            logging.info("The new elected master is {0}.".format(node['node']))
            node['type'] = 'master(*)'
            insert_actual_master(node['url'])
            break

    return nodes


get_localhost_ips = lambda: check_output(['hostname', '--all-ip-addresses']).split(" ")[:-1]


def get_nodes(updateDBname=False, get_localhost=False):
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
            response = get_node()
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
            csocket = connect_to_db_socket()

            query = "insertname " +response['node'] + " " + url
            send_to_socket(csocket, query)
            receive_data_from_db_socket(csocket)

            csocket.close()

    select_actual_master(data)

    return {'items': data, 'totalItems': len(data)}



def get_node(cluster_socket=None):
    data = {}
    config_cluster = read_config()

    if not config_cluster:
        raise WazuhException(3000, "No config found")

    data["node"]    = config_cluster["node_name"]
    data["cluster"] = config_cluster["name"]
    if get_actual_master(csocket=cluster_socket)['url'] in get_localhost_ips():
        data["type"] = "master(*)"
    else:
        data["type"] = config_cluster["node_type"]

    return data


def get_last_sync():
    """
    Function to retrieve information about the last synchronization
    """
    cluster_socket = connect_to_db_socket()

    send_to_socket(cluster_socket, "sellast")

    date, duration = receive_data_from_db_socket(cluster_socket).split(" ")

    cluster_socket.close()

    return str(datetime.fromtimestamp(int(date))), float(duration)


def get_file_status(manager, cluster_socket, offset=0, limit=None, status="all"):
    if not limit:
        count_query = "count {0}".format(manager) if status == "all" else "countstatus {0} {1}".format(manager, status)
        send_to_socket(cluster_socket, count_query)
        n_files = int(receive_data_from_db_socket(cluster_socket))
        limit = n_files
        step = 100
    else:
        step = limit if limit < 100 else 100

    query = "select {0} {1} ".format(manager, step) if status == "all" else "selectstatus {0} {1} {2} ".format(manager, status, step)
    file_status = ""
    # limit = 100
    for offset in range(offset,limit,step):
        send_to_socket(cluster_socket, query + str(offset))
        file_status += receive_data_from_db_socket(cluster_socket)

    # retrieve all files for a node in database with its status
    all_files = [{'filename':f[0], 'status':f[1]} for f in
                    map(lambda x: x.split('*'), filter(lambda x: x != '',
                    file_status.split(' ')))]

    return all_files


def read_id_manager_param(manager, cluster_socket):
    fix_manager = []
    for m in manager:
        if re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").match(m):
            fix_manager.append(m)
        elif re.compile(r"\w+").match(m):
            fix_manager.append(get_ip_from_name(m, cluster_socket))
        else:
            raise WazuhException(3014, m)
    return fix_manager


def get_file_status_all_managers(file_list, manager, status="all", offset=0, limit=None):
    """
    Return a nested list where each element has the following structure
    [manager, filename, status]
    """
    cluster_socket = connect_to_db_socket()
    if manager:
        manager = read_id_manager_param(manager, cluster_socket)

    files = []

    nodes = set(read_config()['nodes']) - set(get_localhost_ips())

    if manager:
        remote_nodes = filter(lambda x: x in manager, nodes)
    else:
        remote_nodes = nodes

    for node in remote_nodes:
        all_files = get_file_status(manager=node, cluster_socket=cluster_socket, status=status, offset=offset, limit=limit)
        if file_list == []:
            local_file_list = all_files
        else:
            local_file_list = filter(lambda x: x['filename'] in file_list, all_files)

        files.extend([[get_name_from_ip(node, cluster_socket), file['filename'], file['status']] for file in local_file_list])

    cluster_socket.close()
    return files


def get_file_status_json(file_list = {'fields':[]}, manager = {'fields':[]}, offset=0, limit=common.database_limit, count=False, filter_status="all"):
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
    offset = int(offset)
    limit = int(limit)

    files = get_file_status_all_managers(file_list['fields'], manager['fields'], filter_status, offset, limit)
    cluster_socket = connect_to_db_socket()
    cluster_dict = {}
    for manager, file, status in files:
        try:
            if not count:
                cluster_dict[manager]['items'].append({'filename': file, 'status': status})
        except KeyError:
            manager_ip = get_ip_from_name(manager, cluster_socket)
            count_query = "count {0}".format(manager_ip) if status == "all" else "countstatus {0} {1}".format(manager_ip, status)
            send_to_socket(cluster_socket, count_query)
            cluster_dict[manager] = {'totalItems': int(receive_data_from_db_socket(cluster_socket)), 'items': []}
            if not count:
                cluster_dict[manager]['items'].append({'filename': file, 'status': status})

    cluster_socket.close()
    return cluster_dict


def get_file_status_one_node_json(node_id, file_list = {'fields':[]}, offset=0, limit=common.database_limit, count=False, status="all"):
    cluster_socket = connect_to_db_socket()

    node_id = read_id_manager_param([node_id], cluster_socket)[0]

    count_query = "count {0}".format(node_id) if status == "all" else "countstatus {0} {1}".format(node_id, status)
    send_to_socket(cluster_socket, count_query)
    n_files = int(receive_data_from_db_socket(cluster_socket))

    if not count:
        files = get_file_status(manager=node_id, cluster_socket=cluster_socket, offset=int(offset), limit=int(limit), status=status)

    cluster_socket.close()

    if not count:
        return {'items': files, 'totalItems': n_files}
    else:
        return {'totalItems': n_files}
