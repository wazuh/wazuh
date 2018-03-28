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
from datetime import datetime, timedelta
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
import asyncore
import asynchat
import errno
import struct

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




#
# Both: Master & Client
#
def walk_dir(dirname, recursive, files, excluded_files, get_cluster_item_key, get_md5=True, whoami='master'):
    walk_files = {}

    try:
        entries = listdir(dirname)
    except OSError as e:
        raise WazuhException(3015, str(e))

    for entry in entries:
        if entry in excluded_files or entry[-1] == '~':
            continue

        if entry in files or files == ["all"]:
            full_path = path.join(dirname, entry)

            if not path.isdir(full_path):
                file_mod_time = datetime.utcfromtimestamp(stat(full_path).st_mtime)

                if whoami == 'client' and file_mod_time < (datetime.utcnow() - timedelta(minutes=30)):
                    continue

                new_key = full_path.replace(common.ossec_path, "")
                walk_files[new_key] = {"mod_time" : str(file_mod_time), 'cluster_item_key': get_cluster_item_key}

                if get_md5:
                    walk_files[new_key]['md5'] = md5(full_path)

            elif recursive:
                walk_files.update(walk_dir(full_path, recursive, files, excluded_files, get_cluster_item_key, get_md5, whoami))

    return walk_files

def get_files_status(node_type, get_md5=True):

    cluster_items = get_cluster_items()

    final_items = {}
    for file_path, item in cluster_items.items():
        if file_path == "excluded_files":
            continue
        if item['source'] == node_type or item['source'] == 'all':
            fullpath = common.ossec_path + file_path
            try:
                final_items.update(walk_dir(fullpath, item['recursive'], item['files'], cluster_items['excluded_files'], file_path, get_md5, node_type))
            except WazuhException as e:
                logging.warning(e)

    return final_items



def compress_files2(source, list_path, cluster_control_json=None):
    path_files = "files/"
    zipped_file = BytesIO()
    with zipfile.ZipFile(zipped_file, 'w') as zf:
        # write files
        for f in list_path:
            try:
                zf.write(filename = common.ossec_path + f, arcname = path_files + f, compress_type=compression)
            except Exception as e:
                logging.error(str(WazuhException(3001, str(e))))

        try:
            zf.writestr("cluster_control.json", json.dumps(cluster_control_json), compression)
        except Exception as e:
            raise WazuhException(3001, str(e))

    return zipped_file.getvalue()


def decompress_files2(zip_bytes):
    zip_json = {}
    with zipfile.ZipFile(BytesIO(zip_bytes)) as zipf:
        zip_json = {name:{'data':zipf.open(name).read(), 'time':datetime(*zipf.getinfo(name).date_time)} for name in zipf.namelist()}

    return zip_json


def _update_file2(fullpath, new_content, umask_int=None, mtime=None, w_mode=None, whoami='master'):

    if path.basename(fullpath) == 'client.keys':
        if whoami =='client':
            logging.info("ToDo: _check_removed_agents***********************************************")
            #_check_removed_agents(new_content.split('\n'))
        else:
            logging.warning("Client.keys file received in a master node.")
            raise WazuhException(3007)

    is_agent_info   = 'agent-info' in fullpath
    is_agent_groups = 'agent-groups' in fullpath
    if is_agent_info or is_agent_groups:
        if whoami =='master':
            # check if the date is older than the manager's date
            if path.isfile(fullpath) and datetime.utcfromtimestamp(int(stat(fullpath).st_mtime)) > mtime:
                #logging.debug("Receiving an old file ({})".format(fullpath))
                return
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


class WazuhClusterClient2():
    def __init__(self, host, port, key, data, file, connection_timeout, socket_timeout):
        self.can_close = False
        self.received_data = []
        self.response = ""
        self.f = key
        self.data = data
        self.file = file
        self.addr = host
        self.port = port
        self.terminator = '\n'
        self.chunk = 4096
        self.connection_timeout = 100 #connection_timeout
        self.socket_timeout = 100 #socket_timeout
        self.connect()


    def connect(self):
        # the two exceptions need to be processed separately because the first
        # one doesn't need to close the socket since it creates it but
        # the second one needs to both close the socket and raise the exception
        try:
            self.socket = socket.create_connection((self.addr, self.port),
                                                    self.connection_timeout)
        except socket.error as e:
            raise WazuhException(3010, str(e))

        try:
            self.socket.settimeout(self.socket_timeout)
        except socket.error as e:
            self.can_close = True
            self.socket.close()
            raise WazuhException(3010, str(e))


    def handle_close(self):
        if self.can_close:
            self.close()


    def handle_receive(self):
        data = ""
        self.received_data = []
        try:
            while not self.terminator in data:
                data = self.socket.recv(self.chunk)
                self.received_data.append(data)
        except socket.error as e:
            logging.error("Could not receive data from {}: {}".format(self.addr, str(e)))
            if str(e) == "timed out":
                logging.warning("Try increasing socket_timeout configuration at ossec.conf to solve this issue and check your firewall is properly configured")
            raise e
        self.found_terminator()

    def found_terminator(self):
        logging.debug("Received {}".format(len(''.join(self.received_data))))

        try:
            self.response = json.loads(self.f.decrypt(''.join(self.received_data)))
        except (InvalidSignature, InvalidToken) as e:
            raise InvalidToken("Could not encrypt message")
        except: # ToDo: Improve this. It shoul be like a cmd?
            response = b''.join(self.received_data)
            self.response = self.f.decrypt(response)

        self.handle_close()

    def handle_write(self):
        try:
            if self.file is not None:
                msg = self.f.encrypt(self.data.encode() + self.file) + '\n\t\t\n'
            else:
                msg = self.f.encrypt(self.data.encode()) + '\n\t\t\n'
        except (InvalidToken, InvalidSignature) as e:
            raise InvalidToken("Could not encrypt message")

        try:
            i = 0
            msg_len = len(msg)
            while i < msg_len:
                next_i = i+self.chunk if i+self.chunk < msg_len else msg_len
                sent = self.socket.send(msg[i:next_i])
                i += sent

            logging.debug("CLIENT: Sent {}/{} bytes to {}".format(i, msg_len, self.addr))
            self.handle_receive()
        except socket.error as e:
            logging.error("Could not send data to {}: {}".format(self.addr, str(e)))
            raise e

def send_request2(host, port, key, data, connection_timeout, socket_timeout, file=None):
    error = 0
    try:
        logging.debug("Active connections: {}".format(common.cluster_connections.keys()))
        client = common.cluster_connections.get(host)
        if not client:
            logging.debug("No opened connection with {}".format(host))
            fernet_key = Fernet(key.encode('base64','strict'))
            client = WazuhClusterClient2(host, int(port), fernet_key, data, file, connection_timeout, socket_timeout)
            client.handle_write()
            response = client.response
            common.cluster_connections[host] = client
        else:
            connection_status = get_connection_status(common.cluster_connections[host].socket)
            logging.debug("Connection status with {} is {}".format(host, connection_status))
            if connection_status == 'ESTABLISHED':
                client.data = data
                client.file = file
                try:
                    client.handle_write()
                except socket.error as e:
                    # if the error is reported as timed out, remove the connection
                    # and create a new socket on the next iteration. This way,
                    # the socket will not be ESTABLISHED but "disconnected"
                    if str(e) == 'timed out':
                        logging.debug("Closing connection with {}".format(host))
                        common.cluster_connections[host].socket.close()
                        del common.cluster_connections[host]
                    raise e
                response = client.response
            else:
                common.cluster_connections[host].socket.close()
                del common.cluster_connections[host]
                return send_request2(host, port, key, data, connection_timeout, socket_timeout, file)

    except NameError as e:
        response = "Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography)"
        error = 1

    except Exception as e:
        logging.error("Error sending request to {}: {}".format(host, str(e)))
        error = 1
        response = str(e)

    return error, response







#
# Master
#
def compare_files(good_files, check_files):

    missing_files = set(good_files.keys()) - set(check_files.keys())
    extra_files = set(check_files.keys()) - set(good_files.keys())

    shared_files = {name: {'cluster_item_key': data['cluster_item_key']} for name, data in good_files.iteritems() if name in check_files and data['md5'] != check_files[name]['md5']}

    if not missing_files:
        missing_files = {}
    else:
        missing_files = {missing_file: {'cluster_item_key': good_files[missing_file]['cluster_item_key']} for missing_file in missing_files }

    if not extra_files:
        extra_files = {}
    else:
        extra_files = {extra_file: {'cluster_item_key': check_files[extra_file]['cluster_item_key']} for extra_file in extra_files }

    return {'missing': missing_files, 'extra': extra_files, 'shared': shared_files}


def update_client_files_in_master(json_file, files_to_update):
    cluster_items = get_cluster_items()

    try:

        for file_name, data in json_file.iteritems():
            # Full path
            file_path = common.ossec_path + file_name

            # Cluster items information: write mode and umask
            cluster_item_key = data['cluster_item_key']
            w_mode = cluster_items[cluster_item_key]['write_mode']
            umask = int(cluster_items[cluster_item_key]['umask'], base=0)

            # File content and time
            file_data = files_to_update[file_name]['data']
            file_time = files_to_update[file_name]['time']

            _update_file2(fullpath=file_path, new_content=file_data, umask_int=umask, mtime=file_time, w_mode=w_mode, whoami='master')

    except Exception as e:
        print(str(e))
        raise e

def process_files_from_client(data_received):
    logging.info("[Master] [Data received]: Start.")

    # Extract recevied data
    logging.info("[Master] [Data received] [STEP 1]: Analyzing received files.")

    master_files_from_client = {}
    client_files = {}
    for key in data_received:
        if key == 'cluster_control.json':
            json_file = json.loads(data_received['cluster_control.json']['data'])
            master_files_from_client = json_file['master_files']
            client_files_json = json_file['client_files']
        else:
            full_path_key = key.replace('files/', '/')
            client_files[full_path_key] = data_received[key]

    # Get master files
    master_files = get_files_status('master')

    # Compare
    client_files_ko = compare_files(master_files, master_files_from_client)

    logging.info("[Master] [Data received] [STEP 2]: Updating manager files.")
    # Update files
    update_client_files_in_master(client_files_json, client_files)

    # Compress data: master files (only KO shared and missing)
    logging.info("[Master] [Data received] [STEP 3]: Compressing KO files for client.")

    master_files_paths = [item for item in client_files_ko['shared']]
    master_files_paths.extend([item for item in client_files_ko['missing']])

    compressed_data = compress_files2('master', master_files_paths, client_files_ko)

    logging.info("[Master] [Data received]: End. Sending KO files to client.")
    # Send KO files
    return compressed_data




#
# Client
#
def update_master_files_in_client(wrong_files, files_to_update):

    cluster_items = get_cluster_items()

    if not wrong_files['shared'] and not wrong_files['missing'] and not wrong_files['extra']:
        logging.info("[Client] [Sync process] [Step 3]: Client meets integrity checks. No actions.")
    else:
        logging.info("[Client] [Sync process] [Step 3]: Client does not meet integrity checks. Actions required.")


    if wrong_files['shared']:
        logging.info("[Client] [Sync process] [Step 3]: Received {} wrong files to fix from master. Action: Overwrite files.".format(len(wrong_files['shared'])))
        try:
            for file_to_overwrite, data in wrong_files['shared'].iteritems():
                logging.debug("\tOVERWRITE {0}".format(file_to_overwrite))
                # Full path
                file_path = common.ossec_path + file_to_overwrite

                # Cluster items information: write mode and umask
                cluster_item_key = data['cluster_item_key']
                w_mode = cluster_items[cluster_item_key]['write_mode']
                umask = int(cluster_items[cluster_item_key]['umask'], base=0)

                # File content and time
                file_data = files_to_update[file_to_overwrite]['data']
                file_time = files_to_update[file_to_overwrite]['time']

                _update_file2(fullpath=file_path, new_content=file_data, umask_int=umask, mtime=file_time, w_mode=w_mode, whoami='client')

        except Exception as e:
            print(str(e))
            raise e

    if wrong_files['missing']:
        logging.info("[Client] [Sync process] [Step 3]: Received {} missing files from master. Action: Create files.".format(len(wrong_files['missing'])))
        for file_to_create, data in wrong_files['missing'].iteritems():
            logging.debug("\tCREATE {0}".format(file_to_create))

            # Full path
            file_path = common.ossec_path + file_to_create

            # Cluster items information: write mode and umask
            cluster_item_key = data['cluster_item_key']
            w_mode = cluster_items[cluster_item_key]['write_mode']
            umask = int(cluster_items[cluster_item_key]['umask'], base=0)

            # File content and time
            file_data = files_to_update[file_to_create]['data']
            file_time = files_to_update[file_to_create]['time']

            _update_file2(fullpath=file_path, new_content=file_data, umask_int=umask, mtime=file_time, w_mode=w_mode, whoami='client')


    if wrong_files['extra']:
        logging.info("[Client] [Sync process] [Step 3]: Received {} extra files from master. Action: Remove files.".format(len(wrong_files['extra'])))
        for file_to_remove in wrong_files['extra']:
            logging.debug("\tREMOVE {0}".format(file_to_remove))
            file_path = common.ossec_path + file_to_remove
            remove(file_path)

    return True


def process_files_from_master(data_received):

    # Extract recevied data
    ko_files = {}
    master_files = {}
    for key in data_received:
        if key == 'cluster_control.json':
            ko_files = json.loads(data_received['cluster_control.json']['data'])
        else:
            full_path_key = key.replace('files/', '/')
            master_files[full_path_key] = data_received[key]

    # Update files
    update_result = update_master_files_in_client(ko_files, master_files)

    return update_result

def send_client_files_to_master(master_node, config_cluster, files):
    sync_result = False

    logging.info("[Client] [Sync process]: Start.")

    logging.info("[Client] [Sync process] [Step 1]: Gathering files.")
    # Get master files (path, md5, mtime): client.keys, ossec.conf, groups, ...
    master_files = get_files_status('master')
    client_files = get_files_status('client', get_md5=False)
    cluster_control_json = {'master_files': master_files, 'client_files': client_files}

    # Getting client file paths: agent-info, agent-groups.
    client_files_paths = client_files.keys()

    # Compress data: client files + control json
    compressed_data = compress_files2('client', client_files_paths, cluster_control_json)


    # Send compressed file to master
    logging.info("[Client] [Sync process] [Step 2]: Sending files to master.")
    error, response = send_request2( host=master_node,
                                    port=config_cluster["port"],
                                    key=config_cluster['key'],
                                    connection_timeout=100, #int(config_cluster['connection_timeout']),
                                    socket_timeout=100, #int(config_cluster['socket_timeout']),
                                    #data="zip {0}".format(str(len(compressed_data)).zfill(common.cluster_protocol_plain_size - len("zip "))),
                                    data="m_c_sync {0}".format(str(len(compressed_data)).zfill(common.cluster_protocol_plain_size - len("m_c_sync "))),
                                    file=compressed_data
    )

    # Update files
    if error == 0:
        if 'error' in response and 'data' in response:
            if response['error'] != 0:
                logging.error("[Client] [Sync process] [Step 3]: ERROR receiving files from master (1): {}".format(response['data']))
        else:
            try:
                logging.info("[Client] [Sync process] [Step 3]: KO files received from master.")
                master_data  = decompress_files2(response)
                sync_result = process_files_from_master(master_data)
            except Exception as e:
                logging.error("[Client] [Sync process] [Step 3]: ERROR receiving files from master (2): {}".format(str(e)))
    else:
        logging.error("[Client] [Sync process] [Step 3]: ERROR receiving files from master")

    # Send ACK
    # ToDo

    # Log
    logging.info("[Client] [Sync process]: Result - {}.".format(sync_result))


#
# Review
#

def get_connection_status(host_socket):
    # Taken from: http://www.cse.scu.edu/~dclark/am_256_graph_theory/linux_2_6_stack/linux_2tcp_8h-source.html (line 78)
    tcp_states = {
        1: 'ESTABLISHED',
        2: 'SYN_SENT',
        3: 'SYN_RECV',
        4: 'FIN_WAIT1',
        5: 'FIN_WAIT2',
        6: 'TIME_WAIT',
        7: 'CLOSE',
        8: 'CLOSE_WAIT',
        9: 'LAST_ACK',
        10: 'LISTEN',
        11: 'CLOSING'
    }
    # retrieve a struct tcp_info (/usr/include/linux/tcp.h). The first value is
    # the status of the connection
    state = struct.unpack("B"*7+"I"*24, host_socket.getsockopt(socket.SOL_TCP,
                                                    socket.TCP_INFO, 104))[0]
    return tcp_states[state]


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
    reservated_ips = {'localhost', 'NODE_IP', '0.0.0.0', '127.0.1.1'}

    if not 'key' in config.keys():
        raise WazuhException(3004, 'Unspecified key')
    elif not iv.check_name(config['key']) or not iv.check_length(config['key'], 32, eq):
        raise WazuhException(3004, 'Key must be 32 characters long and only have alphanumeric characters')

    if config['node_type'] != 'master' and config['node_type'] != 'client':
        raise WazuhException(3004, 'Invalid node type {0}. Correct values are master and client'.format(config['node_type']))
    if not re.compile("\d+[m|s]").match(config['interval']):
        raise WazuhException(3004, 'Invalid interval specification. Please, specify it with format <number>s or <number>m')

    if len(config['nodes']) == 0:
        raise WazuhException(3004, 'No nodes defined in cluster configuration.')

    invalid_elements = list(reservated_ips & set(config['nodes']))

    if len(invalid_elements) != 0:
        raise WazuhException(3004, "Invalid elements in node fields: {0}.".format(', '.join(invalid_elements)))

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
        if not config_cluster.get('socket_timeout'):
            config_cluster['socket_timeout'] = 5
        if not config_cluster.get('connection_timeout'):
            config_cluster['connection_timeout'] = 1
    except WazuhException as e:
        if e.code == 1102:
            raise WazuhException(3006, "Cluster configuration not present in ossec.conf")
        else:
            raise WazuhException(3006, e.message)
    except Exception as e:
        raise WazuhException(3006, str(e))

    return config_cluster


get_localhost_ips = lambda: check_output(['hostname', '--all-ip-addresses']).split(" ")[:-1]

def get_nodes2():
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()

    data = []
    error_response = False

    for url in config_cluster["nodes"]:
        try:
            if not url in localhost_ips:
                error, response = send_request2(host=url, port=config_cluster["port"], key=config_cluster['key'],
                                    connection_timeout=int(config_cluster['connection_timeout']),
                                    socket_timeout=int(config_cluster['socket_timeout']),
                                    data="node {0}".format('-'*(common.cluster_protocol_plain_size - len("node "))))
                if error == 0:
                    if response['error'] == 0:
                        response = response['data']
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
                data.append({'error': response, 'node':'unknown', 'type':'unknown', 'status':'disconnected', 'url':url, 'localhost': False})
                error_response = False
                continue

            if config_cluster['node_type'] == 'master' or \
               response['type'] == 'master' or response["localhost"]:
                data.append({'url':url, 'node':response['node'], 'type': response['type'], 'localhost': response['localhost'],
                             'status':'connected', 'cluster':response['cluster']})

        except TypeError as e:
            error_text = "Response from {} is not in JSON format: {} ({})".format(url, str(e), response)
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})
        except Exception as e:
            error_text = "Error getting information of node {}: {}".format(url, str(e))
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})

    return {'items': data, 'totalItems': len(data)}



def get_nodes(updateDBname=False, config=None):
    if not config:
        config_cluster = read_config()
        if not config_cluster:
            raise WazuhException(3000, "No config found")
    else:
        config_cluster = config

    cluster_socket = connect_to_db_socket()
    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()
    data = []
    error_response = False

    for url in config_cluster["nodes"]:
        try:
            if not url in localhost_ips:
                error, response = send_request(host=url, port=config_cluster["port"], key=config_cluster['key'],
                                    connection_timeout=int(config_cluster['connection_timeout']),
                                    socket_timeout=int(config_cluster['socket_timeout']),
                                    data="node {0}".format('-'*(common.cluster_protocol_plain_size - len("node "))))
                if error == 0:
                    if response['error'] == 0:
                        response = response['data']
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
                data.append({'error': response, 'node':'unknown', 'type':'unknown', 'status':'disconnected', 'url':url, 'localhost': False})
                error_response = False
                continue

            if config_cluster['node_type'] == 'master' or \
               response['type'] == 'master' or response["localhost"]:
                data.append({'url':url, 'node':response['node'], 'type': response['type'], 'localhost': response['localhost'],
                             'status':'connected', 'cluster':response['cluster']})

                if updateDBname:
                    query = "insertname " +response['node'] + " " + url
                    send_to_socket(cluster_socket, query)
                    receive_data_from_db_socket(cluster_socket)
        except TypeError as e:
            error_text = "Response from {} is not in JSON format: {} ({})".format(url, str(e), response)
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})
        except Exception as e:
            error_text = "Error getting information of node {}: {}".format(url, str(e))
            logging.error(error_text)
            data.append({'url': url, 'node': 'unknown', 'type': 'unknown', 'status': 'connected', 'url':url, 'error': error_text, 'localhost': False})

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


def divide_list(l, size=1000):
    return map(lambda x: filter(lambda y: y is not None, x), map(None, *([iter(l)] * size)))

def get_remote_nodes(connected=True, updateDBname=False, config=None):
    try:
        all_nodes = get_nodes(updateDBname, config)['items']
    except Exception as e:
        logging.error("Could not get remote nodes' information: {}".format(str(e)))
        raise #WazuhException(3017, str(e))

    # Get connected nodes in the cluster
    if connected:
        cluster = [(n['url'], n['localhost']) for n in filter(lambda x: x['status'] == 'connected',
                    all_nodes)]
    else:
        cluster = [(n['url'], n['localhost']) for n in all_nodes]
    # search the index of the localhost in the cluster
    try:
        localhost_index = next (x[0] for x in enumerate(cluster) if x[1][1])
    except StopIteration as e:
        logging.error("Cluster nodes are not correctly configured at ossec.conf.")
        raise WazuhException(3016)

    return list(compress(map(itemgetter(0), cluster), map(lambda x: x != localhost_index, range(len(cluster)))))


def run_logtest(synchronized=False):
    log_msg_start = "Synchronized r" if synchronized else "R"
    try:
        # check synchronized rules are correct before restarting the manager
        check_call(['{0}/bin/ossec-logtest -t'.format(common.ossec_path)], shell=True)
        logging.debug("{}ules are correct.".format(log_msg_start))
        return True
    except CalledProcessError as e:
        logging.warning("{}ules are not correct.".format(log_msg_start, str(e)))
        return False


def check_files_to_restart(pending_files, cluster_items):
    restart_items = filter(lambda x: x[0] != 'excluded_files' and x[1]['restart'],
                            cluster_items.items())
    restart_files = {path.dirname(x[0])+'/' for x in pending_files} & {x[0] for x in restart_items}
    if restart_files != set() and not run_logtest():
        return {x for x in pending_files if path.dirname(x[0])+'/' in restart_files}
    else:
        return set()
