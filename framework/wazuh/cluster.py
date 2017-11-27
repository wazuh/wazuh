#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import cut_array, sort_array, search_array, md5
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.configuration import get_ossec_conf
from wazuh.InputValidator import InputValidator
from wazuh import common
import sqlite3
from datetime import datetime
from hashlib import sha512
from time import time, mktime
from os import path, listdir, rename, utime, environ, umask, stat, mkdir, chmod
from subprocess import check_output
from shutil import rmtree
from io import BytesIO
from itertools import compress, chain
import operator
from operator import itemgetter
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

def check_cluster_status():
    """
    Function to check if cluster is enabled in ossec-control
    """
    with open("/etc/ossec-init.conf") as f:
        # the osec directory is the first line of ossec-init.conf
        directory = f.readline().split("=")[1][:-1].replace('"', "")

    try:
        process_list = check_output(["tac", "{0}/bin/.process_list".format(directory)]).split('\n')
    except:
        return False
    for process in process_list:
        if process == 'CLUSTER_DAEMON=""':
            return False
        elif process == 'CLUSTER_DAEMON=wazuh-clusterd':
            return True
    return False

# import python-cryptography lib only if cluster is enabled at ossec-control
if check_cluster_status():
    try:
        from cryptography.fernet import Fernet
    except ImportError as e:
        print("Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography)")
        exit(-1)


class WazuhClusterClient(asynchat.async_chat):
    def __init__(self, host, port, key, data, file):
        asynchat.async_chat.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))
        self.data = data
        self.file = file
        self.set_terminator('\n')
        self.response = ""
        self.can_read = False
        self.can_write = True
        self.received_data = []
        self.f = key

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def readable(self):
        return self.can_read

    def writable(self):
        return self.can_write

    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()
        self.close()
        raise t(v)

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
        asyncore.loop(timeout=common.cluster_timeout)
        data = client.response

    except NameError as e:
        data = "Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography)"
        error = 1

    except Exception as e:
        error = 1
        data = str(e)
    return error, data


def check_cluster_cmd(cmd):
    # cmd must be a list
    if not isinstance(cmd, list):
        return False

    # check command type
    if not cmd[0] in ['zip', 'node']:
        return False

    # check cmd len list
    if len(cmd) != 2:
        return False

    # check cmd len
    if len(' '.join(cmd)) != common.cluster_protocol_plain_size:
        return False

    # second argument of zip is a number
    if cmd[0] == 'zip' and not re.compile('\d+').match(cmd[1]):
        return False

    return True


def check_cluster_config(config):
    iv = InputValidator()

    if not 'key' in config.keys():
        raise WazuhException(3004, 'Unspecified key')
    elif not iv.check_name(config['key']) or not iv.check_length(config['key'], 32, operator.eq):
        raise WazuhException(3004, 'Key must be 32 characters long and only have alphanumeric characters')

    if config['node_type'] != 'master' and config['node_type'] != 'client':
        raise WazuhException(3004, 'Invalid node type {0}. Correct values are master and client'.format(config['node_type']))
    if not re.compile("\d+[m|s]").match(config['interval']):
        raise WazuhException(3004, 'Invalid interval specification. Please, specify it with format <number>s or <number>m')
    if config['nodes'][0] == 'localhost' and len(config['nodes']) == 1:
        raise WazuhException(3004, 'Please specify IPs of all cluster nodes')


def get_file_info(filename, cluster_items):
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
        "size" : st_size,
        'is_synced': st_mtime.is_integer()
    }

    return file_item


def compress_files(list_path):
    zipped_file = BytesIO()
    with zipfile.ZipFile(zipped_file, 'w') as zf:
        # write files
        for f in list_path:
            try:
                zf.write(filename = common.ossec_path + f, arcname = f, compress_type=compression)
            except Exception as e:
                logging.error(str(WazuhException(3001, str(e))))

    return zipped_file.getvalue()

def read_config():
    # Get api/configuration/config.js content
    try:
        config_cluster = get_ossec_conf('cluster')

    except Exception as e:
        raise WazuhException(3000, str(e))

    return config_cluster


get_localhost_ips = lambda: check_output(['hostname', '--all-ip-addresses']).split(" ")[:-1]

def get_nodes():
    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")

    # list with all the ips the localhost has
    localhost_ips = get_localhost_ips()
    data = []

    for url in config_cluster["nodes"]:
        if not url in localhost_ips:
            error, response = send_request(host=url, port=config_cluster["port"], key=config_cluster['key'],
                                data="node {0}".format('a'*(common.cluster_protocol_plain_size - len("node "))))
            if error == 0:
                response = response['data']
        else:
            error = 0
            url = "localhost"
            response = get_node()

        if error:
            logging.warning("Error connecting with {0}: {1}".format(url, response))
            data.append({'error': response, 'node':'unknown', 'status':'disconnected', 'url':url})
            continue

        if config_cluster['node_type'] == 'master' or \
           response['type'] == 'master' or url == "localhost":
            data.append({'url':url, 'node':response['node'],
                         'status':'connected', 'cluster':response['cluster']})

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


def get_files(node_type, cluster_items):
    def get_files_from_dir(dirname, recursive, files, cluster_items):
        items = []
        for entry in listdir(dirname):
            if entry not in cluster_items['excluded_files'] and entry[-1] != '~' \
                and entry in files or files == ["all"]:

                full_path = path.join(dirname, entry)
                if not path.isdir(full_path):
                    new_item = dict(item)
                    new_item["path"] = full_path.replace(common.ossec_path, "")
                    items.append(new_item)
                elif recursive:
                    items = list(chain.from_iterable([items,
                                    get_files_from_dir(full_path, recursive, files, cluster_items)]))
        return items

    # Expand directory
    expanded_items = []
    for file_path, item in cluster_items.items():
        if file_path == "excluded_files":
            continue
        if item['source'] == node_type or \
           item['source'] == 'all':

            fullpath = common.ossec_path + file_path
            expanded_items = chain.from_iterable([expanded_items,
                                   get_files_from_dir(fullpath, item['recursive'],
                                                      item['files'], cluster_items)])

    final_items = {}
    for new_item in expanded_items:
        try:
            final_items[new_item['path']] = get_file_info(new_item['path'], cluster_items)
        except Exception as e:
            continue

    return final_items

def get_file_status(manager, cluster_socket):
    count_query = "count {0}".format(manager)
    cluster_socket.send(count_query)
    n_files = int(filter(lambda x: x != '\x00', cluster_socket.recv(10000)))

    # limit = 100
    query = "select {0} 100 ".format(manager)
    file_status = ""
    for offset in range(0,n_files,100):
        query += str(offset)
        cluster_socket.send(query)
        file_status += filter(lambda x: x != '\x00', cluster_socket.recv(10000))

    # retrieve all files for a node in database with its status
    all_files = {f[0]:f[1] for f in map(lambda x: x.split('*'), filter(lambda x: x != '', file_status.split(' ')))}

    return all_files

def get_file_status_all_managers(file_list, manager):
    """
    Return a nested list where each element has the following structure
    [manager, filename, status]
    """
    cluster_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cluster_socket.connect("{0}/queue/ossec/cluster_db".format(common.ossec_path))
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

        files.extend([[node, file, all_files[file]] for file in file_list])

    cluster_socket.close()
    return files

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
        client_keys = ck.readlines()

    regex = re.compile('-\d{3} \w+ (any|\d+.\d+.\d+.\d+) \w+')
    for removed_line in filter(lambda x: x.startswith('-'), unified_diff(client_keys, new_client_keys)):
        if regex.match(removed_line):
            agent_id, _, _, _, = removed_line[1:].split(" ")

            try:
                Agent(agent_id).remove()
                logging.info("Agent {0} deleted successfully".format(agent_id))
            except WazuhException as e:
                logging.error("Error deleting agent {0}: {1}".format(agent_id, str(e)))


def _update_file(fullpath, new_content, umask_int=None, mtime=None, w_mode=None):
    # Set Timezone to epoch converter
    # environ['TZ']='UTC'

    if path.basename(fullpath) == 'client.keys':
        _check_removed_agents(new_content.split('\n'))

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
    cluster_items = json.load(open('{0}/framework/wazuh/cluster.json'.format(common.ossec_path)))

    logging.info("Receiving zip with {0} files".format(len(zip_file)))

    final_dict = {'error':[], 'updated': [], 'invalid': []}

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
                            w_mode=remote_write_mode)

        except Exception as e:
            logging.error("Error extracting zip file: {0}".format(str(e)))
            final_dict['error'].append({'item': name, 'reason': str(e)})
            continue

        final_dict['updated'].append(name)

    return final_dict


def divide_list(l, size=1000):
    return map(lambda x: filter(lambda y: y is not None, x), map(None, *([iter(l)] * size)))

def get_remote_nodes(connected=True):
    all_nodes = get_nodes()['items']

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


def sync(debug, force=None):
    """
    Sync this node with others
    :return: Files synced.
    """
    def push_updates_single_node(all_files, node_dest, config_cluster, result_queue):
        # filter to send only pending files
        pending_files = filter(lambda x: x[1] != 'synchronized', all_files.items())
        if len(pending_files) > 0:
            logging.info("Sending {0} {1} files".format(node_dest, len(pending_files)))
            zip_file = compress_files(list_path=set(map(itemgetter(0), pending_files)))

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

    config_cluster = read_config()
    if not config_cluster:
        raise WazuhException(3000, "No config found")


    cluster_items = json.load(open('{0}/framework/wazuh/cluster.json'.format(common.ossec_path)))
    before = time()
    # Get own items status
    own_items = dict(filter(lambda x: not x[1]['is_synced'], get_files(config_cluster['node_type'], cluster_items).items()))
    own_items_names = own_items.keys()

    remote_nodes = get_remote_nodes()
    logging.info("Starting to sync localhost's files")

    cluster_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    cluster_socket.connect("{0}/queue/ossec/cluster_db".format(common.ossec_path))
    logging.debug("Connected to cluster database socket")

    # for each connected manager, check its files. If the manager is not on database add it
    # with all files marked as pending
    all_nodes_files = {}

    logging.debug("Nodes to sync: {0}".format(str(remote_nodes)))
    for node in remote_nodes:
        # check files in database
        count_query = "count {0}".format(node)
        cluster_socket.send(count_query)
        n_files = int(filter(lambda x: x != '\x00', cluster_socket.recv(10000)))
        if n_files == 0:
            logging.info("New manager found: {0}".format(node))
            logging.debug("Adding {0}'s files to database".format(node))

            # if the manager is not in the database, add it with all files
            for files in divide_list(own_items_names):

                insert_sql = "insert"
                for file in files:
                    insert_sql += " {0} {1}".format(node, file)

                cluster_socket.send(insert_sql)
                data = cluster_socket.recv(10000)

            all_files = {file:'pending' for file in own_items_names}

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

                cluster_socket.send(insert_sql)
                data = cluster_socket.recv(10000)

        all_nodes_files[node] = all_files

    after = time()
    logging.debug("Time retrieving info from DB: {0}".format(after-before))

    before = time()
    result_queue = queue()
    threads = []
    thread_results = {}
    for node in remote_nodes:
        t = threading.Thread(target=push_updates_single_node, args=(all_nodes_files[node],node,
                                                                    config_cluster,
                                                                    result_queue))
        threads.append(t)
        t.start()
        result = result_queue.get()
        thread_results[result['node']] = {'files': result['files'], 'error': result['error'],
                                          'reason': result['reason']}

    for t in threads:
        t.join()
    after = time()

    logging.debug("Time sending info: {0}".format(after-before))

    before = time()
    for node,data in thread_results.items():
        logging.info("Updating {0}'s file status in DB".format(node))
        for updated in divide_list(data['files']['updated']):
            update_sql = "update2"
            for u in updated:
                update_sql += " synchronized {0} /{1}".format(node, u)

            cluster_socket.send(update_sql)
            received = cluster_socket.recv(10000)

        for failed in divide_list(data['files']['error']):
            update_sql = "update2"
            for f in failed:
                if isinstance(f, dict):
                    update_sql += " failed {0} /{1}".format(node, f['item'])
                else:
                    update_sql += " failed {0} {1}".format(node, f)

            cluster_socket.send(update_sql)
            received = cluster_socket.recv(10000)

        for invalid in divide_list(data['files']['invalid']):
            update_sql = "update2"
            for i in invalid:
                update_sql += " invalid {0} {1}".format(node, i)

            cluster_socket.send(update_sql)
            received = cluster_socket.recv(10000)

    cluster_socket.close()
    after = time()

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
