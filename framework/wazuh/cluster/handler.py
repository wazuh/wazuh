#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import md5, divide_list
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.group import get_all_groups, remove_group
from wazuh.cluster.management import *
from datetime import datetime
from time import time, mktime, sleep
from os import path, listdir, rename, utime, umask, stat, mkdir, chmod
from subprocess import check_output
from io import BytesIO
from itertools import compress
from operator import itemgetter
from ast import literal_eval
import threading
from stat import S_IRWXG, S_IRWXU
from sys import version
from difflib import unified_diff
import re
import socket
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
                local_groups = [x['name'] for x in get_all_groups(limit=None)['items']]
                zf.writestr("remote_groups.txt", '\n'.join(local_groups), compression)
            except Exception as e:
                raise WazuhException(3001, str(e))

    return zipped_file.getvalue()


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
    if path.basename(fullpath) == 'client.keys':
        if node_type=='client':
            _check_removed_agents(new_content.split('\n'))
        elif node_name == get_actual_master()['name']:
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
        local_groups = {x['name'] for x in get_all_groups(limit=None)['items']}
        for removed_group in local_groups - remote_group_set:
            try:
                remove_group(removed_group)
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
            master_name = get_actual_master(csocket=cluster_socket)['name']
            actual_master_ip = get_ip_from_name(master_name, cluster_socket)
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
