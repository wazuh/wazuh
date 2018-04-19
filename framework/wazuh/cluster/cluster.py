#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import md5, mkdir_with_mode
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.manager import status
from wazuh.configuration import get_ossec_conf
from wazuh.InputValidator import InputValidator
from wazuh import common

from datetime import datetime, timedelta
from hashlib import sha512
from time import time, mktime, sleep
from os import path, listdir, rename, utime, environ, umask, stat, chmod, devnull, strerror, remove
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
import asyncore
import asynchat
import errno
import logging
import re
from calendar import timegm
from random import random

# import the C accelerated API of ElementTree
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

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


#
# Cluster
#

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

    if 'port' in config_cluster:
        config_cluster['port'] = int(config_cluster['port'])

    return config_cluster


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


def get_status_json():
    return {"enabled": "yes" if check_cluster_status() else "no",
            "running": "yes" if status()['wazuh-clusterd'] == 'running' else "no"}


#
# Files
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
                logging.warning("get_files_status: {}".format(e))

    return final_items


def compress_files(source, name, list_path, cluster_control_json=None):
    zip_file_path = "{0}/queue/cluster/{1}/{1}-{2}-{3}.zip".format(common.ossec_path, name, time(), str(random())[2:])
    with zipfile.ZipFile(zip_file_path, 'w') as zf:
        # write files
        if list_path:
            for f in list_path:
                logging.debug("Adding {} to zip file".format(f))
                try:
                    zf.write(filename = common.ossec_path + f, arcname = 'rootpath/' + f, compress_type=compression)
                except Exception as e:
                    logging.error(str(WazuhException(3001, str(e))))

        try:
            zf.writestr("cluster_control.json", json.dumps(cluster_control_json), compression)
        except Exception as e:
            raise WazuhException(3001, str(e))

    return zip_file_path


def decompress_files(zip_path, ko_files_name="cluster_control.json"):
    zip_json = {}
    ko_files = ""
    # create a directory to store zip's files
    zip_dir = zip_path + 'dir'
    mkdir_with_mode(zip_dir)
    with zipfile.ZipFile(zip_path) as zipf:
        for name in zipf.namelist():
            if name == ko_files_name:
                ko_files = json.loads(zipf.open(name).read())
            else:
                with open("{}/{}".format(zip_dir, name.replace('rootpath','').replace('/','_')), 'w') as f:
                    f.write(zipf.open(name).read())

    # once read all files, remove the zipfile
    remove(zip_path)
    return ko_files, zip_dir


def _update_file(fullpath, new_content, umask_int=None, mtime=None, w_mode=None, whoami='master'):
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
            mtime = datetime.strptime(mtime, '%Y-%m-%d %H:%M:%S.%f')

            if path.isfile(fullpath):

                local_mtime = datetime.utcfromtimestamp(int(stat(fullpath).st_mtime))
                # check if the date is older than the manager's date
                if local_mtime > mtime:
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
            mkdir_with_mode(dirpath)
            chmod(dirpath, S_IRWXU | S_IRWXG)
            dest_file = open(f_temp, "a+")
        else:
            raise e

    dest_file.write(new_content)

    if umask_int:
        umask(oldumask)

    dest_file.close()

    if mtime:
        mtime_epoch = timegm(mtime.timetuple())
        utime(f_temp, (mtime_epoch, mtime_epoch)) # (atime, mtime)

    # Atomic
    if w_mode == "atomic":
        rename(f_temp, fullpath)


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



def clean_up(node_name=""):
    """
    Cleans all temporary files generated in the cluster. Optionally, it cleans
    all temporary files of node node_name.

    :param node_name: Name of the node to clean up
    """
    def remove_directory_contents(rm_path):
        if not path.exists(rm_path):
            logging.debug("Nothing to remove in {}.".format(rm_path))
            return

        for f in listdir(rm_path):
            if f == "c-internal.sock":
                continue
            f_path = path.join(rm_path, f)
            try:
                if path.isdir(f_path):
                    rmtree(f_path)
                else:
                    remove(f_path)
            except Exception as e:
                logging.error("Error removing {}: {}".format(f_path, str(e)))
                continue

    try:
        rm_path = "{}/queue/cluster/{}".format(common.ossec_path, node_name)
        logging.debug("Removing {}.".format(rm_path))
        remove_directory_contents(rm_path)
    except:
        logging.error("Error cleaning.")

#
# Agents
#


def get_agents_status(filter_status=""):
    """
    Return a nested list where each element has the following structure
    [agent_id, agent_name, agent_status, manager_hostname]
    """
    agent_list = []
    for agent in Agent.get_agents_overview(select={'fields':['id','ip','name','status','node_name']}, limit=None)['items']:
        if int(agent['id']) == 0:
            continue
        if filter_status and agent['status'] != filter_status:
            continue
        if agent.get('node_name') is None or agent['node_name'] == '':
            agent['node_name'] = "Unknown"

        agent_list.append([agent['id'], agent['ip'], agent['name'], agent['status'], "Unknown"])

    return agent_list



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



#
# Others
#

get_localhost_ips = lambda: check_output(['hostname', '--all-ip-addresses']).split(" ")[:-1]


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
