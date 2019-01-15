#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
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
from time import time
from os import path, listdir, rename, utime, umask, stat, chmod, chown, remove, unlink, environ
from subprocess import check_output, check_call, CalledProcessError
from shutil import rmtree, copyfileobj
from operator import eq, setitem, add
import json
from stat import S_IRWXG, S_IRWXU
from difflib import unified_diff
import errno
import logging
import logging.handlers
import re
import os
import ast
from calendar import timegm, month_abbr
from random import random
import glob
import gzip
from functools import reduce
from socket import gethostname

# import the C accelerated API of ElementTree
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import zipfile

try:
    import zlib
    compression = zipfile.ZIP_DEFLATED
except:
    compression = zipfile.ZIP_STORED


#
# Cluster
#

logger = logging.getLogger(__name__)


def get_localhost_ips():
    return set(str(check_output(['hostname', '--all-ip-addresses']).decode()).split(" ")[:-1])


def check_cluster_config(config):
    iv = InputValidator()
    reservated_ips = {'localhost', 'NODE_IP', '0.0.0.0', '127.0.1.1'}

    if len(config['key']) == 0:
        raise WazuhException(3004, 'Unspecified key')
    elif not iv.check_name(config['key']) or not iv.check_length(config['key'], 32, eq):
        raise WazuhException(3004, 'Key must be 32 characters long and only have alphanumeric characters')

    elif config['node_type'] != 'master' and config['node_type'] != 'worker':
        raise WazuhException(3004, 'Invalid node type {0}. Correct values are master and worker'.format(
            config['node_type']))

    if config['disabled'] != 'yes' and config['disabled'] != 'no':
        raise WazuhException(3004, 'Invalid value for disabled option {}. Allowed values are yes and no'.
                             format(config['disabled']))

    if len(config['nodes']) > 1:
        logger.warning(
            "Found more than one node in configuration. Only master node should be specified. Using {} as master.".
            format(config['nodes'][0]))

    invalid_elements = list(reservated_ips & set(config['nodes']))

    if len(invalid_elements) != 0:
        raise WazuhException(3004, "Invalid elements in node fields: {0}.".format(', '.join(invalid_elements)))

    if not isinstance(config['port'], int):
        raise WazuhException(3004, "Cluster port must be an integer.")


def get_cluster_items():
    try:
        with open('{0}/framework/wazuh/cluster/cluster.json'.format(common.ossec_path)) as f:
            cluster_items = json.load(f)
        list(map(lambda x: setitem(x, 'umask', int(x['umask'], base=0)), filter(lambda x: 'umask' in x, cluster_items['files'].values())))
        return cluster_items
    except Exception as e:
        raise WazuhException(3005, str(e))


def get_cluster_items_master_intervals():
    return get_cluster_items()['intervals']['master']


def get_cluster_items_communication_intervals():
    return get_cluster_items()['intervals']['communication']


def get_cluster_items_worker_intervals():
    return get_cluster_items()['intervals']['worker']


def read_config():
    cluster_default_configuration = {
        'disabled': 'no',
        'node_type': 'master',
        'name': 'wazuh',
        'node_name': 'node01',
        'key': '',
        'port': 1516,
        'bind_addr': '0.0.0.0',
        'nodes': ['NODE_IP'],
        'hidden': 'no'
    }

    try:
        config_cluster = get_ossec_conf('cluster')
    except WazuhException as e:
        if e.code == 1106:
            # if no cluster configuration is present in ossec.conf, return default configuration but disabling it.
            cluster_default_configuration['disabled'] = 'yes'
            return cluster_default_configuration
        else:
            raise WazuhException(3006, e.message)
    except Exception as e:
        raise WazuhException(3006, str(e))

    # if any value is missing from user's cluster configuration, add the default one:
    for value_name in set(cluster_default_configuration.keys()) - set(config_cluster.keys()):
        config_cluster[value_name] = cluster_default_configuration[value_name]

    config_cluster['port'] = int(config_cluster['port'])

    # if config_cluster['node_name'].upper() == '$HOSTNAME':
    #     # The HOSTNAME environment variable is not always available in os.environ so use socket.gethostname() instead
    #     config_cluster['node_name'] = gethostname()

    # if config_cluster['node_name'].upper() == '$NODE_NAME':
    #     if 'NODE_NAME' in environ:
    #         config_cluster['node_name'] = environ['NODE_NAME']
    #     else:
    #         raise WazuhException(3006, 'Unable to get the $NODE_NAME environment variable')

    # if config_cluster['node_type'].upper() == '$NODE_TYPE':
    #     if 'NODE_TYPE' in environ:
    #         config_cluster['node_type'] = environ['NODE_TYPE']
    #     else:
    #         raise WazuhException(3006, 'Unable to get the $NODE_TYPE environment variable')

    if config_cluster['node_type'] == 'client':
        logger.info("Deprecated node type 'client'. Using 'worker' instead.")
        config_cluster['node_type'] = 'worker'

    return config_cluster


def get_node():
    data = {}
    config_cluster = read_config()

    data["node"]    = config_cluster["node_name"]
    data["cluster"] = config_cluster["name"]
    data["type"]    = config_cluster["node_type"]

    return data


def check_cluster_status():
    """
    Function to check if cluster is enabled
    """
    return read_config()['disabled'] != 'yes'


def get_status_json():
    return {"enabled": "yes" if check_cluster_status() else "no",
            "running": "yes" if status()['wazuh-clusterd'] == 'running' else "no"}


#
# Files
#

def walk_dir(dirname, recursive, files, excluded_files, excluded_extensions, get_cluster_item_key, get_md5=True, whoami='master'):
    walk_files = {}

    try:
        entries = listdir(dirname)
    except OSError as e:
        raise WazuhException(3015, str(e))

    for entry in entries:
        if entry in excluded_files or reduce(add, map(lambda x: entry[-(len(x)):] == x, excluded_extensions)):
            continue

        full_path = path.join(dirname, entry)
        if entry in files or files == ["all"]:

            if not path.isdir(full_path):
                file_mod_time = datetime.utcfromtimestamp(stat(full_path).st_mtime)

                if whoami == 'worker' and file_mod_time < (datetime.utcnow() - timedelta(minutes=30)):
                    continue

                new_key = full_path.replace(common.ossec_path, "")
                walk_files[new_key] = {"mod_time" : str(file_mod_time), 'cluster_item_key': get_cluster_item_key}
                if '.merged' in entry:
                    walk_files[new_key]['merged'] = True
                    walk_files[new_key]['merge_type'] = 'agent-info' if 'agent-info' in entry else 'agent-groups'
                    walk_files[new_key]['merge_name'] = '/queue/cluster/' + entry
                else:
                    walk_files[new_key]['merged'] = False

                if get_md5:
                    walk_files[new_key]['md5'] = md5(full_path)

        if recursive and path.isdir(full_path):
            walk_files.update(walk_dir(full_path, recursive, files, excluded_files, excluded_extensions, get_cluster_item_key, get_md5, whoami))

    return walk_files


def get_files_status(node_type, get_md5=True):

    cluster_items = get_cluster_items()

    final_items = {}
    for file_path, item in cluster_items['files'].items():
        if file_path == "excluded_files" or file_path == "excluded_extensions":
            continue

        if item['source'] == node_type or item['source'] == 'all':
            if item.get("files") and "agent-info.merged" in item["files"]:
                agents_to_send, merged_path = merge_agent_info(merge_type="agent-info",
                                                               time_limit_seconds=cluster_items\
                                                                        ['sync_options']['get_agentinfo_newer_than'])
                if agents_to_send == 0:
                    return {}
                fullpath = common.ossec_path + path.dirname(merged_path)
            else:
                fullpath = common.ossec_path + file_path
            try:
                final_items.update(walk_dir(fullpath, item['recursive'], item['files'], cluster_items['files']['excluded_files'],
                                            cluster_items['files']['excluded_extensions'], file_path, get_md5, node_type))
            except WazuhException as e:
                logger.warning("[Cluster] get_files_status: {}.".format(e))

    return final_items


def compress_files(name, list_path, cluster_control_json=None):
    zip_file_path = "{0}/queue/cluster/{1}/{1}-{2}-{3}.zip".format(common.ossec_path, name, time(), str(random())[2:])
    with zipfile.ZipFile(zip_file_path, 'w') as zf:
        # write files
        if list_path:
            for f in list_path:
                logger.debug2("[Cluster] Adding {} to zip file".format(f))  # debug2
                try:
                    zf.write(filename = common.ossec_path + f, arcname = f, compress_type=compression)
                except zipfile.LargeZipFile as e:
                    raise WazuhException(3001, str(e))
                except Exception as e:
                    logger.error("[Cluster] {}".format(str(WazuhException(3001, str(e)))))

        try:
            zf.writestr("cluster_control.json", json.dumps(cluster_control_json), compression)
        except Exception as e:
            raise WazuhException(3001, str(e))

    return zip_file_path


def decompress_files(zip_path, ko_files_name="cluster_control.json"):
    ko_files = ""
    zip_dir = zip_path + 'dir'
    mkdir_with_mode(zip_dir)
    with zipfile.ZipFile(zip_path) as zipf:
        for name in zipf.namelist():
            if name == ko_files_name:
                with zipf.open(name) as file:
                    ko_files = json.loads(file.read().decode('utf-8'))
            else:
                filename = "{}/{}".format(zip_dir, path.dirname(name))
                if not path.exists(filename):
                    mkdir_with_mode(filename)
                with open("{}/{}".format(filename, path.basename(name)), 'wb') as cf:
                    with zipf.open(name) as file:
                        content = file.read()
                    cf.write(content)

    # once read all files, remove the zipfile
    remove(zip_path)
    return ko_files, zip_dir


def _update_file(file_path, new_content, umask_int=None, mtime=None, w_mode=None,
                 tmp_dir='/queue/cluster',whoami='master', agents=None):

    dst_path = common.ossec_path + file_path
    if path.basename(dst_path) == 'client.keys':
        if whoami =='worker':
            _check_removed_agents(new_content.split('\n'))
        else:
            logger.warning("[Cluster] Client.keys file received in a master node.")
            raise WazuhException(3007)

    is_agent_info  = 'agent-info' in dst_path
    is_agent_group = 'agent-groups' in dst_path
    if is_agent_info or is_agent_group:
        if whoami =='master':
            agent_names, agent_ids = agents

            if is_agent_info:
                agent_name_re = re.match(r'(^.+)-(.+)$', path.basename(file_path))
                agent_name = agent_name_re.group(1) if agent_name_re else path.basename(file_path)
                if agent_name not in agent_names:
                    raise WazuhException(3010, agent_name)
            elif is_agent_group:
                agent_id = path.basename(file_path)
                if agent_id not in agent_ids:
                    raise WazuhException(3010, agent_id)

            try:
                mtime = datetime.strptime(mtime, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                mtime = datetime.strptime(mtime, '%Y-%m-%d %H:%M:%S')

            if path.isfile(dst_path):

                local_mtime = datetime.utcfromtimestamp(int(stat(dst_path).st_mtime))
                # check if the date is older than the manager's date
                if local_mtime > mtime:
                    logger.debug2("[Cluster] Receiving an old file ({})".format(dst_path))  # debug2
                    return
        elif is_agent_info:
            logger.warning("[Cluster] Agent-info received in a worker node.")
            raise WazuhException(3011)

    # Write
    if w_mode == "atomic":
        f_temp = "{}{}{}.cluster.tmp".format(common.ossec_path, tmp_dir, file_path)
    else:
        f_temp = '{0}'.format(dst_path)

    if umask_int:
        oldumask = umask(umask_int)

    try:
        dest_file = open(f_temp, "w")
    except IOError as e:
        if e.errno == errno.ENOENT:
            dirpath = path.dirname(f_temp)
            mkdir_with_mode(dirpath)
            chmod(dirpath, S_IRWXU | S_IRWXG)
            dest_file = open(f_temp, "w")
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
        dirpath = path.dirname(dst_path)
        if not os.path.exists(dirpath):
            mkdir_with_mode(dirpath)
            chmod(path.dirname(dst_path), S_IRWXU | S_IRWXG)
        chown(f_temp, common.ossec_uid, common.ossec_gid)
        rename(f_temp, dst_path)


def compare_files(good_files, check_files):
    cluster_items = get_cluster_items()['files']

    missing_files = set(good_files.keys()) - set(check_files.keys())

    extra_files, extra_valid_files = [], []
    for my_file in set(check_files.keys()) - set(good_files.keys()):
        (extra_files, extra_valid_files)[cluster_items[check_files[my_file]['cluster_item_key']]['extra_valid']].append(my_file)

    shared_files = {name: {'cluster_item_key': data['cluster_item_key'],
                          'merged':False} for name, data in good_files.items()
                          if name in check_files and data['md5'] != check_files[name]['md5']}

    if not missing_files:
        missing_files = {}
    else:
        missing_files = {missing_file: {'cluster_item_key': good_files[missing_file]['cluster_item_key'],
                                        'merged': False} for missing_file in missing_files }

    if not extra_files:
        extra_files = {}
    else:
        extra_files = {extra_file: {'cluster_item_key': check_files[extra_file]['cluster_item_key'],
                                    'merged': False} for extra_file in extra_files }

    if not extra_valid_files:
        extra_valid_files = {}
    else:
        extra_valid_files = {req_file: {'cluster_item_key': check_files[req_file]['cluster_item_key'],
                                     'merged': False} for req_file in extra_valid_files }

    return {'missing': missing_files, 'extra': extra_files, 'shared': shared_files,
            'extra_valid': extra_valid_files}


def clean_up(node_name=""):
    """
    Cleans all temporary files generated in the cluster. Optionally, it cleans
    all temporary files of node node_name.

    :param node_name: Name of the node to clean up
    """
    def remove_directory_contents(local_rm_path):
        if not path.exists(local_rm_path):
            logger.debug("[Cluster] Nothing to remove in '{}'.".format(local_rm_path))
            return

        for f in listdir(local_rm_path):
            if f == "c-internal.sock":
                continue
            f_path = path.join(local_rm_path, f)
            try:
                if path.isdir(f_path):
                    rmtree(f_path)
                else:
                    remove(f_path)
            except Exception as e:
                logger.error("[Cluster] Error removing '{}': '{}'.".format(f_path, e))
                continue

    try:
        rm_path = "{}/queue/cluster/{}".format(common.ossec_path, node_name)
        logger.debug("[Cluster] Removing '{}'.".format(rm_path))
        remove_directory_contents(rm_path)
        logger.debug("[Cluster] Removed '{}'.".format(rm_path))
    except Exception as e:
        logger.error("[Cluster] Error cleaning up: {0}.".format(str(e)))


#
# Agents
#
def get_agents_status(filter_status="all", filter_nodes="all",  offset=0, limit=common.database_limit):
    """
    Return a nested list where each element has the following structure
    [agent_id, agent_name, agent_status, manager_hostname]
    """
    if not offset:
        offset = 0
    if not filter_status:
        filter_status="all"
    if not filter_nodes:
        filter_nodes="all"
    elif filter_nodes != 'all':
        filter_nodes=ast.literal_eval(filter_nodes)
    if not limit:
        limit = common.database_limit

    agents = Agent.get_agents_overview(filters={'status':filter_status, 'node_name':filter_nodes},
                                       select={'fields':['id','ip','name','status','node_name']}, limit=limit,
                                       offset=offset)
    return agents


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

    regex = re.compile(r'^(\d+) (\S+) (\S+) (\S+)$')
    for removed_line in filter(lambda x: x.startswith('-') or x.startswith('+'), unified_diff(client_keys, new_client_keys)):
        removed_line_match = regex.match(removed_line[1:])
        if removed_line_match is not None:
            agent_id, agent_name, agent_ip, agent_key = removed_line_match.group(1, 2, 3, 4)
            removed = removed_line.startswith('-')

            try:
                Agent(agent_id).remove() if removed else Agent.insert_agent(agent_name, agent_id, agent_key, agent_ip)
                logger.info("[Cluster] Agent '{}' {} successfully.".format(agent_id, 'Deleted' if removed else 'Added'))
            except WazuhException as e:
                logger.error("[Cluster] Agent '{0}': Error - '{1}'.".format(agent_id, str(e)))


#
# Others
#
def run_logtest(synchronized=False):
    log_msg_start = "Synchronized r" if synchronized else "R"
    try:
        # check synchronized rules are correct before restarting the manager
        check_call(['{0}/bin/ossec-logtest -t'.format(common.ossec_path)], shell=True)
        logger.debug("[Cluster] {}ules are correct.".format(log_msg_start))
        return True
    except CalledProcessError as e:
        logger.warning("[Cluster] {}ules are not correct.".format(log_msg_start, str(e)))
        return False



#
# Agents-info
#

def merge_agent_info(merge_type, files="all", file_type="", time_limit_seconds=1800):
    if time_limit_seconds:
        min_mtime = time() - time_limit_seconds
    merge_path = "{}/queue/{}".format(common.ossec_path, merge_type)
    output_file = "/queue/cluster/{}{}.merged".format(merge_type, file_type)
    o_f = None
    files_to_send = 0
    files = "all" if files == "all" else {path.basename(f) for f in files}

    for filename in os.listdir(merge_path):
        if files != "all" and filename not in files:
            continue

        full_path = "{0}/{1}".format(merge_path, filename)
        stat_data = stat(full_path)

        if time_limit_seconds and stat_data.st_mtime < min_mtime:
            continue

        files_to_send += 1
        if not o_f:
            o_f = open(common.ossec_path + output_file, 'w')

        header = "{} {} {}".format(stat_data.st_size, filename.replace(common.ossec_path,''),
                datetime.utcfromtimestamp(stat_data.st_mtime))
        with open(full_path, 'r') as f:
            data = f.read()

        o_f.write(header + '\n' + data)

    if o_f:
        o_f.close()

    return files_to_send, output_file


def unmerge_agent_info(merge_type, path_file, filename):
    src_agent_info_path = path.abspath("{0}/{1}".format(path_file, filename))
    dst_agent_info_path = "/queue/{}".format(merge_type)

    bytes_read = 0
    total_bytes = os.stat(src_agent_info_path).st_size
    src_f = open(src_agent_info_path, 'r')

    while bytes_read < total_bytes:
        # read header
        header = src_f.readline()
        bytes_read += len(header)
        try:
            st_size, name, st_mtime = header[:-1].split(' ',2)
            st_size = int(st_size)
        except ValueError:
            raise Exception("Malformed agent-info.merged file")

        # read data
        data = src_f.read(st_size)
        bytes_read += st_size

        yield dst_agent_info_path + '/' + name, data, st_mtime

    src_f.close()


class CustomFileRotatingHandler(logging.handlers.TimedRotatingFileHandler):
    """
    Wazuh cluster log rotation. It rotates the log at midnight and sets the appropiate permissions to the new log file.
    Also, rotated logs are stored in /logs/ossec
    """

    def doRollover(self):
        """
        Override base class method to make the set the appropiate permissions to the new log file
        """
        # Rotate the file first
        logging.handlers.TimedRotatingFileHandler.doRollover(self)

        # Set appropiate permissions
        chown(self.baseFilename, common.ossec_uid, common.ossec_gid)
        chmod(self.baseFilename, 0o660)

        # Save rotated file in /logs/ossec directory
        rotated_file = glob.glob("{}.*".format(self.baseFilename))[0]

        new_rotated_file = self.computeArchivesDirectory(rotated_file)
        with open(rotated_file, 'rb') as f_in, gzip.open(new_rotated_file, 'wb') as f_out:
            copyfileobj(f_in, f_out)
        chmod(new_rotated_file, 0o640)
        unlink(rotated_file)



    def computeArchivesDirectory(self, rotated_filepath):
        """
        Based on the name of the rotated file, compute in which directory it should be stored.

        :param rotated_filepath: Filepath of the rotated log
        :return: New directory path
        """
        rotated_file = path.basename(rotated_filepath)
        year, month, day = re.match(r'[\w\.]+\.(\d+)-(\d+)-(\d+)', rotated_file).groups()
        month = month_abbr[int(month)]

        log_path = '{}/logs/cluster/{}/{}'.format(common.ossec_path, year, month)
        if not path.exists(log_path):
            mkdir_with_mode(log_path, 0o750)

        return '{}/cluster-{}.log.gz'.format(log_path, day)
