# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import itertools
import json
import logging
import os
import shutil
import zipfile
from datetime import datetime, timedelta
from functools import reduce
from operator import eq, add
from os import listdir, path, stat, remove
from random import random
from shutil import rmtree
from subprocess import check_output
from time import time

from wazuh import WazuhException, WazuhError
from wazuh.core import common
from wazuh.core.InputValidator import InputValidator
from wazuh.core.cluster.utils import get_cluster_items, read_config
from wazuh.core.utils import md5, mkdir_with_mode

logger = logging.getLogger('wazuh')


#
# Cluster
#


def get_localhost_ips():
    return set(str(check_output(['hostname', '--all-ip-addresses']).decode()).split(" ")[:-1])


def check_cluster_config(config):
    iv = InputValidator()
    reservated_ips = {'localhost', 'NODE_IP', '0.0.0.0', '127.0.1.1'}

    if len(config['key']) == 0:
        raise WazuhError(3004, 'Unspecified key')
    elif not iv.check_name(config['key']) or not iv.check_length(config['key'], 32, eq):
        raise WazuhError(3004, 'Key must be 32 characters long and only have alphanumeric characters')

    elif config['node_type'] != 'master' and config['node_type'] != 'worker':
        raise WazuhError(3004, 'Invalid node type {0}. Correct values are master and worker'.format(
            config['node_type']))

    elif not 1024 < config['port'] < 65535:
        raise WazuhError(3004, "Port must be higher than 1024 and lower than 65535.")

    if len(config['nodes']) > 1:
        logger.warning(
            "Found more than one node in configuration. Only master node should be specified. Using {} as master.".
                format(config['nodes'][0]))

    invalid_elements = list(reservated_ips & set(config['nodes']))

    if len(invalid_elements) != 0:
        raise WazuhError(3004, "Invalid elements in node fields: {0}.".format(', '.join(invalid_elements)))


def get_cluster_items_master_intervals():
    return get_cluster_items()['intervals']['master']


def get_cluster_items_communication_intervals():
    return get_cluster_items()['intervals']['communication']


def get_cluster_items_worker_intervals():
    return get_cluster_items()['intervals']['worker']


def get_node():
    data = {}
    config_cluster = read_config()

    data["node"] = config_cluster["node_name"]
    data["cluster"] = config_cluster["name"]
    data["type"] = config_cluster["node_type"]

    return data


def check_cluster_status():
    """
    Function to check if cluster is enabled
    """
    return not read_config()['disabled']


#
# Files
#


def walk_dir(dirname, recursive, files, excluded_files, excluded_extensions, get_cluster_item_key, get_md5=True,
             whoami='master'):
    walk_files = {}

    try:
        entries = listdir(common.ossec_path + dirname)
    except OSError as e:
        raise WazuhError(3015, str(e))

    for entry in entries:
        if entry in excluded_files or reduce(add, map(lambda x: entry[-(len(x)):] == x, excluded_extensions)):
            continue

        try:
            full_path = path.join(dirname, entry)
            if entry in files or files == ["all"]:

                if not path.isdir(common.ossec_path + full_path):
                    file_mod_time = datetime.utcfromtimestamp(stat(common.ossec_path + full_path).st_mtime)

                    if whoami == 'worker' and file_mod_time < (datetime.utcnow() - timedelta(minutes=30)):
                        continue

                    entry_metadata = {"mod_time": str(file_mod_time), 'cluster_item_key': get_cluster_item_key}
                    if '.merged' in entry:
                        entry_metadata['merged'] = True
                        entry_metadata['merge_type'] = 'agent-info' if 'agent-info' in entry else 'agent-groups'
                        entry_metadata['merge_name'] = dirname + '/' + entry
                    else:
                        entry_metadata['merged'] = False

                    if get_md5:
                        entry_metadata['md5'] = md5(common.ossec_path + full_path)

                    walk_files[full_path] = entry_metadata

            if recursive and path.isdir(common.ossec_path + full_path):
                walk_files.update(walk_dir(full_path, recursive, files, excluded_files, excluded_extensions,
                                           get_cluster_item_key, get_md5, whoami))

        except Exception as e:
            logger.error("Could not get checksum of file {}: {}".format(entry, e))

    return walk_files


def get_files_status(node_type, node_name, get_md5=True):
    cluster_items = get_cluster_items()

    final_items = {}
    for file_path, item in cluster_items['files'].items():
        if file_path == "excluded_files" or file_path == "excluded_extensions":
            continue

        if item['source'] == node_type or item['source'] == 'all':
            if item.get("files") and "agent-info.merged" in item["files"]:
                agents_to_send, merged_path = \
                    merge_agent_info(merge_type="agent-info",
                                     node_name=node_name,
                                     time_limit_seconds=cluster_items['sync_options']['get_agentinfo_newer_than']
                                     )
                if agents_to_send == 0:
                    return {}

                fullpath = path.dirname(merged_path)
            else:
                fullpath = file_path
            try:
                final_items.update(
                    walk_dir(fullpath, item['recursive'], item['files'], cluster_items['files']['excluded_files'],
                             cluster_items['files']['excluded_extensions'], file_path, get_md5, node_type))
            except Exception as e:
                logger.warning("Error getting file status: {}.".format(e))

    return final_items


def update_cluster_control_with_failed(failed_files, ko_files):
    """Check if file paths inside 'shared' and 'missing' do really exist.

    Sometimes, files that no longer exist are still listed in cluster_control.json. Two situations can occur:
        - A missing file on a worker no longer exists on the master. It is removed from the list of missing files.
        - A shared file no longer exists on the master. It is deleted from 'shared' and added to 'extra'.

    Parameters
    ----------
    failed_files : list
        List of files to update
    ko_files : dict
        KO files dict with 'missing', 'shared' and 'extra' keys.
    """
    for f in failed_files:
        if 'missing' in ko_files.keys() and f in ko_files['missing'].keys():
            ko_files['missing'].pop(f, None)
        elif 'shared' in ko_files.keys() and 'extra' in ko_files.keys() and f in ko_files['shared'].keys():
            ko_files['extra'][f] = ko_files['shared'][f]
            ko_files['shared'].pop(f, None)


def compress_files(name, list_path, cluster_control_json=None):
    """Create a zip with cluster_control.json and the files listed in list_path.

    Iterate the list of files and groups them in the zip. If a file does not
    exist, the cluster_control_json dictionary is updated.

    Parameters
    ----------
    name : str
        Name of the node to which the zip will be sent.
    list_path : list
        List of file paths to be zipped
    cluster_control_json : dict
        KO files (path-metadata) to be zipped as a json.

    Returns
    -------
    zip_file_path : str
        Path where the zip file has been saved.
    """
    failed_files = list()
    zip_file_path = "{0}/queue/cluster/{1}/{1}-{2}-{3}.zip".format(common.ossec_path, name, time(), str(random())[2:])
    if not os.path.exists(os.path.dirname(zip_file_path)):
        mkdir_with_mode(os.path.dirname(zip_file_path))
    with zipfile.ZipFile(zip_file_path, 'x') as zf:
        # write files
        if list_path:
            for f in list_path:
                try:
                    zf.write(filename=common.ossec_path + f, arcname=f)
                except zipfile.LargeZipFile as e:
                    raise WazuhError(3001, str(e))
                except Exception as e:
                    logger.debug("[Cluster] {}".format(str(WazuhException(3001, str(e)))))
                    failed_files.append(f)
        try:
            if cluster_control_json and failed_files:
                update_cluster_control_with_failed(failed_files, cluster_control_json)
            zf.writestr("cluster_control.json", json.dumps(cluster_control_json))
        except Exception as e:
            raise WazuhError(3001, str(e))

    return zip_file_path


async def decompress_files(zip_path, ko_files_name="cluster_control.json"):
    try:
        ko_files = ""
        zip_dir = zip_path + 'dir'
        mkdir_with_mode(zip_dir)
        with zipfile.ZipFile(zip_path) as zipf:
            zipf.extractall(path=zip_dir)

        if os.path.exists("{}/{}".format(zip_dir, ko_files_name)):
            with open("{}/{}".format(zip_dir, ko_files_name)) as ko:
                ko_files = json.loads(ko.read())
    except Exception as e:
        if os.path.exists(zip_dir):
            shutil.rmtree(zip_dir)
        raise e
    finally:
        # once read all files, remove the zipfile
        remove(zip_path)
    return ko_files, zip_dir


def compare_files(good_files, check_files, node_name):
    def split_on_condition(seq, condition):
        """
        Splits a sequence into two generators based on a conditon
        :param seq: sequence to split
        :param condition: function base splitting on
        :return: two generators
        """
        l1, l2 = itertools.tee((condition(item), item) for item in seq)
        return (i for p, i in l1 if p), (i for p, i in l2 if not p)

    cluster_items = get_cluster_items()['files']

    # missing files will be the ones that are present in good files but not in the check files
    missing_files = {key: good_files[key] for key in good_files.keys() - check_files.keys()}

    # extra files are the ones present in check files but not in good files and aren't extra valid
    extra_valid, extra = split_on_condition(check_files.keys() - good_files.keys(),
                                            lambda x: cluster_items[check_files[x]['cluster_item_key']]['extra_valid'])
    extra_files = {key: check_files[key] for key in extra}
    extra_valid_files = {key: check_files[key] for key in extra_valid}
    # shared files are the ones present in both sets.
    all_shared = [x for x in check_files.keys() & good_files.keys() if check_files[x]['md5'] != good_files[x]['md5']]
    shared_e_v, shared = split_on_condition(all_shared,
                                            lambda x: cluster_items[check_files[x]['cluster_item_key']]['extra_valid'])
    shared_e_v = list(shared_e_v)
    if shared_e_v:
        # merge all shared extra valid files into a single one.
        # To Do: if more extra valid files types are included, compute their merge type and remove hardcoded
        # agent-groups
        shared_merged = [(merge_agent_info(merge_type='agent-groups', files=shared_e_v, file_type='-shared',
                                           node_name=node_name, time_limit_seconds=0)[1],
                          {'cluster_item_key': '/queue/agent-groups/', 'merged': True, 'merge-type': 'agent-groups'})]

        shared_files = dict(itertools.chain(shared_merged, ((key, good_files[key]) for key in shared)))
    else:
        shared_files = {key: good_files[key] for key in shared}

    files = {'missing': missing_files, 'extra': extra_files, 'shared': shared_files, 'extra_valid': extra_valid_files}
    count = {'missing': len(missing_files), 'extra': len(extra_files), 'extra_valid': len(extra_valid_files),
             'shared': len(all_shared)}

    return files, count


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
            except Exception as err:
                logger.error("[Cluster] Error removing '{}': '{}'.".format(f_path, err))
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

def merge_agent_info(merge_type, node_name, files=None, file_type="", time_limit_seconds=1800):
    min_mtime = 0
    if time_limit_seconds:
        min_mtime = time() - time_limit_seconds
    merge_path = "{}/queue/{}".format(common.ossec_path, merge_type)
    output_file = "/queue/cluster/{}/{}{}.merged".format(node_name, merge_type, file_type)
    files_to_send = 0
    files = "all" if files is None else {path.basename(f) for f in files}

    with open(common.ossec_path + output_file, 'wb') as o_f:
        for filename in os.listdir(merge_path):
            if files != "all" and filename not in files:
                continue

            full_path = "{0}/{1}".format(merge_path, filename)
            stat_data = stat(full_path)

            if time_limit_seconds and stat_data.st_mtime < min_mtime:
                continue

            files_to_send += 1
            if o_f is None:
                o_f = open(common.ossec_path + output_file, 'wb')

            with open(full_path, 'rb') as f:
                data = f.read()

            header = "{} {} {}".format(len(data), filename.replace(common.ossec_path, ''),
                                       datetime.utcfromtimestamp(stat_data.st_mtime))

            o_f.write((header + '\n').encode() + data)

    return files_to_send, output_file


def unmerge_agent_info(merge_type, path_file, filename):
    src_agent_info_path = path.abspath("{}/{}".format(path_file, filename))
    dst_agent_info_path = os.path.join("queue", merge_type)

    bytes_read = 0
    total_bytes = stat(src_agent_info_path).st_size
    with open(src_agent_info_path, 'rb') as src_f:
        while bytes_read < total_bytes:
            # read header
            header = src_f.readline().decode()
            bytes_read += len(header)
            try:
                st_size, name, st_mtime = header[:-1].split(' ', 2)
                st_size = int(st_size)
            except ValueError as e:
                logger.warning(f"Malformed agent-info.merged file ({e}). Parsed line: {header}. "
                               f"Some agent statuses won't be synced")
                break

            # read data
            data = src_f.read(st_size)
            bytes_read += st_size

            yield dst_agent_info_path + '/' + name, data, st_mtime
