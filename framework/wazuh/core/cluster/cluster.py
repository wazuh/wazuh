# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import itertools
import json
import logging
import os.path
import shutil
import zipfile
from asyncio import wait_for
from datetime import datetime
from functools import partial
from operator import eq
from os import listdir, path, remove, stat, walk
from random import random
from shutil import rmtree
from subprocess import check_output
from time import time

from wazuh import WazuhError, WazuhException, WazuhInternalError
from wazuh.core import common
from wazuh.core.InputValidator import InputValidator
from wazuh.core.agent import WazuhDBQueryAgents
from wazuh.core.cluster.common import as_wazuh_object
from wazuh.core.cluster.local_client import LocalClient
from wazuh.core.cluster.utils import get_cluster_items, read_config
from wazuh.core.exception import WazuhClusterError
from wazuh.core.utils import md5, mkdir_with_mode, to_relative_path

logger = logging.getLogger('wazuh')
agent_groups_path = os.path.relpath(common.groups_path, common.wazuh_path)


#
# Cluster
#


def get_localhost_ips():
    """Get all localhost IPs addresses.

    Returns
    -------
    set
        All IP addresses.
    """
    return set(str(check_output(['hostname', '--all-ip-addresses']).decode()).split(" ")[:-1])


def check_cluster_config(config):
    """Verify that cluster configuration is correct.

    Following points are checked:
        - Cluster config block is not empty.
        - len(key) == 32 and only alphanumeric characters are used.
        - node_type is 'master' or 'worker'.
        - 1024 < port < 65535.
        - Only 1 node is specified.
        - Reserved IPs are not used.

    Parameters
    ----------
    config : dict
        Cluster configuration.

    Raises
    -------
    WazuhError
        If any of above conditions is not met.
    """
    iv = InputValidator()
    reservated_ips = {'localhost', 'NODE_IP', '0.0.0.0', '127.0.1.1'}

    if len(config['key']) == 0:
        raise WazuhError(3004, 'Unspecified key')
    elif not iv.check_name(config['key']) or not iv.check_length(config['key'], 32, eq):
        raise WazuhError(3004, 'Key must be 32 characters long and only have alphanumeric characters')

    elif config['node_type'] != 'master' and config['node_type'] != 'worker':
        raise WazuhError(3004, f'Invalid node type {config["node_type"]}. Correct values are master and worker')

    elif not 1024 < config['port'] < 65535:
        raise WazuhError(3004, "Port must be higher than 1024 and lower than 65535.")

    if len(config['nodes']) > 1:
        logger.warning(
            "Found more than one node in configuration. Only master node should be specified. Using {} as master.".
            format(config['nodes'][0]))

    invalid_elements = list(reservated_ips & set(config['nodes']))

    if len(invalid_elements) != 0:
        raise WazuhError(3004, f"Invalid elements in node fields: {', '.join(invalid_elements)}.")


def get_cluster_items_master_intervals():
    """Get master's time intervals specified in cluster.json file.

    Returns
    -------
    dict
        Master's time intervals specified in cluster.json file.
    """
    return get_cluster_items()['intervals']['master']


def get_cluster_items_communication_intervals():
    """Get communication's time intervals specified in cluster.json file.

    Returns
    -------
    dict
        Communication's time intervals specified in cluster.json file.
    """
    return get_cluster_items()['intervals']['communication']


def get_cluster_items_worker_intervals():
    """Get worker's time intervals specified in cluster.json file.

    Returns
    -------
    dict
        Worker's time intervals specified in cluster.json file.
    """
    return get_cluster_items()['intervals']['worker']


def get_node():
    """Get dict with current active node information.

    Returns
    -------
    data : dict
        Dict containing current node_name, node_type and cluster_name.
    """
    data = {}
    config_cluster = read_config()

    data["node"] = config_cluster["node_name"]
    data["cluster"] = config_cluster["name"]
    data["type"] = config_cluster["node_type"]

    return data


def check_cluster_status():
    """Get whether cluster is enabled in current active configuration.

    Returns
    -------
    bool
        Whether cluster is enabled.
    """
    return not read_config()['disabled']


#
# Files
#

def walk_dir(dirname, recursive, files, excluded_files, excluded_extensions, get_cluster_item_key, previous_status=None,
             get_md5=True):
    """Iterate recursively inside a directory, save the path of each found file and obtain its metadata.

    Parameters
    ----------
    dirname : str
        Directory within which to look for files.
    recursive : bool
        Whether to recursively look for files inside found directories.
    files : list
        List of files to obtain information from.
    excluded_files : list
        List of files to ignore.
    excluded_extensions : list
        List of extensions to ignore.
    get_cluster_item_key : str
        Key inside cluster.json['files'] to which each file belongs. This is useful to know what actions to take
        after sending a file from one node to another, depending on the directory the file belongs to.
    previous_status : dict
        Information collected in the previous integration process.
    get_md5 : bool
        Whether to calculate and save the MD5 hash of the found file.

    Returns
    -------
    walk_files : dict
        Paths (keys) and metadata (values) of the requested files found inside 'dirname'.
    """
    if previous_status is None:
        previous_status = {}
    walk_files = {}

    full_dirname = path.join(common.wazuh_path, dirname)
    # Get list of all files and directories inside 'full_dirname'.
    try:
        for root_, _, files_ in walk(full_dirname, topdown=True):
            # Check if recursive flag is set or root is actually the initial lookup directory.
            if recursive or root_ == full_dirname:
                for file_ in files_:
                    # If file is inside 'excluded_files' or file extension is inside 'excluded_extensions', skip over.
                    if file_ in excluded_files or any([file_.endswith(ext) for ext in excluded_extensions]):
                        continue
                    try:
                        #  If 'all' files have been requested or entry is in the specified files list.
                        if files == ['all'] or file_ in files:
                            relative_file_path = path.join(path.relpath(root_, common.wazuh_path), file_)
                            abs_file_path = path.join(root_, file_)
                            file_mod_time = path.getmtime(abs_file_path)
                            try:
                                if file_mod_time == previous_status[relative_file_path]['mod_time']:
                                    # The current file has not changed its mtime since the last integrity process.
                                    walk_files[relative_file_path] = previous_status[relative_file_path]
                                    continue
                            except KeyError:
                                pass
                            # Create dict with metadata for the current file.
                            file_metadata = {"mod_time": file_mod_time, 'cluster_item_key': get_cluster_item_key}
                            if '.merged' in file_:
                                file_metadata['merged'] = True
                                file_metadata['merge_type'] = 'agent-groups'
                                file_metadata['merge_name'] = abs_file_path
                            else:
                                file_metadata['merged'] = False
                            if get_md5:
                                file_metadata['md5'] = md5(abs_file_path)
                            # Use the relative file path as a key to save its metadata dictionary.
                            walk_files[relative_file_path] = file_metadata
                    except FileNotFoundError as e:
                        logger.debug(f"File {file_} was deleted in previous iteration: {e}")
                    except PermissionError as e:
                        logger.error(f"Can't read metadata from file {file_}: {e}")
            else:
                break
    except OSError as e:
        raise WazuhInternalError(3015, e)
    return walk_files


def get_files_status(previous_status=None, get_md5=True):
    """Get all files and metadata inside the directories listed in cluster.json['files'].

    Parameters
    ----------
    previous_status : dict
        Information collected in the previous integration process.
    get_md5 : bool
        Whether to calculate and save the MD5 hash of the found file.

    Returns
    -------
    final_items : dict
        Paths (keys) and metadata (values) of all the files requested in cluster.json['files'].
    """
    if previous_status is None:
        previous_status = {}

    cluster_items = get_cluster_items()

    final_items = {}
    for file_path, item in cluster_items['files'].items():
        if file_path == "excluded_files" or file_path == "excluded_extensions":
            continue
        try:
            final_items.update(
                walk_dir(file_path, item['recursive'], item['files'], cluster_items['files']['excluded_files'],
                         cluster_items['files']['excluded_extensions'], file_path, previous_status, get_md5))
        except Exception as e:
            logger.warning(f"Error getting file status: {e}.")

    return final_items


def get_ruleset_status(previous_status):
    """Get hash of custom ruleset files.

    Parameters
    ----------
    previous_status : dict
        Integrity information of local files.

    Returns
    -------
    Dict
        Relative path and hash of local ruleset files.
    """
    final_items = {}
    cluster_items = get_cluster_items()
    user_ruleset = [os.path.join(to_relative_path(user_path), '') for user_path in [common.user_decoders_path,
                                                                                    common.user_rules_path,
                                                                                    common.user_lists_path]]

    for file_path, item in cluster_items['files'].items():
        if file_path == "excluded_files" or file_path == "excluded_extensions" or file_path not in user_ruleset:
            continue
        try:
            final_items.update(
                walk_dir(file_path, item['recursive'], item['files'], cluster_items['files']['excluded_files'],
                         cluster_items['files']['excluded_extensions'], file_path, previous_status, True))
        except Exception as e:
            logger.warning(f"Error getting file status: {e}.")

    return {file_path: file_data['md5'] for file_path, file_data in final_items.items()}


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
        List of file paths to be zipped.
    cluster_control_json : dict
        KO files (path-metadata) to be zipped as a json.

    Returns
    -------
    zip_file_path : str
        Path where the zip file has been saved.
    """
    failed_files = list()
    zip_file_path = path.join(common.wazuh_path, 'queue', 'cluster', name, f'{name}-{time()}-{str(random())[2:]}.zip')
    if not path.exists(path.dirname(zip_file_path)):
        mkdir_with_mode(path.dirname(zip_file_path))
    with zipfile.ZipFile(zip_file_path, 'x') as zf:
        # write files
        if list_path:
            for f in list_path:
                try:
                    zf.write(filename=path.join(common.wazuh_path, f), arcname=f)
                except zipfile.LargeZipFile as e:
                    raise WazuhError(3001, str(e))
                except Exception as e:
                    logger.debug(f"[Cluster] {str(WazuhException(3001, str(e)))}")
                    failed_files.append(f)
        try:
            if cluster_control_json and failed_files:
                update_cluster_control_with_failed(failed_files, cluster_control_json)
            zf.writestr("files_metadata.json", json.dumps(cluster_control_json))
        except Exception as e:
            raise WazuhError(3001, str(e))

    return zip_file_path


async def async_decompress_files(zip_path, ko_files_name="files_metadata.json"):
    """Async wrapper for decompress_files() function.

    Parameters
    ----------
    zip_path : str
        Full path to the zip file.
    ko_files_name : str
        Name of the metadata json inside zip file.

    Returns
    -------
    ko_files : dict
        Paths (keys) and metadata (values) of the files listed in cluster.json.
    zip_dir : str
        Full path to unzipped directory.
    """
    return decompress_files(zip_path, ko_files_name)


def decompress_files(zip_path, ko_files_name="files_metadata.json"):
    """Unzip files in a directory and load the files_metadata.json as a dict.

    Parameters
    ----------
    zip_path : str
        Full path to the zip file.
    ko_files_name : str
        Name of the metadata json inside zip file.

    Returns
    -------
    ko_files : dict
        Paths (keys) and metadata (values) of the files listed in cluster.json.
    zip_dir : str
        Full path to unzipped directory.
    """
    try:
        ko_files = ""
        # Create a directory like {wazuh_path}/{cluster_path}/123456-123456.zipdir/
        zip_dir = zip_path + 'dir'
        mkdir_with_mode(zip_dir)
        with zipfile.ZipFile(zip_path) as zipf:
            zipf.extractall(path=zip_dir)

        if path.exists(path.join(zip_dir, ko_files_name)):
            with open(path.join(zip_dir, ko_files_name)) as ko:
                ko_files = json.loads(ko.read())
    except Exception as e:
        if path.exists(zip_dir):
            shutil.rmtree(zip_dir)
        raise e
    finally:
        # Once read all files, remove the zipfile.
        remove(zip_path)
    return ko_files, zip_dir


def compare_files(good_files, check_files, node_name):
    """Compare metadata of the master files with metadata of files sent by a worker node.

    Compare the integrity information of each file of the master node against those in the worker node (listed in
    cluster.json), calculated in get_files_status(). The files are classified in four groups depending on the
    information of cluster.json: missing, extra, extra_valid and shared.

    Parameters
    ----------
    good_files : dict
        Paths (keys) and metadata (values) of the master's files.
    check_files : dict
        Paths (keys) and metadata (values) of the worker's files.
    node_name : str
        Name of the worker whose files are being compared.

    Returns
    -------
    files : dict
        Paths (keys) and metadata (values) of the files classified into four groups.
    count : int
        Number of files inside each classification.
    """

    def split_on_condition(seq, condition):
        """Split a sequence into two generators based on a condition.

        Parameters
        ----------
        seq : set
            Set of items to split.
        condition : callable
            Function base splitting on.

        Returns
        -------
        generator
            Items that meet the condition.
        generator
            Items that do not meet the condition.
        """
        l1, l2 = itertools.tee((condition(item), item) for item in seq)
        return (i for p, i in l1 if p), (i for p, i in l2 if not p)

    # Get 'files' dictionary inside cluster.json to read options for each file depending on their
    # directory (permissions, if extra_valid files, etc).
    cluster_items = get_cluster_items()['files']

    # Missing files will be the ones that are present in good files (master) but not in the check files (worker).
    missing_files = {key: good_files[key] for key in good_files.keys() - check_files.keys()}

    # Extra files are the ones present in check files (worker) but not in good files (master) and aren't extra valid.
    extra_valid, extra = split_on_condition(check_files.keys() - good_files.keys(),
                                            lambda x: cluster_items[check_files[x]['cluster_item_key']]['extra_valid'])
    extra_files = {key: check_files[key] for key in extra}
    extra_valid_files = {key: check_files[key] for key in extra_valid}
    if extra_valid_files:
        # Check if extra-valid agent-groups files correspond to existing agents.
        try:
            agent_groups = [os.path.basename(file) for file in extra_valid_files if file.startswith(agent_groups_path)]
            db_agents = []
            # Each query can have at most 7500 agents to prevent it from being larger than the wazuh-db socket.
            # 7 digits in the worst case per ID + comma -> 8 * 7500 = 60000 (wazuh-db socket is ~64000)
            for i in range(0, len(agent_groups), chunk_size := 7500):
                with WazuhDBQueryAgents(select=['id'], limit=None, filters={'rbac_ids': agent_groups[i:i + chunk_size]},
                                        rbac_negate=False) as db_query:
                    db_agents.extend(db_query.run()['items'])
            db_agents = {agent['id'] for agent in db_agents}

            for leftover in set(agent_groups) - db_agents:
                extra_valid_files.pop(os.path.join(agent_groups_path, leftover), None)
        except Exception as e:
            logger.error(f"Error getting agent IDs while verifying which extra-valid files are required: {e}")

    # 'all_shared' files are the ones present in both sets but with different MD5 checksum.
    all_shared = [x for x in check_files.keys() & good_files.keys() if check_files[x]['md5'] != good_files[x]['md5']]

    # 'shared_e_v' are files present in both nodes but need to be merged before sending them to the worker. Only
    # 'agent-groups' files fit into this category.
    # 'shared' files can be sent as is, without merging.
    shared_e_v, shared = split_on_condition(all_shared,
                                            lambda x: cluster_items[check_files[x]['cluster_item_key']]['extra_valid'])
    shared_e_v = list(shared_e_v)
    if shared_e_v:
        # Merge all shared extra valid files into a single one. Create a tuple (merged_filepath, {metadata_dict}).
        shared_merged = [(merge_info(merge_type='agent-groups', files=shared_e_v, file_type='-shared',
                                     node_name=node_name)[1],
                          {'cluster_item_key': 'queue/agent-groups/', 'merged': True, 'merge-type': 'agent-groups'})]

        # Dict merging all 'shared' filepaths (keys) and the merged_filepath (key) created above.
        shared_files = dict(itertools.chain(shared_merged, ((key, good_files[key]) for key in shared)))
    else:
        shared_files = {key: good_files[key] for key in shared}

    files = {'missing': missing_files, 'extra': extra_files, 'shared': shared_files, 'extra_valid': extra_valid_files}
    count = {'missing': len(missing_files), 'extra': len(extra_files), 'extra_valid': len(extra_valid_files),
             'shared': len(all_shared)}

    return files, count


def clean_up(node_name=""):
    """Clean all temporary files generated in the cluster.

    Optionally, it cleans all temporary files of node node_name.

    Parameters
    ----------
    node_name : str
        Name of the node to clean up.
    """

    def remove_directory_contents(local_rm_path):
        """Remove files and directories found in local_rm_path.

        Parameters
        ----------
        local_rm_path : str
            Directory whose content to delete.
        """
        if not path.exists(local_rm_path):
            logger.debug(f"Nothing to remove in '{local_rm_path}'.")
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
                logger.error(f"Error removing '{f_path}': '{err}'.")
                continue

    try:
        rm_path = path.join(common.wazuh_path, 'queue', 'cluster', node_name)
        logger.debug(f"Removing '{rm_path}'.")
        remove_directory_contents(rm_path)
        logger.debug(f"Removed '{rm_path}'.")
    except Exception as e:
        logger.error(f"Error cleaning up: {str(e)}.")


def merge_info(merge_type, node_name, files=None, file_type=""):
    """Merge multiple files into one.

    The merged file has the format below (header: content length, filename, modification time; content of the file):
        8 001 2020-11-23 10:51:23
        default
        16 002 2020-11-23 08:50:48
        default,windows

    Parameters
    ----------
    merge_type : str
        Directory inside {wazuh_path}/queue where the files to merge can be found.
    node_name : str
        Name of the node to which the files will be sent.
    files : list
        Files to merge.
    file_type : str
        Type of merge. I.e: '-shared'.

    Returns
    -------
    files_to_send : int
        Number of files that have been merged.
    output_file : str
        Path to the created merged file.
    """
    merge_path = path.join(common.wazuh_path, 'queue', merge_type)
    output_file = path.join('queue', 'cluster', node_name, merge_type + file_type + '.merged')
    files_to_send = 0
    files = "all" if files is None else {path.basename(f) for f in files}

    with open(path.join(common.wazuh_path, output_file), 'wb') as o_f:
        for filename in listdir(merge_path):
            if files != "all" and filename not in files:
                continue

            full_path = path.join(merge_path, filename)
            stat_data = stat(full_path)

            files_to_send += 1
            with open(full_path, 'rb') as f:
                data = f.read()

            header = f"{len(data)} {filename} {datetime.utcfromtimestamp(stat_data.st_mtime)}"

            o_f.write((header + '\n').encode() + data)

    return files_to_send, output_file


def unmerge_info(merge_type, path_file, filename):
    """Unmerge one file into multiples and yield the information.

    Split the information of a file like the one below, using the name (001, 002...), the modification time
    and the content of each one:
        8 001 2020-11-23 10:51:23
        default
        16 002 2020-11-23 08:50:48
        default,windows

    This function does NOT create any file, it only splits and returns the information.

    Parameters
    ----------
    merge_type : str
        Name of the destination directory inside queue. I.e: {wazuh_path}/queue/{merge_type}/<unmerge_files>.
    path_file : str
        Path to the unzipped merged file.
    filename
        Filename of the merged file.

    Yields
    -------
    str
        Splitted relative file path.
    data : str
        Content of the splitted file.
    st_mtime : str
        Modification time of the splitted file.
    """
    src_path = path.abspath(path.join(path_file, filename))
    dst_path = path.join("queue", merge_type)

    bytes_read = 0
    total_bytes = stat(src_path).st_size
    with open(src_path, 'rb') as src_f:
        while bytes_read < total_bytes:
            # read header
            header = src_f.readline().decode()
            bytes_read += len(header)
            try:
                st_size, name, st_mtime = header[:-1].split(' ', 2)
                st_size = int(st_size)
            except ValueError as e:
                logger.warning(f"Malformed file ({e}). Parsed line: {header}. Some files won't be synced")
                break

            # read data
            data = src_f.read(st_size)
            bytes_read += st_size

            yield path.join(dst_path, name), data, st_mtime


async def run_in_pool(loop, pool, f, *args, **kwargs):
    """Run function in process pool if it exists.

    This function checks if the process pool exists. If it does, the function is run inside it and
    the result is waited. Otherwise (the pool is None), the function is run in the parent process,
    as usual.

    Parameters
    ----------
    loop : AbstractEventLoop
        Asyncio loop.
    pool : ProcessPoolExecutor or None
        Process pool object in charge of running functions.
    f : callable
        Function to be executed.
    *args
        Arguments list to be passed to function `f`. Default `None`.
    **kwargs
        Keyword arguments to be passed to function `f`. Default `None`.

    Returns
    -------
    Result of `f(*args, **kwargs)` function.
    """
    if pool is not None:
        task = loop.run_in_executor(pool, partial(f, *args, **kwargs))
        return await wait_for(task, timeout=None)
    else:
        return f(*args, **kwargs)


async def get_node_ruleset_integrity(lc: LocalClient) -> dict:
    """Retrieve custom ruleset integrity.

    Parameters
    ----------
    lc : LocalClient
        LocalClient instance.

    Returns
    -------
    dict
        Dictionary with results
    """
    response = await lc.execute(command=b"get_hash", data=b"", wait_for_complete=False)

    try:
        result = json.loads(response, object_hook=as_wazuh_object)
    except json.JSONDecodeError as e:
        raise WazuhClusterError(3020) if "timeout" in response else e

    if isinstance(result, Exception):
        raise result

    return result
