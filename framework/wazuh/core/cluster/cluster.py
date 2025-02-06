# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import errno
import itertools
import json
import logging
import os.path
import shutil
import zlib
from asyncio import wait_for
from collections import defaultdict
from functools import partial
from os import listdir, path, remove, stat, walk
from uuid import uuid4

from jsonschema import ValidationError, validate, validators
from wazuh import WazuhError, WazuhException, WazuhInternalError
from wazuh.core import common
from wazuh.core.cluster.utils import (
    AGENT_CHUNK_SIZE,
    AGENT_RECONNECTION_STABILITY_TIME,
    AGENT_RECONNECTION_TIME,
    FREQUENCY,
    HAPROXY_HELPER,
    HAPROXY_PORT,
    HAPROXY_PROTOCOL,
    IMBALANCE_TOLERANCE,
    REMOVE_DISCONNECTED_NODE_AFTER,
)
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.InputValidator import InputValidator
from wazuh.core.utils import blake2b, get_date_from_timestamp, get_utc_now, mkdir_with_mode

logger = logging.getLogger('wazuh')

# Separators used in compression/decompression functions to delimit files.
FILE_SEP = '|@@//@@|'
PATH_SEP = '|//@@//|'
MIN_PORT = 1024
MAX_PORT = 65535

HAPROXY_HELPER_SCHEMA = {
    'type': 'object',
    'properties': {
        HAPROXY_PORT: {'type': 'integer', 'minimum': MIN_PORT, 'maximum': MAX_PORT},
        HAPROXY_PROTOCOL: {'type': 'string', 'enum': ['http', 'https']},
        FREQUENCY: {'type': 'integer', 'minimum': 10},
        AGENT_RECONNECTION_STABILITY_TIME: {'type': 'integer', 'minimum': 10},
        AGENT_CHUNK_SIZE: {'type': 'integer', 'minimum': 100},
        AGENT_RECONNECTION_TIME: {'type': 'integer', 'minimum': 0},
        IMBALANCE_TOLERANCE: {'type': 'number', 'exclusiveMinimum': 0, 'maximum': 1},
        REMOVE_DISCONNECTED_NODE_AFTER: {'type': 'integer', 'minimum': 0},
    },
}

#
# Cluster
#


def validate_haproxy_helper_config(config: dict):
    """Validate the values of the give HAProxy helper configuration.

    Parameters
    ----------
    config : dict
        Configuration to validate.

    Raises
    ------
    WazuhError(3004)
        If there any invalid value.
    """
    try:
        validate(config, HAPROXY_HELPER_SCHEMA, cls=validators.Draft202012Validator)
    except ValidationError as error:
        raise WazuhError(3004, f'Invalid value for {error.path.pop()}. {error.message}')


def validate_file_path(config: dict, key: str):
    """Validate a file path is within WAZUH_ETC and that the file exists.

    Parameters
    ----------
    config : dict
        Configuration to validate.
    key : str
        Key of the configuration where the file path is stored.

    Raises
    ------
    WazuhError(3004)
        If the file path is invalid.
    """
    filepath = config[key]

    if not filepath.is_relative_to(common.WAZUH_ETC):
        raise WazuhError(3004, f'The {key} path ({filepath}) is not inside {common.WAZUH_ETC}.')

    if '..' in str(filepath):
        raise WazuhError(3004, f'The {key} path ({filepath}) contains "..".')

    if not filepath.exists():
        raise WazuhError(3004, f'The {key} "{filepath}" does not exist.')


def check_cluster_config(config):
    """Verify that cluster configuration is correct.

    Following points are checked:
        - Cluster config block is not empty.
        - node_type is 'master' or 'worker'.
        - Port is an int type.
        - 1024 < port < 65535.
        - Only 1 node is specified.
        - CAfile, certfile and keyfile paths exist.

    Parameters
    ----------
    config : dict
        Cluster configuration.

    Raises
    ------
    WazuhError
        If any of above conditions is not met.
    """
    InputValidator()

    if config['node_type'] != 'master' and config['node_type'] != 'worker':
        raise WazuhError(3004, f'Invalid node type {config["node_type"]}. Correct values are master and worker')

    if not isinstance(config['port'], int):
        raise WazuhError(3004, 'Port has to be an integer.')

    if not MIN_PORT < config['port'] < MAX_PORT:
        raise WazuhError(3004, f'Port must be higher than {MIN_PORT} and lower than {MAX_PORT}.')

    cert_keys = ['cafile', 'certfile', 'keyfile']
    if len(cert_keys) > len(set(config[key] for key in cert_keys)):
        raise WazuhError(3004, 'Paths to certificates and keys must be different.')

    for key in cert_keys:
        validate_file_path(config, key)

    if len(config['nodes']) > 1:
        logger.warning(
            'Found more than one node in configuration. Only master node should be specified. Using {} as master.'.format(
                config['nodes'][0]
            )
        )

    validate_haproxy_helper_config(config.get(HAPROXY_HELPER, {}))


def get_node():
    """Get dict with current active node information.

    Returns
    -------
    data : dict
        Dict containing current node_name and node_type.
    """
    data = {}
    server_config = CentralizedConfig.get_server_config()

    data['node'] = server_config.node.name
    data['type'] = server_config.node.type

    return data


#
# Files
#


def walk_dir(
    dirname,
    recursive,
    files,
    excluded_files,
    excluded_extensions,
    get_cluster_item_key,
    previous_status=None,
    get_hash=True,
):
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
    get_hash : bool
        Whether to calculate and save the BLAKE2b hash of the found file.

    Returns
    -------
    walk_files : dict
        Paths (keys) and metadata (values) of the requested files found inside 'dirname'.
    result_logs: dict
        Dict containing debug or any error messages emitted in the process.
    """
    if previous_status is None:
        previous_status = {}
    walk_files = {}
    result_logs = {'debug': defaultdict(list), 'error': defaultdict(list)}
    full_dirname = path.join(common.WAZUH_ETC, dirname)
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
                            relative_file_path = path.join(path.relpath(root_, common.WAZUH_ETC), file_)
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
                            # The TYPE string is a placeholder to define the type of merge performed.
                            file_metadata = {'mod_time': file_mod_time, 'cluster_item_key': get_cluster_item_key}
                            if '.merged' not in file_:
                                file_metadata['merged'] = False
                            else:
                                file_metadata['merged'] = True
                                file_metadata['merge_type'] = 'TYPE'
                                file_metadata['merge_name'] = abs_file_path
                            if get_hash:
                                file_metadata['hash'] = blake2b(abs_file_path)
                            # Use the relative file path as a key to save its metadata dictionary.
                            walk_files[relative_file_path] = file_metadata
                    except FileNotFoundError as e:
                        result_logs['debug'][root_].append(f'File {file_} was deleted in previous iteration: {e}')
                    except PermissionError as e:
                        result_logs['error'][root_].append(f"Can't read metadata from file {file_}: {e}")
            else:
                break
    except OSError as e:
        raise WazuhInternalError(3015, e)
    return walk_files, result_logs


def get_files_status(previous_status=None, get_hash=True):
    """Get all files and metadata inside the directories listed in cluster.json['files'].

    Parameters
    ----------
    previous_status : dict
        Information collected in the previous integration process.
    get_hash : bool
        Whether to calculate and save the BLAKE2b hash of the found file.

    Returns
    -------
    final_items : dict
        Paths (keys) and metadata (values) of all the files requested in cluster.json['files'].
    result_logs: dict
        Dict containing debug or any error messages emitted in the process.
    """
    if previous_status is None:
        previous_status = {}

    server_config = CentralizedConfig.get_internal_server_config()

    final_items = {}
    result_logs = {'debug': defaultdict(dict), 'warning': defaultdict(list), 'error': defaultdict(dict)}
    for file_config in server_config.files:
        if file_config.dir == 'excluded_files' or file_config.dir == 'excluded_extensions':
            continue
        try:
            items, logs = walk_dir(
                file_config.dir,
                file_config.recursive,
                file_config.names,
                server_config.excluded_files,
                server_config.excluded_extensions,
                file_config.dir,
                previous_status,
                get_hash,
            )
            if 'debug' in logs and logs['debug']:
                result_logs['debug'][file_config.dir].update(dict(logs['debug']))
            if 'error' in logs and logs['error']:
                result_logs['error'][file_config.dir].update(dict(logs['error']))
            final_items.update(items)
        except Exception as e:
            result_logs['warning'][file_config.dir].append(f'Error getting file status: {e}.')

    return final_items, result_logs


def update_cluster_control(failed_file, ko_files, exists=True):
    """Move or remove files listed inside 'ko_files'.

    Sometimes, files that could not be compressed or that no longer exist, are still listed in cluster_control.json.
    Two situations can occur:
        - A missing file on a worker no longer exists on the master. It is removed from the list of missing files.
        - A missing file on a worker could not be compressed (too big or not space left). It is also removed from
        the list of missing files.
        - A shared file no longer exists on the master. It is deleted from 'shared' and added to 'extra'.
        - A shared file could not be compressed (too big or not space left). It is removed from the 'shared' list.

    Parameters
    ----------
    failed_file : str
        File path (used as a dict key) to be searched and updated/deleted in the ko_files dict.
    ko_files : dict
        KO files dict with 'missing', 'shared' and 'extra' keys.
    exists : bool
        Whether the file to be removed exists in the master. If it does not exist, but it is in the 'shared' list,
        it should be moved to the 'extra' files list.
    """
    try:
        if failed_file in ko_files['missing']:
            ko_files['missing'].pop(failed_file, None)
        elif failed_file in ko_files['shared']:
            if not exists:
                ko_files['extra'][failed_file] = ko_files['shared'][failed_file]
            ko_files['shared'].pop(failed_file, None)
    except (KeyError, AttributeError, TypeError):
        pass


def compress_files(name, list_path, cluster_control_json=None, max_zip_size=None):
    """Create a zip with cluster_control.json and the files listed in list_path.

    Iterate the list of files and groups them in a compressed file. If a file does not
    exist, the cluster_control_json dictionary is updated.

    Parameters
    ----------
    name : str
        Name of the node to which the compress file will be sent.
    list_path : list
        File paths to be zipped.
    cluster_control_json : dict
        KO files (path-metadata) to be compressed as a json.
    max_zip_size : int
        Maximum size from which no new files should be added to the zip.

    Returns
    -------
    compress_file_path : str
        Path where the compress file has been saved.
    result_logs: dict
        Dict containing warning and debug messages emitted in the process.
    """
    zip_size = 0
    exceeded_size = False
    result_logs = {'warning': defaultdict(list), 'debug': defaultdict(list)}
    server_config = CentralizedConfig.get_server_config()

    compress_level = server_config.communications.zip.compress_level
    if max_zip_size is None:
        max_zip_size = server_config.communications.zip.max_size
    zip_file_path = path.join(common.WAZUH_QUEUE, name, f'{name}-{get_utc_now().timestamp()}-{uuid4().hex}.zip')

    if not path.exists(path.dirname(zip_file_path)):
        mkdir_with_mode(path.dirname(zip_file_path))

    with open(zip_file_path, 'ab') as wf:
        for file in list_path:
            if exceeded_size:
                update_cluster_control(file, cluster_control_json)
                continue

            try:
                with open(path.join(common.WAZUH_ETC, file), 'rb') as rf:
                    new_file = rf.read()
                    if len(new_file) > max_zip_size:
                        result_logs['warning'][file].append(
                            f'File too large to be synced: ' f'{path.join(common.WAZUH_ETC, file)}'
                        )
                        update_cluster_control(file, cluster_control_json)
                        continue
                    # Compress the content of each file and surrounds it with separators.
                    new_file = (
                        f'{file}{PATH_SEP}'.encode() + zlib.compress(new_file, level=compress_level) + FILE_SEP.encode()
                    )

                if (len(new_file) + zip_size) <= max_zip_size:
                    # Append the new compressed file to previous ones only if total size is under max allowed.
                    zip_size += len(new_file)
                    wf.write(new_file)
                else:
                    # Otherwise, remove it from cluster_control_json.
                    result_logs['warning'][file].append(
                        'Maximum zip size exceeded. ' 'Not all files will be compressed during this sync.'
                    )
                    exceeded_size = True
                    update_cluster_control(file, cluster_control_json)
            except zlib.error as e:
                raise WazuhError(3001, str(e))
            except Exception as e:
                result_logs['debug'][file].append('Exception raised: ' + str(WazuhException(3001, str(e))))
                update_cluster_control(file, cluster_control_json, exists=False)

        try:
            # Compress and save cluster_control data as a JSON.
            wf.write(
                f'files_metadata.json{PATH_SEP}'.encode()
                + zlib.compress(json.dumps(cluster_control_json).encode(), level=compress_level)
            )
        except Exception as e:
            raise WazuhError(3001, str(e))

    return zip_file_path, result_logs


async def async_decompress_files(zip_path, ko_files_name='files_metadata.json'):
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


def decompress_files(compress_path, ko_files_name='files_metadata.json'):
    """Decompress files in a directory and load the files_metadata.json as a dict.

    To avoid consuming too many memory resources, the compressed file is read in chunks
    of 'windows_size' and split based on a file separator.

    Parameters
    ----------
    compress_path : str
        Full path to the compress file.
    ko_files_name : str
        Name of the metadata json inside the compress file.

    Returns
    -------
    ko_files : dict
        Paths (keys) and metadata (values) of the files listed in cluster.json.
    zip_dir : str
        Full path to decompressed directory.
    """
    ko_files = ''
    compressed_data = b''
    window_size = 1024 * 1024 * 10  # 10 MiB
    decompress_dir = compress_path + 'dir'

    try:
        mkdir_with_mode(decompress_dir)

        with open(compress_path, 'rb') as rf:
            while True:
                new_data = rf.read(window_size)
                compressed_data += new_data
                files = compressed_data.split(FILE_SEP.encode())
                if new_data:
                    # If 'files' list contains only 1 item, it is probably incomplete, so it is not used.
                    compressed_data = files.pop(-1)

                for file in files:
                    filepath, content = file.split(PATH_SEP.encode(), 1)
                    content = zlib.decompress(content)
                    full_path = os.path.join(decompress_dir, filepath.decode())
                    if not os.path.exists(os.path.dirname(full_path)):
                        try:
                            os.makedirs(os.path.dirname(full_path))
                        except OSError as exc:  # Guard against race condition
                            if exc.errno != errno.EEXIST:
                                raise
                    with open(full_path, 'wb') as f:
                        f.write(content)

                if not new_data:
                    break

        if path.exists(path.join(decompress_dir, ko_files_name)):
            with open(path.join(decompress_dir, ko_files_name)) as ko:
                ko_files = json.loads(ko.read())
    except Exception as e:
        if path.exists(decompress_dir):
            shutil.rmtree(decompress_dir)
        raise e
    finally:
        # Once read all files, remove the compress file.
        remove(compress_path)

    return ko_files, decompress_dir


def compare_files(good_files, check_files, node_name):
    """Compare metadata of the master files with metadata of files sent by a worker node.

    Compare the integrity information of each file of the master node against those in the worker node (listed in
    cluster.json), calculated in get_files_status(). The files are classified in four groups depending on the
    information of cluster.json: missing, extra, and shared.

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

    # Get 'SharedFiles' object  to read options for each file depending on their
    # directory (permissions, if extra_valid files, etc).
    server_config = CentralizedConfig.get_internal_server_config()

    # Missing files will be the ones that are present in good files (master) but not in the check files (worker).
    missing_files = {key: good_files[key] for key in good_files.keys() - check_files.keys()}

    # Extra files are the ones present in check files (worker) but not in good files (master). The underscore is used
    # to not change the function, as previously it returned an iterator for the 'extra_valid' files as well, but these
    # are no longer in use.
    def condition_func(x):
        return next(
            (
                file_config.extra_valid
                for file_config in server_config.files
                if file_config.dir == check_files[x]['cluster_item_key']
            ),
            False,
        )

    _extra_valid, extra = split_on_condition(check_files.keys() - good_files.keys(), condition_func)
    extra_files = {key: check_files[key] for key in extra}
    # extra_valid_files = {key: check_files[key] for key in _extra_valid}

    # This condition should never take place. The 'PATH' string is a placeholder to indicate the type of variable that
    # we should place.
    # if extra_valid_files:
    #     extra_valid_function()

    # 'all_shared' files are the ones present in both sets but with different BLAKE2b checksum.
    all_shared = [x for x in check_files.keys() & good_files.keys() if check_files[x]['hash'] != good_files[x]['hash']]

    # 'shared_e_v' are files present in both nodes but need to be merged before sending them to the worker. Only
    # 'agent-groups' files fit into this category.
    # 'shared' files can be sent as is, without merging.
    shared_e_v, shared = split_on_condition(all_shared, condition_func)
    shared_e_v = list(shared_e_v)
    if shared_e_v:
        # Merge all shared extra valid files into a single one. Create a tuple (merged_filepath, {metadata_dict}).
        # The TYPE and ITEM_KEY strings are placeholders for the merge type and the cluster item key.
        shared_merged = [
            (
                merge_info(merge_type='TYPE', files=shared_e_v, file_type='-shared', node_name=node_name)[1],
                {'cluster_item_key': 'ITEM_KEY', 'merged': True, 'merge-type': 'TYPE'},
            )
        ]

        # Dict merging all 'shared' filepaths (keys) and the merged_filepath (key) created above.
        shared_files = dict(itertools.chain(shared_merged, ((key, good_files[key]) for key in shared)))
    else:
        shared_files = {key: good_files[key] for key in shared}

    return {'missing': missing_files, 'extra': extra_files, 'shared': shared_files}


def clean_up(node_name=''):
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
            if f == common.LOCAL_SERVER_SOCKET:
                continue
            f_path = path.join(local_rm_path, f)
            try:
                if path.isdir(f_path):
                    shutil.rmtree(f_path)
                else:
                    remove(f_path)
            except Exception as err:
                logger.error(f"Error removing '{f_path}': '{err}'.")
                continue

    try:
        rm_path = path.join(common.WAZUH_QUEUE, node_name)
        logger.debug(f"Removing '{rm_path}'.")
        remove_directory_contents(rm_path)
        logger.debug(f"Removed '{rm_path}'.")
    except Exception as e:
        logger.error(f'Error cleaning up: {str(e)}.')


def merge_info(merge_type, node_name, files=None, file_type=''):
    """Merge multiple files into one.

    The merged file has the format below (header: content length, filename, modification time; content of the file):
        8 001 2020-11-23 10:51:23
        default
        16 002 2020-11-23 08:50:48
        default,windows

    Parameters
    ----------
    merge_type : str
        Directory inside {wazuh_path}/PATH where the files to merge can be found.
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
    merge_path = path.join(common.WAZUH_QUEUE, merge_type)
    output_file = path.join('cluster', node_name, merge_type + file_type + '.merged')
    files_to_send = 0
    files = 'all' if files is None else {path.basename(f) for f in files}

    with open(path.join(common.WAZUH_RUN, output_file), 'wb') as o_f:
        for filename in listdir(merge_path):
            if files != 'all' and filename not in files:
                continue

            full_path = path.join(merge_path, filename)
            stat_data = stat(full_path)

            files_to_send += 1
            with open(full_path, 'rb') as f:
                data = f.read()

            header = f'{len(data)} {filename} {get_date_from_timestamp(stat_data.st_mtime)}'

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
        Name of the destination directory inside queue. I.e: {wazuh_path}/PATH/{merge_type}/<unmerge_files>.
    path_file : str
        Path to the unzipped merged file.
    filename : str
        Filename of the merged file.

    Yields
    ------
    str
        Splitted relative file path.
    data : str
        Content of the splitted file.
    st_mtime : str
        Modification time of the splitted file.
    """
    src_path = path.abspath(path.join(path_file, filename))
    dst_path = path.join('queue', merge_type)

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
