#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from wazuh.cluster.cluster import get_cluster_items, _update_file
from wazuh.exception import WazuhException
from wazuh import common


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

            _update_file(fullpath=file_path, new_content=file_data, umask_int=umask, mtime=file_time, w_mode=w_mode, whoami='master')

    except Exception as e:
        print(str(e))
        raise e
