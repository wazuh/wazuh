#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import json
from os import remove

from wazuh.cluster.cluster import get_cluster_items, _update_file
from wazuh.exception import WazuhException
from wazuh import common


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
                logging.debug("\t[Client] OVERWRITE {0}".format(file_to_overwrite))
                # Full path
                file_path = common.ossec_path + file_to_overwrite

                # Cluster items information: write mode and umask
                cluster_item_key = data['cluster_item_key']
                w_mode = cluster_items[cluster_item_key]['write_mode']
                umask = int(cluster_items[cluster_item_key]['umask'], base=0)

                # File content and time
                file_data = files_to_update[file_to_overwrite]['data']
                file_time = files_to_update[file_to_overwrite]['time']

                _update_file(fullpath=file_path, new_content=file_data, umask_int=umask, mtime=file_time, w_mode=w_mode, whoami='client')

        except Exception as e:
            print(str(e))
            raise e

    if wrong_files['missing']:
        logging.info("[Client] [Sync process] [Step 3]: Received {} missing files from master. Action: Create files.".format(len(wrong_files['missing'])))
        for file_to_create, data in wrong_files['missing'].iteritems():
            logging.debug("\t[Client] CREATE {0}".format(file_to_create))

            # Full path
            file_path = common.ossec_path + file_to_create

            # Cluster items information: write mode and umask
            cluster_item_key = data['cluster_item_key']
            w_mode = cluster_items[cluster_item_key]['write_mode']
            umask = int(cluster_items[cluster_item_key]['umask'], base=0)

            # File content and time
            file_data = files_to_update[file_to_create]['data']
            file_time = files_to_update[file_to_create]['time']

            _update_file(fullpath=file_path, new_content=file_data, umask_int=umask, mtime=file_time, w_mode=w_mode, whoami='client')


    if wrong_files['extra']:
        logging.info("[Client] [Sync process] [Step 3]: Received {} extra files from master. Action: Remove files.".format(len(wrong_files['extra'])))
        for file_to_remove in wrong_files['extra']:
            logging.debug("\t[Client] REMOVE {0}".format(file_to_remove))
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


