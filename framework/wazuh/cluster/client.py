#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import json
import threading
import time
from os import remove

from wazuh.cluster.cluster import get_cluster_items, _update_file, get_files_status, compress_files, decompress_files
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.cluster.communication import ClientHandler, Handler


class ClientManager(ClientHandler):

    def __init__(self, cluster_config):
        ClientHandler.__init__(self, cluster_config['nodes'][0], cluster_config['port'], cluster_config['node_name'])

        self.config = cluster_config


    def process_request(self, command, data):
        logging.debug("[Client] Request received: '{0}'.".format(command))

        if command == 'echo-m':
            return 'ok-m ', data.decode()
        elif command == 'sync_m_c':
            cmf_thread = ClientProcessMasterFiles(data)
            cmf_thread.setclient(self)
            cmf_thread.start()
            return 'ack', 'Sync: Thanks master, Im going to do it'  # TO DO
        elif command == 'req_sync_m_c':
            return 'ack', 'Starting sync from master on demand'  # TO DO
        elif command == 'getintegrity':
            return 'json', json.dumps({'/etc/client.keys':'pending'})  # TO DO
        else:
            return ClientHandler.process_request(self, command, data)


    @staticmethod
    def process_response(response):
        # FixMe: Move this line to communications
        answer, payload = Handler.split_data(response)

        logging.debug("[Client] Response received: '{0}'.".format(answer))

        response_data = None

        if answer == 'ok-c':  # test
            response_data = '[response_only_for_client] Master answered: {}.'.format(payload)
        else:
            response_data = ClientHandler.process_response(response)

        return response_data


    def send_client_files_to_master(self, reason=None):
        sync_result = False

        logging.info("[Client] [Sync process c->m]: Start. Reason: '{0}'".format(reason))

        # Step 1
        logging.info("[Client] [Sync process c->m] [Step 1]: Finding master.")

        master_node = self.config['nodes'][0]  # Now, we only have 1 node: the master

        logging.info("[Client] [Sync process c->m] [Step 1]: Master: {0}.".format(master_node))


        # Step 2
        logging.info("[Client] [Sync process c->m] [Step 2]: Gathering files.")
        # Get master files (path, md5, mtime): client.keys, ossec.conf, groups, ...
        master_files = get_files_status('master')
        client_files = get_files_status('client', get_md5=False)
        cluster_control_json = {'master_files': master_files, 'client_files': client_files}

        # Getting client file paths: agent-info, agent-groups.
        client_files_paths = client_files.keys()

        # Compress data: client files + control json
        compressed_data = compress_files('client', client_files_paths, cluster_control_json)


        # Step 3
        # Send compressed file to master
        logging.info("[Client] [Sync process c->m] [Step 3]: Sending files to master.")


        response = self.send_request('sync_c_m', compressed_data)
        processed_response = self.process_response(response)
        if processed_response:
            sync_result = True
            logging.info("[Client] [Sync process c->m] [Step 3]: {0}".format(processed_response))
        else:
            logging.error("[Client] [Sync process c->m] [Step 3]: Master reported an error receiving files.")

        return sync_result


    def process_files_from_master(self, data_received):
        sync_result = False

        logging.info("[Client] [Sync process m->c]: Start.")

        master_data  = decompress_files(data_received)

        # Extract received data
        logging.info("[Client] [Sync process m->c] [STEP 1]: Analyzing received files.")

        ko_files = {}
        master_files = {}
        for key in master_data:
            if key == 'cluster_control.json':
                ko_files = json.loads(master_data['cluster_control.json']['data'])
            else:
                full_path_key = key.replace('files/', '/')
                master_files[full_path_key] = master_data[key]

        # Update files
        logging.info("[Client] [Sync process m->c] [STEP 2]: Updating client files.")
        sync_result = ClientManager._update_master_files_in_client(ko_files, master_files)


        # ToDo: Send ACK

        return sync_result

    @staticmethod
    def _update_master_files_in_client(wrong_files, files_to_update):

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


#
# Client threads
#
class ClientIntervalThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.client = None
        self.running = True


    def run(self):
        while self.running:
            if self.client and self.client.is_connected():
                result = self.client.send_client_files_to_master(reason="Interval")
                if result:
                    logging.info("[Client] [Sync process c->m]: Result: Successfully.")
                else:
                    logging.error("[Client] [Sync process c->m]: Result: Error.")

                logging.info("[Client] [Sync process c->m] Sleeping: {0}s.".format(self.client.config['interval']))
                time.sleep(self.client.config['interval'])
            else:
                time.sleep(5)


    def setclient(self, client):
        self.client = client


    def stop(self):
        self.running = False


class ClientProcessMasterFiles(threading.Thread):

    def __init__(self, data):
        threading.Thread.__init__(self)
        self.daemon = True
        self.client = None
        self.running = True
        self.data = data


    def run(self):
        while self.running:
            if self.client and self.client.is_connected():

                logging.debug("[Client-FileThread] Started.")
                result = self.client.process_files_from_master(self.data)
                if result:
                    logging.info("[Client] [Sync process m->c]: Result: Successfully.")
                else:
                    logging.error("[Client] [Sync process m->c]: Result: Error.")
                logging.debug("[Client-FileThread] Ended.")

                self.stop()
            else:
                time.sleep(5)


    def setclient(self, client):
        self.client = client


    def stop(self):
        self.running = False


#
# Internal socket
#
from wazuh.cluster.communication import InternalSocketHandler

class ClientInternalSocketHandler(InternalSocketHandler):
    def __init__(self, sock, manager, map):
        InternalSocketHandler.__init__(self, sock=sock, manager=manager, map=map)

    def process_request(self, command, data):
        logging.debug("[Transport-I] Forwarding request to cluster clients '{0}' - '{1}'".format(command, data))
        serialized_response = ""

        response = self.manager.send_request(command=command, data=data).split(' ', 1)
        if response:
            serialized_response = response.split(' ', 1)

        return serialized_response
