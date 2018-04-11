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
        self.set_lock_interval_thread(False)

    def set_lock_interval_thread(self, status):
        with self.lock:
            self.lock_interval_thread = status

    def get_lock_interval_thread(self):
        with self.lock:
            return self.lock_interval_thread

    def process_request(self, command, data):
        logging.debug("[Client] Request received: '{0}'.".format(command))

        if command == 'echo-m':
            return 'ok-m ', data.decode()
        elif command == 'sync_m_c':
            cmf_thread = ClientProcessMasterFiles(data)
            cmf_thread.setclient(self)
            cmf_thread.start()
            return 'ack', 'Sync: Thanks master, Im going to do it'  # TO DO
        elif command == 'sync_m_c_err':
            logging.info("[Client] The master was not able to send me the files. Unlocking.")
            self.set_lock_interval_thread(False)
            return 'ack', "Thanks!"
        elif command == 'req_sync_m_c':
            return 'ack', 'Starting sync from master on demand'  # TO DO
        elif command == 'getintegrity':
            return 'json', json.dumps({'/etc/client.keys':'pending'})  # TO DO
        elif command == 'file_status':
            return 'json', json.dumps({'/etc/client.keys': {
                                            'mod_time': '2018-04-10 16:31:50',
                                            'md5': 'a'*32
                                    }})
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


    def send_client_files_to_master(self, reason=None, tag=None):
        sync_result = False

        if not tag:
            tag = "[Client] [Sync process c->m]"

        logging.info("{0}: Start. Reason: '{1}'".format(tag, reason))

        # Step 1
        logging.info("{0} [Step 1]: Finding master.".format(tag))

        master_node = self.config['nodes'][0]  # Now, we only have 1 node: the master

        logging.info("{0} [Step 1]: Master: {1}.".format(tag, master_node))


        # Step 2
        logging.info("{0} [Step 2]: Gathering files.".format(tag))
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
        logging.info("{0} [Step 3]: Sending files to master.".format(tag))


        response = self.send_request('sync_c_m', compressed_data)
        processed_response = self.process_response(response)
        if processed_response:
            sync_result = True
            logging.info("{0} [Step 3]: {1}".format(tag, processed_response))
        else:
            logging.error("{0} [Step 3]: Master reported an error receiving files.".format(tag))

        return sync_result


    def process_files_from_master(self, data_received, tag=None):
        sync_result = False

        if not tag:
            tag = "[Client] [Sync process m->c]"

        logging.info("{0}: Start.".format(tag))

        master_data  = decompress_files(data_received)

        # Extract received data
        logging.info("{0} [STEP 1]: Analyzing received files.".format(tag))

        ko_files = {}
        master_files = {}
        for key in master_data:
            if key == 'cluster_control.json':
                ko_files = json.loads(master_data['cluster_control.json']['data'])
            else:
                full_path_key = key.replace('files/', '/')
                master_files[full_path_key] = master_data[key]

        # Update files
        logging.info("{0} [STEP 2]: Updating client files.".format(tag))
        sync_result = ClientManager._update_master_files_in_client(ko_files, master_files, tag)


        # ToDo: Send ACK

        return sync_result

    @staticmethod
    def _update_master_files_in_client(wrong_files, files_to_update, tag=None):
        if not tag:
            tag = "[Client] [Sync process]"

        cluster_items = get_cluster_items()

        if not wrong_files['shared'] and not wrong_files['missing'] and not wrong_files['extra']:
            logging.info("{0} [Step 3]: Client meets integrity checks. No actions.".format(tag))
        else:
            logging.info("{0} [Step 3]: Client does not meet integrity checks. Actions required.".format(tag))


        if wrong_files['shared']:
            logging.info("{0} [Step 3]: Received {1} wrong files to fix from master. Action: Overwrite files.".format(tag, len(wrong_files['shared'])))
            try:
                for file_to_overwrite, data in wrong_files['shared'].iteritems():
                    logging.debug("{0} Overwrite file: '{1}'".format(tag, file_to_overwrite))
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
            logging.info("{0} [Step 3]: Received {1} missing files from master. Action: Create files.".format(tag, len(wrong_files['missing'])))
            for file_to_create, data in wrong_files['missing'].iteritems():
                logging.debug("{0} Create file: '{1}'".format(tag, file_to_create))

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
            logging.info("{0} [Step 3]: Received {1} extra files from master. Action: Remove files.".format(tag, len(wrong_files['extra'])))
            for file_to_remove in wrong_files['extra']:
                logging.debug("{0} Remove file: '{1}'".format(tag, file_to_remove))
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
        self.thread_tag = "[Client] [ClientIntervalThread] [Sync process c->m]"


    def run(self):
        while self.running:
            # Waint until client is set
            if not self.client:
                time.sleep(2)
                continue

            # Waint until client is connected
            if not self.client.is_connected():
                check_seconds = 2
                logging.info("{0}: Client is not connected. Waiting: {1}s.".format(self.thread_tag, check_seconds))
                time.sleep(check_seconds)
                continue

            # Client set and connected
            try:
                new_interval = self.client.config['interval']

                # Send files
                result = self.client.send_client_files_to_master(reason="Interval", tag=self.thread_tag)

                # Master received the file properly
                if result:
                    logging.info("{0}: Result: Successfully.".format(self.thread_tag))

                    # Lock until:
                    #  - Master sends files: sync_m_c
                    #  - Master sends error: sync_m_c_err
                    #  - Client is disconnected and connected again
                    logging.info("{0}: Locking: Wait for master files.".format(self.thread_tag))
                    self.client.set_lock_interval_thread(True)
                    n_seconds = 0
                    while self.client.get_lock_interval_thread():
                        # Print each 5 seconds
                        if n_seconds != 0 and n_seconds % 5 == 0:
                            logging.info("{0}: Master didnt send the files in the last 5 seconds.".format(self.thread_tag))

                        time.sleep(1)
                        n_seconds += 1

                    logging.info("{0}: Unlocked: Master files processed.".format(self.thread_tag))
                    new_interval = max(0, self.client.config['interval'] - n_seconds)

                # Master reported an error receiving files
                else:
                    logging.error("{0}: Result: Error.".format(self.thread_tag))
            except Exception as e:
                logging.error("{0}: Unknown Error: '{1}'.".format(self.thread_tag, str(e)))

            logging.info("{0}: Sleeping: {1}s.".format(self.thread_tag, new_interval))
            time.sleep(new_interval)


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
        self.thread_tag = "[Client] [ProcessFilesThread] [Sync process m->c]"


    def run(self):
        while self.running:
            if self.client and self.client.is_connected():

                try:
                    result = self.client.process_files_from_master(self.data)
                    if result:
                        logging.info("{0}: Result: Successfully.".format(self.thread_tag))
                    else:
                        logging.error("{0}: Result: Error.".format(self.thread_tag))
                except:
                    logging.error("{0}: Result: Unknown error.".format(self.thread_tag))

                logging.info("{0}: Unlocking Interval thread.".format(self.thread_tag))
                self.client.set_lock_interval_thread(False)
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
