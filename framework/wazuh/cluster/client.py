#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import json
import threading
import time
import os
import shutil
import ast

from wazuh.cluster.cluster import get_cluster_items, _update_file, get_files_status, compress_files, decompress_files, get_files_status, clean_up
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.utils import mkdir_with_mode
from wazuh.cluster.communication import ClientHandler, Handler, ProcessFiles, ClusterThread, InternalSocketHandler


#
# Client Handler
# There is only one ClientManagerHandler: the connection with master.
#
class ClientManagerHandler(ClientHandler):

    def __init__(self, cluster_config):
        ClientHandler.__init__(self, cluster_config['nodes'][0], cluster_config['port'], cluster_config['node_name'])

        self.config = cluster_config
        self.set_lock_interval_thread(False)

    # Overridden methods
    def handle_connect(self):
        ClientHandler.handle_connect(self)
        dir_path = "{}/queue/cluster/{}".format(common.ossec_path, self.name)
        if not os.path.exists(dir_path):
            mkdir_with_mode(dir_path)


    def process_request(self, command, data):
        logging.debug("[Client] Request received: '{0}'.".format(command))

        if command == 'echo-m':
            return 'ok-m ', data.decode()
        elif command == 'sync_m_c':
            cmf_thread = ClientProcessMasterFiles(manager_handler=self, filename=data, stopper=self.stopper)
            cmf_thread.start()
            return 'ack', self.set_worker(command, cmf_thread, data)
        elif command == 'sync_m_c_ok':
            logging.info("[Client] The master says that everything is right. Unlocking.")
            self.set_lock_interval_thread(False)
            return 'ack', "Thanks2!"
        elif command == 'sync_m_c_err':
            logging.info("[Client] The master was not able to send me the files. Unlocking.")
            self.set_lock_interval_thread(False)
            return 'ack', "Thanks!"
        elif command == 'req_sync_m_c':
            return 'ack', 'Starting sync from master on demand'  # TO DO
        elif command == 'getintegrity':
            return 'json', json.dumps({'/etc/client.keys':'pending'})  # TO DO
        elif command == 'file_status':
            master_files = get_files_status('master', get_md5=True)
            client_files = get_files_status('client', get_md5=True)
            files = master_files
            files.update(client_files)
            return 'json', json.dumps(files)
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

    # Private methods
    @staticmethod
    def _update_master_files_in_client(wrong_files, zip_path_dir, tag=None):
        def overwrite_or_create_files(filename, data):
            # Full path
            file_path = common.ossec_path + filename
            zip_path = "{}/{}".format(zip_path_dir, filename.replace('/','_'))

            # Cluster items information: write mode and umask
            cluster_item_key = data['cluster_item_key']
            w_mode = cluster_items[cluster_item_key]['write_mode']
            umask = int(cluster_items[cluster_item_key]['umask'], base=0)

            # File content and time
            with open(zip_path, 'rb') as f:
                file_data = f.read()

            _update_file(fullpath=file_path, new_content=file_data,
                         umask_int=umask, w_mode=w_mode, whoami='client')

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
                for file_to_overwrite, data in wrong_files['shared'].items():
                    logging.debug("{0} Overwrite file: '{1}'".format(tag, file_to_overwrite))
                    overwrite_or_create_files(file_to_overwrite, data)

            except Exception as e:
                print(str(e))
                raise e

        if wrong_files['missing']:
            logging.info("{0} [Step 3]: Received {1} missing files from master. Action: Create files.".format(tag, len(wrong_files['missing'])))
            for file_to_create, data in wrong_files['missing'].items():
                logging.debug("{0} Create file: '{1}'".format(tag, file_to_create))
                overwrite_or_create_files(file_to_create, data)

        if wrong_files['extra']:
            logging.info("{0} [Step 3]: Received {1} extra files from master. Action: Remove files.".format(tag, len(wrong_files['extra'])))
            for file_to_remove in wrong_files['extra']:
                logging.debug("{0} Remove file: '{1}'".format(tag, file_to_remove))
                file_path = common.ossec_path + file_to_remove
                os.remove(file_path)


        return True


    # New methods
    def set_lock_interval_thread(self, status):
        with self.lock:
            self.lock_interval_thread = status


    def get_lock_interval_thread(self):
        with self.lock:
            return self.lock_interval_thread


    def send_integrity_to_master(self, reason=None, tag=None):
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
        cluster_control_json = {'master_files': master_files, 'client_files': None}

        # Compress data: control json
        compressed_data_path = compress_files('client', self.name, None, cluster_control_json)

        # Step 3
        # Send compressed file to master
        logging.info("{0} [Step 3]: Sending files to master.".format(tag))

        response = self.send_file(reason = 'sync_i_c_m', file = compressed_data_path, remove = True)
        processed_response = self.process_response(response)
        if processed_response:
            sync_result = True
            logging.info("{0} [Step 3]: Master received the sync properly.".format(tag))
        else:
            logging.error("{0} [Step 3]: Master reported an error receiving files.".format(tag))

        return sync_result


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
        client_files = get_files_status('client', get_md5=False)
        cluster_control_json = {'master_files': {}, 'client_files': client_files}

        # Getting client file paths: agent-info, agent-groups.
        client_files_paths = client_files.keys()

        logging.debug("{0} [Step 2]: Client files found: {1}".format(tag, len(client_files_paths)))

        if len(client_files_paths) != 0:
            # Compress data: client files + control json
            compressed_data_path = compress_files('client', self.name, client_files_paths, cluster_control_json)

            # Step 3
            # Send compressed file to master
            logging.info("{0} [Step 3]: Sending files to master.".format(tag))

            response = self.send_file(reason = 'sync_ai_c_m', file = compressed_data_path, remove = True)
            processed_response = self.process_response(response)
            if processed_response:
                sync_result = True
                logging.info("{0} [Step 3]: Master received the sync properly.".format(tag))
            else:
                logging.error("{0} [Step 3]: Master reported an error receiving files.".format(tag))
        else:
            sync_result = True
            logging.info("{0} [Step 3]: There are no agent-info files to send.".format(tag))

        return sync_result


    def process_files_from_master(self, data_received, tag=None):
        sync_result = False

        if not tag:
            tag = "[Client] [Sync process m->c]"

        logging.info("{0}: Start.".format(tag))

        # Extract received data
        logging.info("{0} [STEP 1]: Analyzing received files.".format(tag))

        try:
            ko_files, zip_path  = decompress_files(data_received)
        except Exception as e:
            logging.error("{}: Error decompressing files from master: {}".format(tag, str(e)))
            raise e

        if ko_files:
            logging.debug("{0}: Integrity: Missing: {1}. Shared: {2}. Extra: {3}.".format(tag, len(ko_files['missing']), len(ko_files['shared']), len(ko_files['extra'])))
            logging.debug("{0}: Received cluster_control.json: {1}".format(tag, ko_files))
        else:
            raise Exception("cluster_control.json not included in received zip file.")

        # Update files
        logging.info("{0} [STEP 2]: Updating client files.".format(tag))
        sync_result = ClientManagerHandler._update_master_files_in_client(ko_files, zip_path, tag)

        # remove temporal zip file directory
        shutil.rmtree(zip_path)

        # ToDo: Send ACK

        return sync_result



#
# Threads (workers) created by ClientManagerHandler
#
class ClientProcessMasterFiles(ProcessFiles):

    def __init__(self, manager_handler, filename, stopper):
        ProcessFiles.__init__(self, manager_handler, filename, manager_handler.name, stopper)
        self.thread_tag = "[Client] [ProcessFilesThread] [Sync process m->c]"
        self.status_type = "sync_agent"


    def check_connection(self):
        # if not self.manager_handler:
        #     self.sleep(2)
        #     return False

        if not self.manager_handler.is_connected():
            check_seconds = 2
            logging.info("{0}: Client is not connected. Waiting {1}s".format(self.thread_tag, check_seconds))
            self.sleep(check_seconds)
            return False

        return True


    def lock_status(self, status):
        # the client only needs to do the unlock
        # because the lock was performed in the Integrity thread
        if not status:
            self.manager_handler.set_lock_interval_thread(status)


    def process_file(self):
        return self.manager_handler.process_files_from_master(self.filename, self.thread_tag)

#
# Client
#
class ClientManager():
    SYNC_I_T = "Sync_I_Thread"
    SYNC_AI_T = "Sync_AI_Thread"
    KA_T = "KeepAlive_Thread"

    def __init__(self, cluster_config):
        self.handler = ClientManagerHandler(cluster_config=cluster_config)
        self.cluster_config = cluster_config

        # Threads
        self.stopper = threading.Event()
        self.threads = {}
        self._initiate_client_threads()

    # Private methods
    def _initiate_client_threads(self):
        logging.debug("[Master] Creating threads.")
        # Sync integrity
        self.threads[ClientManager.SYNC_I_T] = SyncIntegrityThread(client_handler=self.handler, stopper=self.stopper)
        self.threads[ClientManager.SYNC_I_T].start()

        # Sync AgentInfo
        self.threads[ClientManager.SYNC_AI_T] = SyncAgentInfoThread(client_handler=self.handler, stopper=self.stopper)
        self.threads[ClientManager.SYNC_AI_T].start()

        # KA
        self.threads[ClientManager.KA_T] = KeepAliveThread(client_handler=self.handler, stopper=self.stopper)
        self.threads[ClientManager.KA_T].start()

    # New methods
    def exit(self):
        logging.info("[Client] Cleaning...")

        # Cleaning client threads
        logging.debug("[Client] Cleaning main threads")
        self.stopper.set()

        for thread in self.threads:
            logging.debug("[Client] Cleaning main threads: '{0}'.".format(thread))
            self.threads[thread].join(timeout=5)
            if self.threads[thread].isAlive():
                logging.warning("[Client] Cleaning main threads. Timeout for: '{0}'.".format(thread))
            else:
                logging.debug("[Client] Cleaning main threads. Terminated: '{0}'.".format(thread))

        # Cleaning handler threads
        logging.debug("[Client] Cleaning handler threads.")
        self.handler.exit()

        logging.debug("[Client] Cleaning generated temporary files.")
        clean_up()

        logging.info("[Client] Cleaning end.")


#
# Client threads
#
class KeepAliveThread(ClusterThread):

    def __init__(self, client_handler, stopper):
        ClusterThread.__init__(self, stopper)
        self.client = client_handler
        self.thread_tag = "[Client] [KeepAliveThread] [Sync process c->m]"


    def run(self):

        while not self.stopper.is_set() and self.running:
            self.thread_tag = "[Client] [KeepAliveThread] [Sync process c->m]"

            # Waint until client is set
            if not self.client:
                #time.sleep(2)
                self.sleep(2)
                continue

            # Waint until client is connected
            if not self.client.is_connected():
                check_seconds = 2
                logging.info("{0}: Client is not connected. Waiting: {1}s.".format(self.thread_tag, check_seconds))
                #time.sleep(check_seconds)
                self.sleep(check_seconds)
                continue

            # Client set and connected
            try:
                result = self.client.send_request('echo-c', 'Keep-alive from client!')

                if result:
                    logging.info("{0}: KA: Successfully.".format(self.thread_tag))
                else:
                    logging.error("{0}: KA: Error.".format(self.thread_tag))
            except Exception as e:
                logging.error("{0}: KA Unknown Error: '{1}'.".format(self.thread_tag, str(e)))
                clean_up(self.client.name)

            logging.info("{0}: KA Sleeping: {1}s.".format(self.thread_tag, self.client.config['ka_interval']))
            #time.sleep(self.client.config['ka_interval'])
            self.sleep(self.client.config['ka_interval'])


class SyncIntegrityThread(ClusterThread):

    def __init__(self, client_handler, stopper):
        ClusterThread.__init__(self, stopper)
        self.client = client_handler
        self.thread_tag = "[Client] [SyncIntegrityThread [Sync process c->m]"


    def run(self):

        while not self.stopper.is_set() and self.running:

            # Waint until client is set
            if not self.client:
                # time.sleep(2)
                self.sleep(2)
                continue

            # Waint until client is connected
            if not self.client.is_connected():
                check_seconds = 2
                logging.info("{0}: Client is not connected. Waiting: {1}s.".format(self.thread_tag, check_seconds))
                #time.sleep(check_seconds)
                self.sleep(check_seconds)
                continue

            # Client set and connected
            try:
                new_interval = self.client.config['interval']

                wait_for_permission = True
                n_seconds = 0

                logging.info("{0}: Asking permission to sync integrity.".format(self.thread_tag))
                while wait_for_permission:
                    response = self.client.send_request('sync_i_c_m_p')
                    processed_response = self.client.process_response(response)

                    if processed_response:
                        if 'True' in processed_response:
                            wait_for_permission = False

                    time.sleep(1)
                    n_seconds += 1
                    if n_seconds != 0 and n_seconds % 5 == 0:
                        logging.info("{0}: Waiting for Master permission to sync integrity.".format(self.thread_tag))

                logging.info("{0}: Permission granted.".format(self.thread_tag))

                # Send files
                self.client.set_lock_interval_thread(True)
                result = self.client.send_integrity_to_master(reason="Interval", tag=self.thread_tag)

                # Master received the file properly
                if result:
                    logging.info("{0}: Result: Successfully.".format(self.thread_tag))

                    # Lock until:
                    #  - Master sends files: sync_m_c
                    #  - Master sends error: sync_m_c_err
                    #  - Client is disconnected and connected again
                    logging.info("{0}: Locking: Wait for master files.".format(self.thread_tag))

                    n_seconds = 0
                    while self.client.get_lock_interval_thread():
                        # Print each 5 seconds
                        if n_seconds != 0 and n_seconds % 5 == 0:
                            logging.info("{0}: Master didnt send the files in the last 5 seconds.".format(self.thread_tag))

                        time.sleep(1)
                        n_seconds += 1
                        if self.stopper.is_set() or not self.running:
                            break  # it doesnt go to the else
                    else:
                        logging.info("{0}: Unlocked: Master files processed or error from master.".format(self.thread_tag))
                        new_interval = max(0, self.client.config['interval'] - n_seconds)

                # Master reported an error receiving files
                else:
                    logging.info("{0}: Unlocked: Master reported an error receiving files.".format(self.thread_tag))
                    self.client.set_lock_interval_thread(False)

                    logging.error("{0}: Result: Error.".format(self.thread_tag))
            except Exception as e:
                logging.error("{0}: Unknown Error: '{1}'.".format(self.thread_tag, str(e)))
                clean_up(self.client.name)

            logging.info("{0}: Sleeping: {1}s.".format(self.thread_tag, new_interval))
            #time.sleep(new_interval)
            self.sleep(new_interval)


class SyncAgentInfoThread(ClusterThread):

    def __init__(self, client_handler, stopper):
        ClusterThread.__init__(self, stopper)
        self.client = client_handler
        self.thread_tag = "[Client] [SyncAgentInfoThread] [Sync process c->m]"


    def run(self):

        while not self.stopper.is_set() and self.running:

            # Waint until client is set
            if not self.client:
                # time.sleep(2)
                self.sleep(2)
                continue

            # Waint until client is connected
            if not self.client.is_connected():
                check_seconds = 2
                logging.info("{0}: Client is not connected. Waiting: {1}s.".format(self.thread_tag, check_seconds))
                #time.sleep(check_seconds)
                self.sleep(check_seconds)
                continue

            # Client set and connected
            try:
                new_interval = self.client.config['interval']

                wait_for_permission = True
                n_seconds = 0

                logging.info("{0}: Asking permission to sync agentinfo.".format(self.thread_tag))
                while wait_for_permission:
                    response = self.client.send_request('sync_ai_c_mp')
                    processed_response = self.client.process_response(response)

                    if processed_response:
                        if 'True' in processed_response:
                            wait_for_permission = False

                    time.sleep(1)
                    n_seconds += 1
                    if n_seconds != 0 and n_seconds % 5 == 0:
                        logging.info("{0}: Waiting for Master permission to sync agentinfo.".format(self.thread_tag))

                logging.info("{0}: Permission granted.".format(self.thread_tag))

                # Send files
                result = self.client.send_client_files_to_master(reason="Interval", tag=self.thread_tag)

                # Master received the file properly
                if result:
                    logging.info("{0}: Result: Successfully.".format(self.thread_tag))
                # Master reported an error receiving files
                else:
                    logging.error("{0}: Result: Error.".format(self.thread_tag))
            except Exception as e:
                logging.error("{0}: Unknown Error: '{1}'.".format(self.thread_tag, str(e)))
                clean_up(self.client.name)

            logging.info("{0}: Sleeping: {1}s.".format(self.thread_tag, new_interval))
            #time.sleep(new_interval)
            self.sleep(new_interval)

#
# Internal socket
#
class ClientInternalSocketHandler(InternalSocketHandler):
    def __init__(self, sock, manager, map):
        InternalSocketHandler.__init__(self, sock=sock, manager=manager, map=map)

    def process_request(self, command, data):
        logging.debug("[Transport-I] Forwarding request to cluster clients '{0}' - '{1}'".format(command, data))
        serialized_response = ""


        if command == "get_files":
            split_data = data.split(' ', 1)
            file_list = ast.literal_eval(split_data[0]) if split_data[0] else None
            node_response = self.manager.handler.process_request(command = 'file_status', data="")

            if node_response[0] == 'err': # Error response
                response = {"err":node_response[1]}
            else:
                response = json.loads(node_response[1])
                # Filter files
                if file_list and len(response):
                    response = {file:content for file,content in response.iteritems() if file in file_list}

            response =  json.dumps(response)

            serialized_response = ['ok', response]

            return serialized_response
        elif command == "get_nodes":
            split_data = data.split(' ', 1)
            node_list = ast.literal_eval(split_data[0]) if split_data[0] else None

            node_response = self.manager.handler.send_request(command=command, data=data).split(' ', 1)

            type_response = node_response[0]
            response = node_response[1]

            if type_response == "err":
                response = {"err":response}
            else:
                response = json.loads(response)
                if node_list:
                    response = {node:info for node, info in response.iteritems() if node in node_list}

            serialized_response = ['ok', json.dumps(response)]
            return serialized_response
        else:
            response = self.manager.send_request(command=command, data=data)
            if response:
                serialized_response = response.split(' ', 1)

        return serialized_response
