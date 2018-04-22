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

from wazuh.cluster.cluster import get_cluster_items, _update_file, get_files_status, compress_files, decompress_files, get_files_status
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
        ClientHandler.__init__(self, cluster_config['key'], cluster_config['nodes'][0], cluster_config['port'], cluster_config['node_name'])

        self.config = cluster_config
        self.integrity_received_and_processed = threading.Event()
        self.integrity_received_and_processed.clear()  # False

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
            logging.info("[Client] The master has verified that the integrity is right. Unlocking SyncIntegrityThread.")
            self.integrity_received_and_processed.set()
            return 'ack', "Thanks2!"
        elif command == 'sync_m_c_err':
            logging.info("[Client] The master was not able to verify the integrity. Unlocking SyncIntegrityThread.")
            self.integrity_received_and_processed.set()
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


    def process_response(self, response):
        # FixMe: Move this line to communications
        answer, payload = self.split_data(response)

        logging.debug("[Client] Response received: '{0}'.".format(answer))

        response_data = None

        if answer == 'ok-c':  # test
            response_data = '[response_only_for_client] Master answered: {}.'.format(payload)
        else:
            response_data = ClientHandler.process_response(self, response)

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

            _update_file(dst_path=file_path, new_content=file_data,
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
    def send_integrity_to_master(self, reason=None, tag=None):
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

        return compressed_data_path


    def send_client_files_to_master(self, reason=None, tag=None):
        data_for_master = None

        if not tag:
            tag = "[Client] [Sync process c->m]"

        logging.info("{0}: Start. Reason: '{1}'".format(tag, reason))

        # Step 1
        logging.info("{0} [Step 1]: Finding master.".format(tag))

        master_node = self.config['nodes'][0]  # Now, we only have 1 node: the master

        logging.info("{0} [Step 1]: Master: {1}.".format(tag, master_node))


        # Step 2
        logging.info("{0} [Step 2]: Gathering files.".format(tag))


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

            data_for_master = compressed_data_path

        else:
            logging.info("{0} [Step 3]: There are no agent-info files to send.".format(tag))

        return data_for_master


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
            self.manager_handler.integrity_received_and_processed.set()


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
            try:
                self.threads[thread].join(timeout=2)
            except Exception as e:
                logging.error("[Client] Cleaning main threads. Error for: '{0}' - '{1}'.".format(thread, str(e)))

            if self.threads[thread].isAlive():
                logging.warning("[Client] Cleaning main threads. Timeout for: '{0}'.".format(thread))
            else:
                logging.debug("[Client] Cleaning main threads. Terminated: '{0}'.".format(thread))

        # Cleaning handler threads
        logging.debug("[Client] Cleaning handler threads.")
        self.handler.exit()


        logging.info("[Client] Cleaning end.")


#
# Client threads
#
class ClientThread(ClusterThread):

    def __init__(self, client_handler, stopper):
        ClusterThread.__init__(self, stopper)
        self.client_handler = client_handler
        self.interval = self.client_handler.config['interval']


    def run(self):

        while not self.stopper.is_set() and self.running:

            # Waint until client is set
            if not self.client_handler:
                # time.sleep(2)
                self.sleep(2)
                continue

            # Waint until client is connected
            if not self.client_handler.is_connected():
                check_seconds = 2
                logging.info("{0}: Client is not connected. Waiting: {1}s.".format(self.thread_tag, check_seconds))
                #time.sleep(check_seconds)
                self.sleep(check_seconds)
                continue

            try:
                self.interval = self.client_handler.config['interval']

                self.ask_for_permission()

                result = self.job()

                if result:
                    logging.info("{0}: Result: Successfully.".format(self.thread_tag))
                    self.process_result()
                else:
                    logging.error("{0}: Result: Error".format(self.thread_tag))
                    self.clean()
            except Exception as e:
                logging.error("{0}: Unknown Error: '{1}'.".format(self.thread_tag, str(e)))
                self.clean()

            logging.info("{0}: Sleeping: {1}s.".format(self.thread_tag, self.interval))
            self.sleep(self.interval)


    def ask_for_permission(self):
        raise NotImplementedError


    def clean(self):
        raise NotImplementedError


    def job(self):
        raise NotImplementedError


    def process_result(self):
        raise NotImplementedError


class KeepAliveThread(ClientThread):

    def __init__(self, client_handler, stopper):
        ClientThread.__init__(self, client_handler, stopper)
        self.thread_tag = "[Client] [KeepAliveThread]"


    def ask_for_permission(self):
        pass


    def clean(self):
        pass


    def job(self):
        return self.client_handler.send_request('echo-c', 'Keep-alive from client!')


    def process_result(self):
        pass


class SyncClientThread(ClientThread):
    def __init__(self, client_handler, stopper):
        ClientThread.__init__(self, client_handler, stopper)


    def ask_for_permission(self):
        wait_for_permission = True
        n_seconds = 0

        logging.info("{0}: Asking permission to sync.".format(self.thread_tag))
        waiting_count = 0
        while wait_for_permission and not self.stopper.is_set() and self.running:
            response = self.client_handler.send_request(self.request_type)
            processed_response = self.client_handler.process_response(response)

            if processed_response:
                if 'True' in processed_response:
                    logging.info("{0}: Permission granted.".format(self.thread_tag))
                    wait_for_permission = False

            sleeped = self.sleep(5)
            n_seconds += sleeped
            if n_seconds >= 5 and n_seconds % 5 == 0:
                waiting_count += 1
                logging.info("{0}: Waiting for Master permission to sync [{1}].".format(self.thread_tag, waiting_count))


    def clean(self):
        pass


    def job(self):
        sync_result = True
        compressed_data_path = self.function(reason="Interval", tag=self.thread_tag)
        if compressed_data_path:
            response = self.client_handler.send_file(reason = self.reason, file = compressed_data_path, remove = True)
            processed_response = self.client_handler.process_response(response)
            if processed_response:
                logging.info("{0} [Step 3]: Master received the sync properly.".format(self.thread_tag))
            else:
                sync_result = False
                logging.error("{0} [Step 3]: Master reported an error receiving files.".format(self.thread_tag))
        return sync_result


    def process_result(self):
        pass


class SyncIntegrityThread(SyncClientThread):

    def __init__(self, client_handler, stopper):
        SyncClientThread.__init__(self, client_handler, stopper)
        self.request_type = "sync_i_c_m_p"
        self.reason = "sync_i_c_m"
        self.function = self.client_handler.send_integrity_to_master
        self.thread_tag = "[Client] [SyncIntegrityThread]"


    def job(self):
        # The client is going to send the integrity, so it is not received and processed
        self.client_handler.integrity_received_and_processed.clear()
        return SyncClientThread.job(self)


    def process_result(self):
        # The client sent the integrity.
        # It must wait until integrity_received_and_processed is set:
        #  - Master sends files: sync_m_c AND the client processes the integrity.
        #  - Master sends error: sync_m_c_err
        #  - Master sends error: sync_m_c_ok
        #  - Thread is stopped (all threads - stopper, just this thread - running)
        #  - Client is disconnected and connected again
        logging.info("{0}: Locking: Waiting for receiving Master response and process the integrity if necessary.".format(self.thread_tag))

        n_seconds = 0
        while not self.client_handler.integrity_received_and_processed.isSet() and not self.stopper.is_set() and self.running:
            event_is_set = self.client_handler.integrity_received_and_processed.wait(1)
            n_seconds += 1

            if event_is_set:  # No timeout -> Free
                logging.info("{0}: Unlocking: Master sent the response and the integrity was processed if necessary.".format(self.thread_tag))
                self.interval = max(0, self.client_handler.config['interval'] - n_seconds)
            else:  # Timeout
                # Print each 5 seconds
                if n_seconds != 0 and n_seconds % 5 == 0:
                    logging.info("{0}: Master did not send the integrity in the last 5 seconds. Waiting.".format(self.thread_tag))


    def clean(self):
        SyncClientThread.clean(self)
        self.client_handler.integrity_received_and_processed.clear()


class SyncAgentInfoThread(SyncClientThread):

    def __init__(self, client_handler, stopper):
        SyncClientThread.__init__(self, client_handler, stopper)
        self.thread_tag = "[Client] [SyncAgentInfoThread]"
        self.request_type = "sync_ai_c_mp"
        self.reason = "sync_ai_c_m"
        self.function = self.client_handler.send_client_files_to_master


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
        elif command == "get_health":
            response = self.manager.handler.send_request(command=command, data=data).split(' ', 1)[1]
            serialized_response = ['ok',  response]
            return serialized_response
        else:
            response = self.manager.send_request(command=command, data=data)
            if response:
                serialized_response = response.split(' ', 1)

        return serialized_response
