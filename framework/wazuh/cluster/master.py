#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import threading
import time
import shutil
import json

from wazuh.exception import WazuhException
from wazuh import common
from wazuh.cluster.cluster import get_cluster_items, _update_file, decompress_files, get_files_status, compress_files, compare_files, get_agents_status
from wazuh.cluster.communication import ProcessFiles, Server, ServerHandler, Handler, InternalSocketHandler
import ast

class MasterManagerHandler(ServerHandler):

    def __init__(self, sock, server, map, addr=None):
        ServerHandler.__init__(self, sock, server, map, addr)
        self.manager = server


    def process_request(self, command, data):
        logging.debug("[Master] Request received: '{0}'.".format(command))

        if command == 'echo-c':
            return 'ok-c ', data.decode()
        elif command == 'req_sync_m_c':
            return 'ack', 'Starting sync from master'
        elif command == 'sync_c_m':
            mcf_thread = MasterProcessClientFiles(self, self.get_client(), data)
            mcf_thread.start()
            # data will contain the filename
            return 'ack', self.set_worker(command, mcf_thread, data)
        else:
            return ServerHandler.process_request(self, command, data)

    @staticmethod
    def process_response(response):
        # FixMe: Move this line to communications
        answer, payload = Handler.split_data(response)

        logging.debug("[Master] Response received: '{0}'.".format(answer))

        response_data = None

        if answer == 'ok-m':  # test
            response_data = '[response_only_for_master] Client answered: {}.'.format(payload)
        else:
            response_data = ServerHandler.process_response(response)

        return response_data


    def update_client_files_in_master(self, json_file, files_to_update_json, zip_dir_path):
        cluster_items = get_cluster_items()

        try:

            for file_name, data in json_file.items():
                # Full path
                file_path = common.ossec_path + file_name
                zip_path  = "{}/{}".format(zip_dir_path, file_name.replace('/','_'))

                # Cluster items information: write mode and umask
                cluster_item_key = data['cluster_item_key']
                w_mode = cluster_items[cluster_item_key]['write_mode']
                umask = int(cluster_items[cluster_item_key]['umask'], base=0)

                # File content and time
                with open(zip_path, 'rb') as f:
                    file_data = f.read()
                file_time = files_to_update_json[file_name]['mod_time']

                with self.lock:
                    _update_file(fullpath=file_path, new_content=file_data,
                                 umask_int=umask, mtime=file_time, w_mode=w_mode,
                                 whoami='master')

        except Exception as e:
            print(str(e))
            raise e


    def process_files_from_client(self, client_name, data_received, tag=None):
        sync_result = False

        if not tag:
            tag = "[Master] [Sync process m->c]"

        logging.info("{0} [{1}]: Start.".format(tag, client_name))

        json_file, zip_dir_path = decompress_files(data_received)
        if json_file:
            logging.debug("{0}: Received cluster_control.json".format(tag))
            master_files_from_client = json_file['master_files']
            client_files_json = json_file['client_files']
        else:
            raise Exception("cluster_control.json not included in received zip file")
        # Extract recevied data
        logging.info("{0} [{1}] [STEP 1]: Analyzing received files.".format(tag, client_name))

        logging.debug("{0} Received {1} client files to update".format(tag, len(client_files_json)))
        logging.debug("{0} Received {1} master files to check".format(tag, len(master_files_from_client)))

        # Get master files
        master_files = get_files_status('master')

        # Compare
        client_files_ko = compare_files(master_files, master_files_from_client)

        logging.info("{0} [{1}] [STEP 2]: Updating manager files.".format(tag, client_name))

        # Update files
        self.update_client_files_in_master(client_files_json, client_files_json, zip_dir_path)

        # Remove tmp directory created when zip file was received
        shutil.rmtree(zip_dir_path)

        # Compress data: master files (only KO shared and missing)
        logging.info("{0} [{1}] [STEP 3]: Compressing KO files for client.".format(tag, client_name))

        master_files_paths = [item for item in client_files_ko['shared']]
        master_files_paths.extend([item for item in client_files_ko['missing']])

        compressed_data = compress_files('master', client_name, master_files_paths, client_files_ko)

        logging.info("{0} [{1}] [STEP 3]: Sending KO files to client.".format(tag, client_name))

        response = self.manager.send_file(client_name, 'sync_m_c', compressed_data, True)
        processed_response = self.process_response(response)
        if processed_response:
            sync_result = True
            logging.info("{0} [{1}] [STEP 3]: Client received the sync properly".format(tag, client_name))
        else:
            logging.error("{0} [{1}] [STEP 3]: Client reported an error receiving files.".format(tag, client_name))

        # Send KO files
        return sync_result



class MasterManager(Server):

    def __init__(self, cluster_config):
        Server.__init__(self, cluster_config['bind_addr'],
            cluster_config['port'], MasterManagerHandler)

        logging.info("[Master] Listening.")

        self.config = cluster_config
        self.handler = MasterManagerHandler

    def req_file_status_to_clients(self):
        responses = list(self.send_request_broadcast(command = 'file_status'))
        nodes_file = {node:json.loads(data.split(' ',1)[1]) for node,data in responses}
        return 'ok', json.dumps(nodes_file)

#
# Master threads
#
class MasterKeepAliveThread(threading.Thread):

    def __init__(self, manager):
        threading.Thread.__init__(self)
        self.daemon = True
        self.running = True
        self.manager = manager


    def run(self):

        while self.running:
            connected_clients = len(self.manager.get_connected_clients())

            if connected_clients > 0:
                logging.debug("[Master] Sending KA to clients ({0}).".format(connected_clients))

                for client_name, response in self.manager.send_request_broadcast('echo-m', 'Keep-alive from master!'):
                    processed_response = self.manager.handler.process_response(response)
                    if processed_response:
                        logging.debug("[Master] KA received from client: '{0}'.".format(client_name))
                    else:
                        logging.error("[Master] KA was not received from client: '{0}'.".format(client_name))

            time.sleep(self.manager.config['ka_interval'])

    def stop(self):
        self.running = False


class MasterProcessClientFiles(ProcessFiles):

    def __init__(self, manager_handler, client_name, filename):
        ProcessFiles.__init__(self, manager_handler, filename, common.ossec_path)
        self.client_name = client_name
        self.thread_tag = "[Master] [ProcessFilesThread] [Sync process m->c]"

    def run(self):
        while self.running:
            if self.received_all_information:

                try:
                    result = self.manager_handler.process_files_from_client(self.client_name, self.filename, self.thread_tag)
                    if result:
                        logging.info("{0}: Result: Successfully.".format(self.thread_tag))
                    else:
                        logging.error("{0}: Result: Error.".format(self.thread_tag))
                except:
                    logging.error("{0}: Unknown error for {1}.".format(self.thread_tag, self.client_name))

                    self.manager_handler.manager.send_request(self.client_name, 'sync_m_c_err')

                self.stop()

            else:
                self.process_file_cmd()

            time.sleep(0.1)


#
# Internal socket
#

class MasterInternalSocketHandler(InternalSocketHandler):
    def __init__(self, sock, manager, map):
        InternalSocketHandler.__init__(self, sock=sock, manager=manager, map=map)

    def process_request(self, command, data):
        logging.debug("[Transport-I] Forwarding request to master of cluster '{0}' - '{1}'".format(command, data))
        serialized_response = ""

        if command == 'req_file_s_c':
            split_data = data.split(' ', 2)
            file_list = ast.literal_eval(split_data[0]) if split_data[0] else None
            node_list = ast.literal_eval(split_data[1]) if split_data[1] else None
            response = json.loads(self.manager.req_file_status_to_clients()[1])

            if node_list and len(response):
                response = {node: response.get(node) for node in node_list}
            if file_list and len(response):
                response = {node:{f_name:f_content for f_name,f_content in files.iteritems() if f_name in file_list} for node,files in response.iteritems()}

            serialized_response = ['ok',  json.dumps(response)]
            return serialized_response

        elif command == 'get_nodes':
            response = {name:data['info'] for name,data in self.manager.get_connected_clients().iteritems()}
            if data: # filter a node
                response = {data:response.get(data)} if response.get(data) else {data:"{} doesn't exist".format(data)}
            serialized_response = ['ok',  json.dumps(response)]
            return serialized_response

        elif command == 'get_agents':
            response = get_agents_status()
            serialized_response = ['ok',  json.dumps(response)]
            return serialized_response

        else:
            split_data = data.split(' ', 1)
            host = split_data[0]
            data = split_data[1] if len(split_data) > 1 else None

            if host == 'all':
                response = list(self.manager.send_request_broadcast(command=command, data=data))
                serialized_response = ['ok', json.dumps({node:data for node,data in response})]
            else:
                response = self.manager.send_request(client_name=host, command=command, data=data)
                if response:
                    serialized_response = response.split(' ', 1)

            return serialized_response
