#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import threading
import time

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


from wazuh.cluster.communication import Server, ServerHandler, Handler


class MasterManagerHandler(ServerHandler):

    def __init__(self, sock, server, map):
        ServerHandler.__init__(self, sock, server, map)

    def process_request(self, command, data):
        logging.debug("[Master] Request received: '{0}'.".format(command))

        if command == 'echo-c':
            return 'ok-c ', data.decode()
        elif command == 'req_sync_m_c':
            return 'ack', 'Starting sync from master'
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


class MasterManager(Server):

    def __init__(self, cluster_config):
        Server.__init__(self, cluster_config['bind_addr'],
            cluster_config['port'], MasterManagerHandler)

        logging.info("[Master] Listening.")

        self.config = cluster_config
        self.handler = MasterManagerHandler


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
