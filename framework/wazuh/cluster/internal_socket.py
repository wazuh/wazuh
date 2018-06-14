#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.cluster import communication
from wazuh import common
from wazuh.exception import WazuhException
from wazuh.cluster.cluster import read_config, check_cluster_config, get_status_json
import socket
import random
import json
import threading
import time
import os
import logging
import asyncore

logger = logging.getLogger(__name__)

class InternalSocketHandler(communication.ServerHandler):

    def __init__(self, sock, server, asyncore_map, addr):
        communication.ServerHandler.__init__(self, server=server, sock=sock, asyncore_map=asyncore_map, addr=addr)


    def process_request(self, command, data):
        if command == 'hello':
            self.name = self.server.add_client(data, '', self)
            return None
        else:
            return ['err', json.dumps({'err', "Received an unknown command '{}'".format(command)})]


class InternalSocket(communication.AbstractServer):

    def __init__(self, socket_name, manager, handle_type, asyncore_map = {}):
        self.socket_addr = "{}{}/{}.sock".format(common.ossec_path, "/queue/cluster", socket_name)

        communication.AbstractServer.__init__(self, addr=self.socket_addr, handle_type=handle_type, asyncore_map=asyncore_map,
                                              socket_family=socket.AF_UNIX, socket_type=socket.SOCK_STREAM,
                                              tag="[Transport-InternalSocket]")
        self.manager = manager
        self.config = {'key': None}


    def create_socket(self, family=socket.AF_UNIX, type=socket.SOCK_STREAM):
        logger.debug2("{0} Creating.".format(self.tag))

        # Make sure the socket does not already exist
        try:
            os.unlink(self.socket_addr)
        except OSError:
            if os.path.exists(self.socket_addr):
                logger.error("{} Error: '{}' already exits".format(self.tag, self.socket_addr))
                raise

        communication.AbstractServer.create_socket(self, family, type)


    def add_client(self, data, ip, handler):
        with self._clients_lock:
            self._clients[data] = {'handler': handler}

        return data


    def find_client_by_ip(self, client_ip):
        return None


#
# Internal Socket thread
#
class InternalSocketThread(threading.Thread):
    def __init__(self, socket_name, tag="[InternalSocketThread]"):
        threading.Thread.__init__(self)
        self.daemon = True
        self.manager = None
        self.running = True
        self.internal_socket = None
        self.socket_name = socket_name
        self.thread_tag = tag
        self.interval_connection_retry = 5

    def setmanager(self, manager, handle_type):
        try:
            self.internal_socket = InternalSocket(socket_name=self.socket_name, manager=manager, handle_type=handle_type)
        except Exception as e:
            logger.error("{0} [Internal-COM ]: Error initializing: '{1}'.".format(self.thread_tag, e))
            self.internal_socket = None


    def run(self):
        while self.running:
            if self.internal_socket:
                logger.info("{0} [Internal-COM ]: Ready.".format(self.thread_tag))

                asyncore.loop(timeout=1, use_poll=False, map=self.internal_socket.map, count=None)

                logger.info("{0} [Internal-COM ]: Disconnected. Trying to connect again in {1}s.".format(self.thread_tag, self.interval_connection_retry))

                time.sleep(self.interval_connection_retry)
            time.sleep(2)


class InternalSocketClient(communication.AbstractClient):

    def __init__(self, socket_name, asyncore_map = {}):
        self.socket_addr = "{}{}/{}.sock".format(common.ossec_path, "/queue/cluster", socket_name)
        connect_query = str(random.randint(0, 2 ** 32 - 1))
        logger.debug("[InternalSocketClient] Client ID: {}".format(connect_query))
        communication.AbstractClient.__init__(self, None, self.socket_addr, connect_query, socket.AF_UNIX, socket.SOCK_STREAM,
                                              connect_query, "[InternalSocket-Client] [{}]".format(connect_query), asyncore_map)
        self.final_response = communication.Response()


    def send_request(self, command, data=None):
        if data:
            data = "{} {}".format(self.name, data)

        return communication.AbstractClient.send_request(self, command, data)


    def process_response(self, response):
        command, data = response

        if command == 'ok' or command == 'ack':
            return False
        if command == 'json':
            self.final_response.write(data)
            return False
        elif command == 'err':
            self.final_response.write(data)
            return True


    def process_request(self, command, data):
        if command == 'dapi_res':
            string_receiver = FragmentedAPIResponseReceiver(manager_handler=self, stopper=self.stopper)
            string_receiver.start()
            return 'ack', self.set_worker(command, string_receiver)
        else:
            return communication.AbstractClient.process_request(self, command, data)


class FragmentedAPIResponseReceiver(communication.FragmentedStringReceiverClient):

    def __init__(self, manager_handler, stopper):
        communication.FragmentedStringReceiverClient.__init__(self, manager_handler, stopper)
        self.thread_tag = "[APIResponseReceiver]"


    def process_received_data(self):
        self.manager_handler.final_response.write(self.sting_received)
        return True


class InternalSocketClientThread(communication.ClusterThread):

    def __init__(self, socket_name, stopper = threading.Event()):
        communication.ClusterThread.__init__(self, stopper)
        self.manager = InternalSocketClient(socket_name)


    def run(self):
        while not self.stopper.is_set() and self.running:

            asyncore.loop(map = self.manager.map)


def check_cluster_status():
    # Get cluster config
    cluster_config = read_config()

    if not cluster_config or cluster_config['disabled'] == 'yes':
        raise WazuhException(3013)

    # Validate cluster config
    check_cluster_config(cluster_config)

    status = get_status_json()
    if status["running"] != "yes":
        raise WazuhException(3012)


def execute(request):
    socket_name = "c-internal"
    try:
        # if no exception is raised from function check_cluster_status, the cluster is ok.
        check_cluster_status()

        isocket_client_thread = InternalSocketClientThread(socket_name=socket_name)
        isocket_client_thread.start()
        command, payload = request.split(' ',1)
        is_error = isocket_client_thread.manager.process_response(isocket_client_thread.manager.send_request(command = command, data = payload).split(' ',1))
        response = isocket_client_thread.manager.final_response.read()
        isocket_client_thread.manager.handle_close()
        isocket_client_thread.stop()
        response = json.loads(response) if not is_error else response
        return response
    except WazuhException as e:
        raise e
    except Exception as e:
        raise WazuhException(3009, str(e))