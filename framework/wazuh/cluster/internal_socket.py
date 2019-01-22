#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.cluster import communication
from wazuh import common
from wazuh.exception import WazuhException
from wazuh.cluster.cluster import read_config, check_cluster_config, get_status_json, \
    get_cluster_items_communication_intervals
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
        communication.ServerHandler.__init__(self, server=server, sock=sock, asyncore_map=asyncore_map, addr=addr,
                                             tag="[Cluster] [LocalServer  ]")


    def process_request(self, command, data):
        if command == 'hello':
            self.name = self.server.add_worker(data, '', self)
            logger.info("{} [{}]: Connected.".format(self.tag, self.name))
            return None
        else:
            return 'err',"Received an unknown command '{}'".format(command)


class InternalSocket(communication.AbstractServer):

    def __init__(self, socket_name, manager, handle_type, asyncore_map = {}):
        self.socket_addr = "{}{}/{}.sock".format(common.ossec_path, "/queue/cluster", socket_name)

        communication.AbstractServer.__init__(self, addr=self.socket_addr, handle_type=handle_type,
                                              asyncore_map=asyncore_map, socket_family=socket.AF_UNIX,
                                              socket_type=socket.SOCK_STREAM, tag="[Cluster] [LocalServer  ]")
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


    def add_worker(self, data, ip, handler):
        with self._workers_lock:
            self._workers[data] = {'handler': handler}

        return data


    def find_worker_by_ip(self, worker_ip):
        return None


#
# Internal Socket thread
#
class InternalSocketThread(threading.Thread):
    def __init__(self, socket_name, tag="[LocalServer]"):
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
            logger.error("{0} [LocalServer  ]: Error initializing: '{1}'.".format(self.thread_tag, e))
            self.internal_socket = None


    def run(self):
        while self.running:
            if self.internal_socket:
                logger.info("{0} [LocalServer  ]: Ready.".format(self.thread_tag))

                asyncore.loop(timeout=1, use_poll=False, map=self.internal_socket.map, count=None)

                logger.info("{0} [LocalServer  ]: Disconnected. Trying to connect again in {1}s.".format(self.thread_tag, self.interval_connection_retry))

                time.sleep(self.interval_connection_retry)
            time.sleep(2)


class InternalSocketClient(communication.AbstractClient):

    def __init__(self, socket_name, data_received, asyncore_map = {}):
        self.socket_addr = "{}{}/{}.sock".format(common.ossec_path, "/queue/cluster", socket_name)
        connect_query = str(random.SystemRandom().randint(0, 2 ** 32 - 1))
        self.c_is_id = connect_query
        logger.debug("[ClusterClient] Worker ID: {}".format(connect_query))
        communication.AbstractClient.__init__(self, None, self.socket_addr, self.c_is_id, socket.AF_UNIX, socket.SOCK_STREAM,
                                              connect_query, "[ClusterClient] [{}]".format(connect_query), asyncore_map)

        self.final_data = None
        self.data_received = data_received


    def send_request(self, command, data=None):
        before = time.time()
        if data:
            data = "{} {}".format(self.name, data)

        res = communication.AbstractClient.send_request(self, command, data)
        after = time.time()
        logger.debug("{} Time sending request to internal socket server: {}s".format(self.tag, after - before))
        return res


    def process_response(self, response):
        command, data = response

        if command == 'ok' or command == 'ack':
            return False
        if command == 'json':
            self.final_data = data
            self.data_received.set()
            return True
        elif command == 'err':
            self.final_data = data
            self.data_received.set()
            return True


    def process_request(self, command, data):

        if command == 'dapi_res':
            self.string_receiver = FragmentedAPIResponseReceiver(manager_handler=self, stopper=self.stopper)
            self.string_receiver.start()
            return 'ok', self.set_worker_thread(command, self.string_receiver)
        elif command == 'err-is':
            data = data.decode()
            self.final_data = json.dumps({"error":1000, "message":data})
            self.data_received.set()
            return 'ack','thanks'
        else:
            return communication.AbstractClient.process_request(self, command, data)


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        try:
            self_repr = repr(self)
        except:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        logger.error("{} Error: '{}'.".format(self.tag, v))
        logger.debug("{} Error: '{}' - '{}'.".format(self.tag, t, tbinfo))



class FragmentedAPIResponseReceiver(communication.FragmentedStringReceiverWorker):

    def __init__(self, manager_handler, stopper):
        communication.FragmentedStringReceiverWorker.__init__(self, manager_handler, stopper)
        self.thread_tag = "[Cluster] [API-R_{}]".format(self.manager_handler.c_is_id)


    def process_received_data(self):
        logger.debug("{}: Data received.".format(self.thread_tag))
        self.manager_handler.final_data = self.sting_received
        self.manager_handler.data_received.set()
        return True


    def unlock_and_stop(self, reason, send_err_request=None):
        if reason=='error':
            self.final_data = json.dumps({"message": send_err_request, "error": 1000})
            self.data_received.set()

        communication.FragmentedStringReceiverWorker.unlock_and_stop(self,reason,None)


class InternalSocketWorkerThread(communication.ClusterThread):

    def __init__(self, socket_name, data_received, stopper = threading.Event()):
        communication.ClusterThread.__init__(self, stopper)
        asyncore_map = {}
        self.manager = InternalSocketClient(socket_name=socket_name, asyncore_map=asyncore_map, data_received=data_received)


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


def execute(request, disable_timeout=False):
    socket_name = "c-internal"
    try:
        # if no exception is raised from function check_cluster_status, the cluster is ok.
        check_cluster_status()

        # This event will be set when the final response is received
        data_received = threading.Event()

        # Create socket client
        isocket_worker_thread = InternalSocketWorkerThread(socket_name=socket_name, data_received=data_received)
        isocket_worker_thread.start()

        # Send request
        command, payload = request.split(' ',1)
        raw_response = isocket_worker_thread.manager.send_request(command = command, data = payload).split(' ',1)
        isocket_worker_thread.manager.process_response(raw_response)

        # Wait response
        #  Data received will be free when dapi_forward request is received, or when a json/err response is processed.
        logger.debug("Waiting response.")
        timeout_not_expired = data_received.wait(None if disable_timeout else
                                                 get_cluster_items_communication_intervals()['timeout_api_request'])

        if timeout_not_expired:
            response = json.loads(isocket_worker_thread.manager.final_data)
        else:
            response = {"error":1000, "message":"Timeout waiting local server."}

        # Stop socket client
        isocket_worker_thread.stop()

        return response
    except WazuhException as e:
        raise e
    except Exception as e:
        raise WazuhException(3009, str(e))
