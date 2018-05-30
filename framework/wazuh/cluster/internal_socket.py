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
            return ['ack', self.server.add_client()]
        else:
            return ['err', json.dumps({'err', "Received an unknown command '{}'".format(command)})]


class InternalSocket(communication.AbstractServer):

    def __init__(self, socket_name, manager, handle_type, asyncore_map = {}):
        self.socket_addr = "{}{}/{}.sock".format(common.ossec_path, "/queue/cluster", socket_name)

        communication.AbstractServer.__init__(self, addr=self.socket_addr, handle_type=handle_type, asyncore_map=asyncore_map,
                                              socket_type=socket.AF_UNIX, socket_family=socket.SOCK_STREAM,
                                              tag="[Transport-InternalSocket]")
        self.manager = manager
        self.config = {'key': None}


    def create_socket(self, socket_type, socket_family):
        logger.debug2("[Transport-InternalSocket] Creating.")

        # Make sure the socket does not already exist
        try:
            os.unlink(self.socket_addr)
        except OSError:
            if os.path.exists(self.socket_addr):
                logger.error("[Transport-InternalSocket] Error: '{}' already exits".format(self.socket_addr))
                raise

        communication.AbstractServer.create_socket(self, socket_type, socket_family)


    def add_client(self, data, ip, handler):
        node_id = random.randint(0, 2 ** 32 -1)
        with self._clients_lock:
            self._clients[node_id] = handler

        return node_id


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


def send_to_internal_socket(socket_name, message):
    # Create a UDS socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_address = "{}/{}/{}.sock".format(common.ossec_path, "/queue/cluster", socket_name)
    logger.debug("[Transport-InternalSocketSend] Starting: {}.".format(socket_address))
    response = b""

    # Connect to UDS socket
    try:
        sock.connect(socket_address)
    except Exception as e:
        logger.error('[Transport-InternalSocketSend] Error connecting: {}'.format(e))
        return response

    # Send message
    logger.debug("[Transport-InternalSocketSend] Sending request: '{0}'.".format(message))

    message = message.split(" ", 1)
    cmd = message[0]
    data = message[1] if len(message) > 1 else None
    message_built = communication.msgbuild(random.SystemRandom().randint(0, 2 ** 32 - 1), cmd, None, data)
    sock.sendall(message_built)

    logger.debug("[Transport-InternalSocketSend] Request sent.")

    # Receive response
    buf = b""
    buf_size = 4096
    try:
        while not response:
            buf += sock.recv(buf_size)
            parse = communication.msgparse(buf, None)
            if parse:
                offset, counter, command, response = parse

        logger.debug("[Transport-InternalSocketSend] Answer received: '{0}'.".format(command))

    except Exception as e:
        logger.error("[Transport-InternalSocketSend] Error: {}.".format(str(e)))
    finally:
        logger.debug("[Transport-InternalSocketSend] Closing socket.")
        sock.close()
        logging.debug("[Transport-InternalSocketSend] Socket closed.")

    return response.decode()


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

        response = send_to_internal_socket(socket_name=socket_name, message=request)
        response_json = json.loads(response)
        return response_json
    except WazuhException as e:
        raise e
    except Exception as e:
        raise WazuhException(3009, str(e))