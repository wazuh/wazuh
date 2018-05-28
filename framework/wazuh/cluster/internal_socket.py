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

class InternalSocketHandler(communication.Handler):

    def __init__(self, sock, manager, asyncore_map):
        communication.Handler.__init__(self, key=None, sock=sock, asyncore_map=asyncore_map)
        self.manager = manager


    def process_request(self, command, data):
        return ['err', json.dumps({'err', "Received an unknown command '{}'".format(command)})]


class InternalSocket(asyncore.dispatcher):

    def __init__(self, socket_name, manager, handle_type, asyncore_map = {}):
        asyncore.dispatcher.__init__(self, map=asyncore_map)
        self.handle_type = handle_type
        self.map = asyncore_map
        self.socket_name = socket_name
        self.manager = manager
        self.socket_address = "{}{}/{}.sock".format(common.ossec_path, "/queue/cluster", self.socket_name)
        self.__create_socket()


    def __create_socket(self):
        logger.debug2("[Transport-InternalSocket] Creating.")

        # Make sure the socket does not already exist
        try:
            os.unlink(self.socket_address)
        except OSError:
            if os.path.exists(self.socket_address):
                logger.error("[Transport-InternalSocket] Error: '{}' already exits".format(self.socket_address))
                raise

        self.create_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.set_reuse_addr()
        try:
            self.bind(self.socket_address)
            os.chown(self.socket_address, common.ossec_uid, common.ossec_gid)
            self.listen(5)
            logger.debug2("[Transport-InternalSocket] Listening.")
        except Exception as e:
            logger.error("[Transport-InternalSocket] Cannot create the socket: '{}'.".format(e))

        logger.debug2("[Transport-InternalSocket] Created.")


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logger.debug("[Transport-InternalSocket] Incoming connection from '{0}'.".format(repr(addr)))
            handler = self.handle_type(sock=sock, manager=self.manager, asyncore_map=self.map)


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        try:
            self_repr = repr(self)
        except:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        self.handle_close()

        logger.error("[Transport-InternalSocket] Error: '{}'.".format(v))
        logger.debug("[Transport-InternalSocket] Error: '{}' - '{}'.".format(t, tbinfo))


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

                logger.info("{0} [Internal-COM ]: Disconnected. Trying to connect again in {}s.".format(self.thread_tag, self.interval_connection_retry))

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