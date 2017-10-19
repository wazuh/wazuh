#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import socket
import select
from sys import argv, exit, path
from os.path import dirname
from collections import deque
import json

import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

# Import framework
try:
    from wazuh import Wazuh
    from wazuh.cluster import *
    from wazuh.exception import WazuhException
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

tasks = deque()
recv_wait = {}
send_wait = {}

def loop():
    while any([tasks, recv_wait, send_wait]):
        while not tasks:
            can_recv, can_send, _ = select.select(recv_wait, send_wait, [])
            for task in can_recv:
                tasks.append(recv_wait.pop(task))

            for task in can_send:
                tasks.append(send_wait.pop(task))

        task = tasks.popleft()
        try:
            task_type, task_place = next(task)

            if task_type == "recv":
                recv_wait[task_place] = task

            if task_type == "send":
                send_wait[task_place] = task
        except StopIteration as e:
            logging.info("All jobs done")

def server(port, host):
    try:
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        # Bind the socket to all IP address of the host
        try:
            sock.bind((host, port))
        except socket.error as e:
            logging.error("Can't bind socket: {0}".format(str(e)))
            return

        logging.info("Listening on port {0}.".format(port))
        # listen to 5 connections at the same time
        sock.listen(5)

        while True:
            # accept connections from outside
            yield "recv", sock
            clientsocket, address = sock.accept()
            logging.info("Accepted connection from host {0}".format(address[0]))
            tasks.append(handler(clientsocket, address))

    except socket.error as e:
        try:
            clientsocket.close()
            logging.error("Closed connection with {0}. {1}".format(address[0], str(e)))
        except:
            sock.close()
            logging.error("Closed socket: {0}".format(str(e)))


def handler(clientsocket, address):
    try:
        res = ""
        # receive size of command
        yield "recv", clientsocket
        size = int(clientsocket.recv(4))
        logging.debug("I will receive a command of size {0} from {1}".format(size, address))
        # send confirmation
        yield "send", clientsocket
        clientsocket.send(b'1')
        logging.debug("I've sent confirmation of receiving msg size to {0}".format(address))
        # receive command
        yield "recv", clientsocket
        command = clientsocket.recv(size).decode().split(" ")
        logging.debug("Command received: {0}".format(command[0]))

        if command[0] == "sync":
            # command[1] can be either true or false
            res = sync(command[1])
        elif command[0] == "node":
            res = get_node()
        elif command[0] == "zip":
            # command[1] is the size of zip file
            # zip command has two stages: one to receive the will to send
            # a zip file and another to send the zip file
            yield "send", clientsocket
            clientsocket.send('1')
            logging.debug("Asking {0} for the bytes of zip file".format(address))
            yield "recv", clientsocket
            zip_bytes = clientsocket.recv(int(command[1]))
            res = extract_zip()

        # convert data to json format
        data = json.dumps(res).encode()
        logging.debug("Command {0} executed for {1}".format(command[0], address))
        # send data size to client
        yield "send", clientsocket
        res_size = str(len(data))
        clientsocket.send(res_size.encode())
        logging.debug("Size of response is {0}".format(res_size))
        # wait for confirmation
        yield "recv", clientsocket
        clientsocket.recv(4)
        logging.debug("Confirmation from {0} received".format(address))
        # send data
        yield "send", clientsocket
        clientsocket.send(data)
        logging.debug("Data sent to {0}".format(address))
        # close connection
        clientsocket.close()
        logging.info("Closed connection with host {0}".format(address))

    except Exception as e:
        logging.error("Error handling client request: {0}".format(str(e)))


if __name__ == '__main__':
    # Initialize framework
    myWazuh = Wazuh(get_init=True)
    # get cluster conf
    cluster_config = read_config()
    tasks.append(server(port=int(cluster_config['port']),
                        host='' if not cluster_config['host'] else cluster_config['host']))
    loop()

