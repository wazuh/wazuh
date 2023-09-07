#!/usr/bin/env python3

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

import os
import threading
import json
import socket
import sys
import time
from os.path import abspath, dirname

sys.path.insert(0, dirname(dirname(abspath(__file__))))
from utils import MAX_EVENT_SIZE

try:
    import docker
except:
    sys.stderr.write("'docker' module needs to be installed. Execute 'pip3 install docker' to do it.\n")
    exit(1)


class DockerListener:
    wait_time = 5
    field_debug_name = "Wodle event"

    def __init__(self):
        """"
        DockerListener constructor

        """
        if sys.platform == "win32":
            sys.stderr.write("This wodle does not work on Windows.\n")
            sys.exit(1)
        # socket variables
        self.wazuh_path = os.path.abspath(os.path.join(__file__, "..", "..", ".."))
        self.wazuh_queue = os.path.join(self.wazuh_path, "queue", "sockets", "queue")
        self.msg_header = "1:Wazuh-Docker:"
        # docker variables
        self.client = None
        self.thread1 = None
        self.thread2 = None

    def start(self):
        self.send_msg(json.dumps({self.field_debug_name: "Started"}))
        self.thread1 = threading.Thread(target=self.listen)
        self.thread2 = threading.Thread(target=self.listen)
        self.connect(first_time=True)

    def connect(self, first_time=False):
        """
        Connects to Docker service, retrying if connection is not successful

        """
        if self.check_docker_service():
            if not first_time:
                # this is for having a thread assigned to a variable ever
                if self.thread1.is_alive():
                    self.thread2 = threading.Thread(target=self.listen)
                    self.thread2.start()
                else:
                    self.thread1 = threading.Thread(target=self.listen)
                    self.thread1.start()
            else:
                self.thread1.start()
            print("Docker service was started.")
            self.send_msg(json.dumps({self.field_debug_name: "Connected to Docker service"}))
        else:
            if first_time:
                print("Docker service is not running.")
                self.send_msg(json.dumps({self.field_debug_name: "Docker service is not running"}))
            while not self.check_docker_service():
                print("Reconnecting...")
                time.sleep(self.wait_time)
            self.connect()

    def check_docker_service(self):
        """
        Checks if Docker service is running

        :return: True if Docker service is active or False if it is inactive.
        """
        try:
            self.client = docker.from_env()
            self.client.ping()
            return True
        except Exception:
            return False

    def listen(self):
        """
        Listens Docker events

        """
        try:
            for event in self.client.events():
                self.process(event)
        except Exception as e:
            raise e
        print("Docker service was stopped.")
        self.send_msg(json.dumps({self.field_debug_name: "Disconnected from the Docker service"}))
        self.connect()

    def process(self, event):
        """"
        Processes a main Docker event

        :param event: Docker event.
        """
        self.send_msg(event.decode("utf-8"))

    def format_msg(self, msg):
        """
        Formats a Docker event

        :param msg: message to be formatted.
        :return: formatted message.
        """
        return {'integration': 'docker', 'docker': json.loads(msg)}

    def send_msg(self, msg):
        """
        Sends a Docker event to the Wazuh Queue

        :param msg: message to be sent.
        """
        try:
            json_msg = json.dumps(self.format_msg(msg))
            print(json_msg)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)

            encoded_msg = "{header}{msg}".format(header=self.msg_header,
                                                 msg=json_msg).encode()
            # Logs warning if event is bigger than max size
            if len(encoded_msg) > MAX_EVENT_SIZE:
                sys.stderr.write(f"WARNING: Event size exceeds the maximum allowed limit of {MAX_EVENT_SIZE} bytes.")

            s.send(encoded_msg)
            s.close()
        except socket.error as e:
            if e.errno == 111:
                sys.stderr.write('Wazuh must be running.\n')
                sys.exit(11)
            else:
                sys.stderr.write("Error sending message to wazuh: {}\n".format(e))
                sys.exit(13)
        except Exception as e:
            sys.stderr.write("Error sending message to wazuh: {}\n".format(e))
            sys.exit(13)


if __name__ == "__main__":
    dl = DockerListener()
    dl.start()
