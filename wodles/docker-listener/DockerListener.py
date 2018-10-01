#!/usr/bin/env python


try:
    import docker
except:
    raise Exception("\'docker\' module needs to be installed.")
import threading
import json
import socket
import sys
import time


class DockerListener:

    wait_time = 5
    field_debug_name = "Wodle event"

    def __init__(self):
        """"
        DockerListener constructor

        """
        # socket variables
        if sys.platform == "win32":
            self.wazuh_path = 'C:\Program Files (x86)\ossec-agent'
            print("ERROR: This wodle does not work on Windows.")
            sys.exit(1)
        else:
            self.wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
        self.wazuh_queue = '{0}/queue/ossec/queue'.format(self.wazuh_path)
        self.msg_header = "1:Wazuh-Docker:"
        # docker variables
        self.client = docker.from_env()
        self.send_msg(json.dumps({self.field_debug_name: "Started"}))
        self.thread1 = threading.Thread(target=self.listen)
        self.connect(first_time=True)

    def connect(self, first_time=False):
        """
        Connects to Docker service, retrying if connection is not successful

        """
        if self.check_docker_service():
            if not first_time:
                self.thread1 = threading.Thread(target=self.listen)
            self.thread1.start()
            self.send_msg(json.dumps({self.field_debug_name: "Connected to Docker service"}))
        else:
            if first_time:
                self.send_msg(json.dumps({self.field_debug_name: "Docker service is not running"}))
            while not self.check_docker_service():
                time.sleep(self.wait_time)
            self.connect()

    def check_docker_service(self):
        """
        Checks if Docker service is running

        :return: True if Docker service is active or False if it is inactive.
        """
        try:
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
        except Exception:
            raise Exception
        self.send_msg(json.dumps({self.field_debug_name: "Disconnected to Docker service"}))
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
        Sends an AWS event to the Wazuh Queue

        :param msg: message to be sent.
        """
        try:
            json_msg = json.dumps(self.format_msg(msg))
            print(json_msg)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            s.connect(self.wazuh_queue)
            s.send("{header}{msg}".format(header=self.msg_header,
                                          msg=json_msg).encode())
            s.close()
        except socket.error as e:
            if e.errno == 111:
                print('ERROR: Wazuh must be running.')
                sys.exit(11)
            else:
                print("ERROR: Error sending message to wazuh: {}".format(e))
                sys.exit(13)
        except Exception as e:
            print("ERROR: Error sending message to wazuh: {}".format(e))
            sys.exit(13)


if __name__ == "__main__":
    dl = DockerListener()
