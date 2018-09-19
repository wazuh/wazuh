#!/usr/bin/env python


try:
    import docker
except:
    raise Exception("\'docker\' module needs to be installed")
import threading
import json
import socket
import sys


class DockerListener:

    def __init__(self, interval=1):
        """"
        DockerListener constructor

        """
        # socket variables
        if sys.platform == "win32":
            self.wazuh_path = 'C:\Program Files (x86)\ossec-agent'
        else:
            self.wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
        self.wazuh_queue = '{0}/queue/ossec/queue'.format(self.wazuh_path)
        self.msg_header = "1:Wazuh-Docker:"
        # docker variables
        self.interval = interval
        self.client = docker.from_env()
        self.check_docker_service()
        # self.event_list = []  # could be removed
        self.thread = threading.Thread(target=self.listen)
        self.thread.start()

    def check_docker_service(self):
        """
        Checks if Docker service is running

        """
        try:
            self.client.ping()
        except Exception:
            sys.exit("Docker service is not running.")

    def listen(self):
        """
        Listens Docker events

        """
        try:
            for event in self.client.events():
                self.process(event)
        except Exception:
            raise Exception

    def process(self, event):
        """"
        Processes a main Docker event

        :param event: Docker event.
        """
        """
        #### events not catched: kill, die
        if 'status' in event:
            if event['status'] is "create":
                print("One container was created")
                self.event_list.append(event)
                # sends the event to the socket
                self.send_msg(str(event))
            elif event['status'] is "destroy":
                print("One container was destroyed")
                self.event_list.append(event)
                # sends the event to the socket
                self.send_msg(str(event))
            elif event['status'] is "pause":
                print("One container was paused")
                self.event_list.append(event)
                # sends the event to the socket
                self.send_msg(str(event))
             elif event['status'] is "unpause":
                print("One container was restarted")
                self.event_list.append(event)
                # sends the event to the socket
                self.send_msg(str(event))
             elif event['status'] is "start":
                print("One container was started")
                self.event_list.append(event)
                # sends the event to the socket
                self.send_msg(str(event))
             elif event['status'] is "stop":
                print("One container was stopped")
                self.event_list.append(event)
                # sends the event to the socket
                self.send_msg(str(event))
        """
        self.send_msg(event.decode("utf-8"))

    def debug(self, msg, msg_level):
        # if debug_level >= msg_level:
        print('DEBUG: {debug_msg}'.format(debug_msg=msg))

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
            # self.debug(json_msg, 3)
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
