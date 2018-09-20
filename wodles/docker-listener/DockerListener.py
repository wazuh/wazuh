#!/usr/bin/env python


try:
    import docker
except:
    raise Exception("\'docker\' module needs to be installed")
import threading
import json
import socket
import sys
import time


class DockerListener:

    wait_time = 5

    def __init__(self):
        """"
        DockerListener constructor

        """
        # socket variables
        if sys.platform == "win32":
            self.wazuh_path = 'C:\Program Files (x86)\ossec-agent'
            print("ERROR: This wodle does't work on Windows.")
            sys.exit(1)
        else:
            self.wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
        self.wazuh_queue = '{0}/queue/ossec/queue'.format(self.wazuh_path)
        self.msg_header = "1:Wazuh-Docker:"
        # docker variables
        self.client = docker.from_env()
        self.check_docker_service()
        self.thread1 = threading.Thread(target=self.listen)
        self.thread1.start()

    def reconnect(self):
        """
        Tries to reconnect to Docker service waiting the time specified in class variable 'wait_time'

        """
        try:
            if self.client.ping():
                self.thread1 = threading.Thread(target=self.listen)
                self.thread1.start()
            print("Docker service was restarted.")  # delete
            self.send_msg(json.dumps({"info_docker": "Reconnected to Docker service"}))
            return
        except:
            print("Reconnecting...")  # delete
            # self.send_msg(json.dumps({"info_docker": "Reconnecting to Docker service"}))
            time.sleep(self.wait_time)
            self.reconnect()


    def check_docker_service(self):
        """
        Checks if Docker service is running

        """
        try:
            self.client.ping()
            print("Docker service is running.")  # delete
            self.send_msg(json.dumps({"info_docker": "Connected to Docker service"}))
            # return True
        except Exception:
            # print("Docker service is not running.")
            # return False
            print("Docker service is not running.")
            time.sleep(self.wait_time)
            self.check_docker_service()

            # sys.exit("Docker service isn't running.")

    def listen(self):
        """
        Listens Docker events

        """
        try:
            for event in self.client.events():
                self.process(event)
        except Exception:
            raise Exception
        print("Docker service was stopped.")  # delete
        self.send_msg(json.dumps({"info_docker": "Docker service was stopped"}))
        self.reconnect()

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
