#!/usr/bin/env python

import threading
import time
import docker
import json
import socket
import sys


class DockerListener:

    def __init__(self, interval=1):
        # socket variables
        self.wazuh_path = open('/etc/ossec-init.conf').readline().split('"')[1]
        self.wazuh_queue = '{0}/queue/ossec/queue'.format(self.wazuh_path)
        # docker variables
        self.interval = interval
        self.client = docker.from_env()
        self.event_list = []
        thread = threading.Thread(target=self.listen)
        thread.daemon = True
        thread.start()

    def listen(self):
        for event in self.client.events():
            self.event_list.append(event)
            # print(event)
            self.process(event)

    def process(self, event):
        if("\"status\":\"unpause\"" in str(event)):
            print("One container was restarted")
        elif("\"status\":\"pause\"" in str(event)):
            print("One container was paused")
        elif("\"status\":\"start\"" in str(event)):
            print("One container was started")
        elif("\"status\":\"stop\"" in str(event)):
            print("One container was stopped")

    def debug(msg, msg_level):
        # if debug_level >= msg_level:
        print('DEBUG: {debug_msg}'.format(debug_msg=msg))

    def send_msg(self, msg):
        """
        Sends an AWS event to the Wazuh Queue

        :param msg: JSON message to be sent.
        """
        try:
            json_msg = json.dumps(msg)
            self.debug(json_msg, 3)
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
    while True:
        time.sleep(5)

"""
msg = {
            'integration': 'aws',
            'aws': {
                'log_info': {
                    'aws_account_alias': self.account_alias,
                    'log_file': log_key,
                    's3bucket': self.bucket
                }
            }
        }
must have -> {'integration':, 'data':}
"""