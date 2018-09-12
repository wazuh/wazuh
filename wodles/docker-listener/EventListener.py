#!/usr/bin/env python

import threading
import time
import docker

class DockerListener:

    def __init__(self, interval=1):
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


if __name__ == "__main__":
    dl = DockerListener()
    while True:
        time.sleep(5)
