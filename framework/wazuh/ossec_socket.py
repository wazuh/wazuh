#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh import common
import socket
from json import dumps, loads
from struct import pack, unpack

class OssecSocket:

    MAX_SIZE = 65536

    def __init__(self, path):
        self.path = path
        self._connect()

    def _connect(self):
        try:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(self.path)
        except:
            raise WazuhException(1013, self.path)

    def close(self):
        self.s.close()

    def send(self, msg):
        try:
            sent = self.s.send(pack("<I", len(msg)) + msg)
            if sent == 0:
                raise WazuhException(1014, self.path)
            return sent
        except:
            raise WazuhException(1014, self.path)

    def receive(self):

        try:
            size = unpack("<I", self.s.recv(4, socket.MSG_WAITALL))[0]

            if size > OssecSocket.MAX_SIZE:
                raise WazuhException(1014, self.path)

            return self.s.recv(size, socket.MSG_WAITALL)
        except:
            raise WazuhException(1014, self.path)

class OssecSocketJSON(OssecSocket):

    MAX_SIZE = 65536

    def __init__(self, path):
        super().__init__(path)

    def send(self, msg):
        return super().send(dumps(msg).encode())

    def receive(self):
        try:
            chunk = super().receive().decode()
            response = loads(super().receive().decode())
        except:
            raise WazuhException(1014, self.path)

        if 'error' in response.keys():
            if response['error'] != 0:
                raise WazuhException(response['error'], response['message'], cmd_error=True)
            else:
                return response['data']
