#!/usr/bin/python3
import socket as s
import sys
import os


sock = s.socket(s.AF_UNIX, s.SOCK_DGRAM)
sock.connect("/var/wazuh-manager/queue/sockets/queue")
sock.send(open(sys.argv[1], "rb").read())
