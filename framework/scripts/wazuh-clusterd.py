#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncore
import asynchat
import socket
import json
from distutils.util import strtobool
from sys import argv, exit, path
from os.path import dirname
from subprocess import check_call, CalledProcessError, check_output
from os import devnull, seteuid, setgid, getpid, kill
from multiprocessing import Process
from re import search
from time import sleep
from pwd import getpwnam
from signal import signal, SIGINT
import ctypes
import ctypes.util
from cryptography.fernet import Fernet

import logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s',
                    filename="/var/ossec/logs/cluster.log")

import argparse
parser =argparse.ArgumentParser()
parser.add_argument('-f', help="Run in foreground", action='store_true')
parser.add_argument('-d', help="Enable debug messages", action='store_true')
parser.add_argument('-V', help="Print version", action='store_true')

# Set framework path
path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

child_pid = 0

# Import framework
try:
    from wazuh import Wazuh
    from wazuh.common import *
    from wazuh.cluster import *
    from wazuh.exception import WazuhException
    from wazuh.InputValidator import InputValidator
    from wazuh.utils import send_request
    from wazuh.pyDaemonModule import pyDaemon, create_pid, delete_pid
    iv = InputValidator()
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    exit()

class WazuhClusterHandler(asynchat.async_chat):
    def __init__(self, sock, addr, key):
        asynchat.async_chat.__init__(self, sock)
        self.addr = addr
        self.f = Fernet(key.encode('base64','strict'))
        self.set_terminator('\n\t\t\n')
        self.received_data=[]
        self.data=""
        self.counter = 0

    def collect_incoming_data(self, data):
        self.received_data.append(data)

    def found_terminator(self):
        response = b''.join(self.received_data)
        error = 0
        try:
            cmd = self.f.decrypt(response[:common.cluster_sync_msg_size]).decode()
            command = cmd.split(" ")

            logging.debug("Command received: {0}".format(command))

            if not iv.check_cluster_cmd(command):
                logging.error("Received invalid cluster command {0} from {1}".format(
                                command[0], self.addr))
                error = 1
                res = "Received invalid cluster command {0}".format(command[0])

            if error == 0:
                if command[0] == 'node':
                    res = get_node()
                elif command[0] == 'zip':
                    zip_bytes = self.f.decrypt(response[common.cluster_sync_msg_size:])
                    res = extract_zip(zip_bytes)

                logging.debug("Command {0} executed for {1}".format(command[0], self.addr))

            self.data = json.dumps({'error': error, 'data': res})

        except Exception as e:
            logging.error("Error handling client request: {0}".format(str(e)))
            self.data = json.dumps({'error': 1, 'data': str(e)})

        self.handle_write()

    def handle_write(self):
        msg = self.f.encrypt(self.data + '\n')
        i = 0
        while i < len(msg): 
            next_i = i+4096 if i+4096 < len(msg) else len(msg)
            sent = self.send(msg[i:next_i])
            if sent == 4096 or next_i == len(msg):
                i = next_i

        logging.debug("Data sent to {0}".format(self.addr))

class WazuhClusterServer(asyncore.dispatcher):

    def __init__(self, host, port, key):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.key = key
        try:
            self.bind((host, port))
        except socket.error as e:
            logging.error("Can't bind socket: {0}".format(str(e)))
            raise e
        self.listen(50)
        logging.info("Listening on port {0}.".format(port))

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logging.info("Accepted connection from host {0}".format(addr[0]))
            handler = WazuhClusterHandler(sock, addr[0], self.key)
        return

    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()
        raise t(v)


def crontab_sync(interval):
    interval_number  = int(search('\d+', interval).group(0))
    interval_measure = interval[-1]
    while True:
        logging.debug("Crontab: starting to sync")
        sync(False)
        sleep(interval_number if interval_measure == 's' else interval_number*60)

def signal_handler(n_signal, frame):
    def strsignal(n_signal):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        strsignal_proto = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_int)
        strsignal_c = strsignal_proto(("strsignal", libc), ((1,),))

        return strsignal_c(n_signal)

    logging.info("Signal [{0}-{1}] received. Exit cleaning...".format(n_signal, 
                                                               strsignal(n_signal)))
    # received Cntrl+C
    if n_signal == SIGINT:
        # kill C daemon if it's running
        try:
            pid = int(check_output(["pidof","{0}/framework/wazuh-clusterd-internal".format(ossec_path)]))
            kill(pid, SIGINT)
        except CalledProcessError:
            pass

        if child_pid != 0:
            # remove pid files
            delete_pid("wazuh-clusterd", getpid())
    exit(1)

if __name__ == '__main__':
    # Drop privileges to ossec
    pwdnam_ossec = getpwnam('ossec')
    setgid(pwdnam_ossec.pw_gid)
    seteuid(pwdnam_ossec.pw_uid)
    
    args = parser.parse_args()
    if args.V:
        check_output(["{0}/bin/wazuh-clusterd-internal".format(ossec_path), '-V'])
        exit(0)

    # Capture Cntrl + C
    signal(SIGINT, signal_handler)

    cluster_config = read_config()

    # execute C cluster daemon (database & inotify) if it's not running
    try:
        exit_code = check_call(["ps", "-C", "wazuh-clusterd-internal"], stdout=open(devnull, 'w'))
    except CalledProcessError:
        call_list = ["{0}/bin/wazuh-clusterd-internal".format(ossec_path), "-t{0}".format(cluster_config['node_type'])]
        if args.d:
            call_list.append("-ddd")
        check_call(call_list)
    
    if not args.f:
        res_code = pyDaemon()
    else:
        # define a Handler which writes INFO messages or higher to the sys.stderr
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        # set a format which is simpler for console use
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logging.getLogger('').addHandler(console)

    create_pid("wazuh-clusterd", getpid())

    if not args.d:
        logging.getLogger('').setLevel(logging.INFO)

    try:
        iv.check_cluster_config(cluster_config)
    except WazuhException as e:
        logging.error(str(e))
        exit(1)

    # Initialize framework
    myWazuh = Wazuh(get_init=True)
    
    # execute an independent process to "crontab" the sync interval
    p = Process(target=crontab_sync, args=(cluster_config['interval'],))
    if not args.f:
        p.daemon=True
    p.start()
    child_pid = p.pid

    server = WazuhClusterServer('' if not cluster_config['host'] else cluster_config['host'], 
                                int(cluster_config['port']), cluster_config['key'])
    asyncore.loop()
