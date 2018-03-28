#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
try:
    import asyncore
    import asynchat
    import socket
    import json
    from distutils.util import strtobool
    from sys import argv, exit, path
    from os.path import dirname
    from subprocess import check_call, CalledProcessError
    from os import devnull, seteuid, setgid, getpid, kill, remove
    from multiprocessing import Process, Manager, Value
    from re import search
    from time import sleep
    from pwd import getpwnam
    from signal import signal, pause, alarm, SIGINT, SIGTERM, SIGUSR1, SIGALRM
    import ctypes
    import ctypes.util
    from operator import or_
    from traceback import print_exc, extract_tb
    from io import BytesIO
    from sys import exc_info
    from errno import EINTR
    from datetime import datetime, timedelta

    import argparse
    parser =argparse.ArgumentParser()
    parser.add_argument('-f', help="Run in foreground", action='store_true')
    parser.add_argument('-d', help="Enable debug messages", action='store_true')
    parser.add_argument('-V', help="Print version", action='store_true')
    parser.add_argument('-r', help="Run as root", action='store_true')

    # Set framework path
    path.append(dirname(argv[0]) + '/../framework')  # It is necessary to import Wazuh package

    child_pid = 0

    # Import framework
    try:
        from wazuh import Wazuh

        # Initialize framework
        myWazuh = Wazuh(get_init=True)

        from wazuh import common
        from wazuh.cluster import *
        from wazuh.exception import WazuhException
        from wazuh.utils import check_output
        from wazuh.pyDaemonModule import pyDaemon, create_pid, delete_pid
    except Exception as e:
        print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
        exit()

    if check_cluster_status():
        try:
            from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
        except ImportError as e:
            print("Error importing cryptography module. Please install it with pip, yum (python-cryptography & python-setuptools) or apt (python-cryptography)")
            exit(-1)

    import logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s',
                        filename="{0}/logs/cluster.log".format(common.ossec_path))
except Exception as e:
    print("wazuh-clusterd: Python 2.7 required. Exiting. {}".format(str(e)))
    exit()


# Both

class WazuhClusterHandler(asynchat.async_chat):
    def __init__(self, sock, addr, key, node_type, requests_queue, finished_clients, restart_after_sync, connected_clients, clients_to_restart):
        asynchat.async_chat.__init__(self, sock)
        self.addr = addr
        self.f = Fernet(key.encode('base64','strict'))
        self.set_terminator('\n\t\t\n')
        self.received_data = []
        self.data = ""
        self.counter = 0
        self.node_type = node_type
        self.requests_queue = requests_queue
        self.finished_clients = finished_clients
        self.command = []
        self.restart_after_sync = restart_after_sync
        self.connected_clients = connected_clients
        self.clients_to_restart = clients_to_restart
        self.socket.setblocking(1)

    def handle_close(self):
        self.requests_queue[self.addr] = False
        self.received_data = []

    def collect_incoming_data(self, data):
        self.requests_queue[self.addr] = True
        self.received_data.append(data)

    def found_terminator(self):
        res_is_zip = False
        response = b''.join(self.received_data)
        error = 0

        response_decrypted = self.f.decrypt(response)

        cmd = response_decrypted[:common.cluster_protocol_plain_size].decode()
        self.command = cmd.split(" ")

        logging.debug("Command received: {0}".format(self.command))

        # if not check_cluster_cmd(self.command, self.node_type):
        #     logging.error("Received invalid cluster command {0} from {1}".format(
        #                     self.command[0], self.addr))
        #     error = 1
        #     res = "Received invalid cluster command {0}".format(self.command[0])

        if error == 0:


            # Review
            if self.command[0] == 'node':
                res = get_node()
            elif self.command[0] == 'zip':
                zip_bytes = self.f.decrypt(response[common.cluster_sync_msg_size:])
                res = extract_zip(zip_bytes)
                self.restart_after_sync.value = 'T' if res['restart'] else 'F'
            elif self.command[0] == 'ready':
                # sync_one_node(False, self.addr)
                res = "Starting to sync client's files"
                # execute an independent process to "crontab" the sync interval
                kill(child_pid, SIGUSR1)
            elif self.command[0] == 'finished':
                res = "Sleeping..."

                if bool(int(self.command[1])):
                    clients_to_restart.append(self.addr)

                self.finished_clients.value += 1
                logging.debug("Finished clients: {} of {}".format(self.finished_clients.value, self.connected_clients.value))
                # execute an independent process to "crontab" the sync interval
                if self.finished_clients.value == self.connected_clients.value:
                    self.finished_clients.value = 0
                    self.connected_clients.value = 0
                    kill(child_pid, SIGALRM)



            # New
            elif self.command[0] == 'm_c_sync':
                zip_bytes = response_decrypted[common.cluster_protocol_plain_size:]
                unzip = decompress_files2(zip_bytes)
                res = process_files_from_client(unzip)


                res_is_zip = True
                # Continuing working on master node
                kill(child_pid, SIGUSR1)


            logging.debug("Command {0} executed for {1}".format(self.command[0], self.addr))
        if res_is_zip:
            self.data = res
        else:
            self.data = json.dumps({'error': error, 'data': res})
        self.handle_write()


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()

        if t == socket.error and (v.args[0] == socket.errno.EPIPE or
                                  v.args[0] == socket.errno.EBADF):
            # there is an error in the connection with the other node.
            logging.error("Error in connection with {}: {}".format(self.addr, str(v)))
            self.handle_close()
            self.close()
            self.socket.close()
            return 1

        if t == InvalidToken or t == InvalidSignature:
            error = "Could not decrypt message from {0}".format(self.addr)
        else:
            error = str(v)

        logging.error("Error handling client request: {0}".format(error))
        self.data = json.dumps({'error': 1, 'data': error})
        self.handle_write()


    def handle_write(self):
        msg = self.f.encrypt(self.data) + '\n'
        i = 0
        msg_len = len(msg)
        while i < msg_len:
            next_i = i+4096 if i+4096 < msg_len else msg_len
            try:
                sent = self.socket.send(msg[i:next_i])
                i += sent
            except socket.error as e:
                self.socket.close()
                raise e
        logging.debug("SERVER: Sent {}/{} bytes to {}".format(i, msg_len, self.addr))
        self.handle_close()


class WazuhClusterServer(asyncore.dispatcher):

    def __init__(self, bind_addr, port, key, node_type, requests_queue, finished_clients, restart_after_sync, connected_clients, clients_to_restart, socket_timeout):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(socket_timeout)
        self.set_reuse_addr()
        self.key = key
        self.node_type = node_type
        self.requests_queue = requests_queue
        self.finished_clients = finished_clients
        self.restart_after_sync = restart_after_sync
        self.connected_clients = connected_clients
        self.clients_to_restart = clients_to_restart
        try:
            self.bind((bind_addr, port))
        except socket.error as e:
            logging.error("Can't bind socket: {0}".format(str(e)))
            raise e
        self.listen(50)

        cluster_info = read_config()
        logging.info("Starting cluster {0}".format(cluster_info['name']))
        logging.info("Listening on port {0}.".format(port))
        logging.info("{0} nodes found in configuration".format(len(cluster_info['nodes'])))
        logging.info("Synchronization interval: {0}".format(cluster_info['interval']))


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logging.info("Accepted connection from host {0}".format(addr[0]))
            handler = WazuhClusterHandler(sock, addr[0], self.key, self.node_type,
                                        self.requests_queue, self.finished_clients,
                                        self.restart_after_sync, self.connected_clients,
                                        self.clients_to_restart)
        return

    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()
        self.close()
        raise t(v)


def master_main():
    def sync_handler(n_signal, frame):
        logging.debug("[Master] Signal received - deprecated.")

    try:
        signal(SIGUSR1, sync_handler)
        while True:
            logging.info("[Master] Waiting for client requests.")
            pause()

    except Exception as e:
        error_msg = "Error in cluster client process: {}".format(str(e))
        logging.error(error_msg)



def client_main(cluster_config, debug):
    def sleep_handler(n_signal, frame):
        alarm(0)
        logging.info("[Client] Nothing to do. Sleeping for {}{}...".format(interval_number, interval_measure))
        sleep(sleep_time)

    interval_number  = int(search('\d+', cluster_config['interval']).group(0))
    interval_measure = cluster_config['interval'][-1]
    sleep_time = interval_number if interval_measure == 's' else interval_number*60

    signal(SIGALRM, sleep_handler)

    while True:
        logging.info("[Client] Starting work.")

        try:
            all_nodes = get_nodes2()['items']
            master_node = 'unknown'
            for item in all_nodes:
                if item['type'] == 'master':
                    master_node = item['url']

            if master_node == 'unknown':
                raise
        except:
            logging.error("[Client] Master not found. Going to sleep.")
            alarm(1)
            pause()

        try:
            max_retries = 5
            n_retries = 0
            max_interruptions = 100
            n_interruptions = 0

            while n_retries <= max_retries:
                try:
                    send_client_files_to_master(master_node, cluster_config, [])
                    break
                except IOError as e:
                    if e.errno != EINTR:
                        raise
                    else:
                        n_interruptions += 1
                        if max_interruptions >= n_interruptions:
                            logging.error("Reached maximum number of EINTR errors: {}. Sleeping for 60s.".format(str(e)))
                            sleep(60)
                            n_interruptions = 0
                            continue
                        else:
                            continue
                except Exception as e:
                    exc_type, exc_value, exc_traceback = exc_info()
                    filename, line_number, module, line_content = extract_tb(exc_traceback)[-1]
                    logging.error("Error {} synchronizing information ({}:{}): {}".format(exc_type, filename, line_number, exc_value.args[0]))
                    n_retries += 1
                    if n_retries < max_retries:
                        sleep(5)
                    else:
                        logging.warning("Reached maximum number of retries: sleeping for 60s.")
                        sleep(60)
                        n_retries = 0

            alarm(1)
            pause()
        except Exception as e:
            error_msg = "Error in cluster master process: {}".format(str(e))
            if debug:
                exc_buffer = BytesIO()
                print_exc(file=exc_buffer)
                debug_info = exc_buffer.getvalue()
                error_msg += '\n' + debug_info
            logging.error(error_msg)
            logging.info("Sleeping for {}s".format(sleep_time))
            sleep(sleep_time)
            continue


def signal_handler(n_signal, frame):
    def strsignal(n_signal):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        strsignal_proto = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_int)
        strsignal_c = strsignal_proto(("strsignal", libc), ((1,),))

        return strsignal_c(n_signal)

    logging.info("Signal [{0}-{1}] received. Exit cleaning...".format(n_signal, strsignal(n_signal)))

    # received Cntrl+C
    if n_signal == SIGINT or n_signal == SIGTERM:

        if child_pid != 0:
            try:
                # kill child
                kill(child_pid, SIGTERM)
                # remove pid files
                delete_pid("wazuh-clusterd", getpid())
            except Exception as e:
                logging.error("Error killing child process: {}".format(str(e)))
                if args.d:
                    raise
        else:
            for connections in common.cluster_connections.values():
                try:
                    logging.debug("Closing socket {}...".format(connections.socket.getpeername()))
                    connections.socket.close()
                except socket.error as e:
                    if e.errno == socket.errno.EBADF:
                        logging.debug("Socket already closed: {}".format(str(e)))
                    else:
                        logging.error("Could not close socket: {}".format(str(e)))
    exit(1)


if __name__ == '__main__':
    global cluster_connections

    args = parser.parse_args()
    try:
        # Capture Cntrl + C
        signal(SIGINT, signal_handler)
        signal(SIGTERM, signal_handler)

        # Foreground/daemon and logging
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

        if not args.d:
            logging.getLogger('').setLevel(logging.INFO)

        # Read configuration
        try:
            cluster_config = read_config()
        except WazuhException as e:
            if e.code == 3006:
                cluster_config = None
            else:
                raise e

        if not cluster_config or cluster_config['disabled'] == 'yes':
            logging.info("Cluster disabled. Exiting...")
            kill(getpid(), SIGINT)

        # Drop privileges to ossec
        if not args.r:
            pwdnam_ossec = getpwnam('ossec')
            setgid(pwdnam_ossec.pw_gid)
            seteuid(pwdnam_ossec.pw_uid)

        # ToDo:
        create_pid("wazuh-clusterd", getpid())

        # Get cluster configuration
        try:
            check_cluster_config(cluster_config)
        except WazuhException as e:
            logging.error(str(e))
            kill(getpid(), SIGINT)

        # Main process for master or client
        m = Manager()
        remote_connections = set(cluster_config['nodes']) - set(get_localhost_ips())
        requests_queue = m.dict([(node_ip, False) for node_ip in remote_connections])
        clients_to_restart = m.list()
        finished_clients = Value('i',0)
        connected_clients = Value('i',0)
        restart_after_sync = Value('c','F')

        if cluster_config['node_type'] == 'master':
            #p = Process(target=crontab_sync_master, args=(cluster_config['interval'],cluster_config,requests_queue,connected_clients,finished_clients,clients_to_restart,args.d,))
            p = Process(target=master_main, args=())
            if not args.f:
                p.daemon=True
            p.start()
            child_pid = p.pid
        else:
            p = Process(target=client_main, args=(cluster_config,args.d,))
            if not args.f:
                p.daemon=True
            p.start()
            child_pid = p.pid

        # Create server
        server = WazuhClusterServer('' if cluster_config['bind_addr'] == '0.0.0.0' else cluster_config['bind_addr'],
                                    int(cluster_config['port']),
                                    cluster_config['key'],
                                    cluster_config['node_type'],
                                    requests_queue,
                                    finished_clients,
                                    restart_after_sync,
                                    connected_clients,
                                    clients_to_restart,
                                    100 #int(cluster_config['socket_timeout'])
                                    )
        asyncore.loop()

    except Exception as e:
        logging.error("Error in wazuh-clusterd: {}".format(str(e)))
        if args.d:
            raise
