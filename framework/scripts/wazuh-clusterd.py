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
    from os import devnull, seteuid, setgid, getpid, kill
    from multiprocessing import Process, Manager, Value
    from re import search
    from time import sleep
    from pwd import getpwnam
    from signal import signal, pause, SIGINT, SIGTERM, SIGUSR1
    import ctypes
    import ctypes.util
    from operator import or_

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

        # Initialize framework
        myWazuh = Wazuh(get_init=True)

        from wazuh.common import *
        from wazuh.cluster.handler import *
        from wazuh.cluster.management import *
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
except:
    print("wazuh-clusterd: Python 2.7 required. Exiting.")
    exit()

class WazuhClusterHandler(asynchat.async_chat):
    def __init__(self, sock, addr, key, node_type, requests_queue, finished_clients, restart_after_sync, connected_clients, config_cluster, cluster_items):
        asynchat.async_chat.__init__(self, sock)
        self.addr = addr
        self.f = Fernet(key.encode('base64','strict'))
        self.set_terminator('\n\t\t\n')
        self.received_data=[]
        self.data=""
        self.counter = 0
        self.node_type = node_type
        self.requests_queue = requests_queue
        self.finished_clients = finished_clients
        self.command = []
        self.restart_after_sync = restart_after_sync
        self.connected_clients = connected_clients
        self.config_cluster = config_cluster
        self.cluster_items = cluster_items

    def handle_close(self):
        self.requests_queue[self.addr] = False
        self.close()

    def collect_incoming_data(self, data):
        self.requests_queue[self.addr] = True
        self.received_data.append(data)

    def found_terminator(self):
        response = b''.join(self.received_data)
        error = 0
        cmd = self.f.decrypt(response[:common.cluster_sync_msg_size]).decode()
        self.command = cmd.split(" ")

        logging.debug("Command received: {0}".format(self.command))

        if not check_cluster_cmd(self.command, self.node_type):
            logging.error("Received invalid cluster command {0} from {1}".format(
                            self.command[0], self.addr))
            error = 1
            res = "Received invalid cluster command {0}".format(self.command[0])

        if error == 0:
            if self.command[0] == 'node':
                res = get_node(self.config_cluster)
            elif self.command[0] == 'zip':
                zip_bytes = self.f.decrypt(response[common.cluster_sync_msg_size:])
                res = extract_zip(zip_bytes, self.config_cluster, self.cluster_items)
                self.restart_after_sync.value = 'T' if res['restart'] else 'F'
            elif self.command[0] == 'ready':
                # sync_one_node(False, self.addr)
                res = "Starting to sync client's files"
                # execute an independent process to "crontab" the sync interval
                kill(child_pid, SIGUSR1)
            elif self.command[0] == 'finished':
                res = "Sleeping..."
                self.finished_clients.value += 1
                logging.debug("Finished clients: {} of {}".format(self.finished_clients.value, self.connected_clients.value))
                # execute an independent process to "crontab" the sync interval
                if self.finished_clients.value == connected_clients.value:
                    self.finished_clients.value = 0
                    self.connected_clients.value = 0
                    kill(child_pid, SIGUSR1)

            logging.debug("Command {0} executed for {1}".format(self.command[0], self.addr))

        self.data = json.dumps({'error': error, 'data': res})
        self.handle_write()


    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()
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
            sent = self.send(msg[i:next_i])
            if sent == 4096 or next_i == msg_len:
                i = next_i
            logging.debug("SERVER: Sending {} of {}".format(i, msg_len))

        logging.debug("Data sent to {0}".format(self.addr))
        self.handle_close()

class WazuhClusterServer(asyncore.dispatcher):

    def __init__(self, bind_addr, port, key, node_type, requests_queue, finished_clients, restart_after_sync, connected_clients, cluster_info, cluster_items):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(common.cluster_timeout)
        self.set_reuse_addr()
        self.key = key
        self.node_type = node_type
        self.requests_queue = requests_queue
        self.finished_clients = finished_clients
        self.restart_after_sync = restart_after_sync
        self.connected_clients = connected_clients
        self.config_cluster = cluster_info
        self.cluster_items = cluster_items
        try:
            self.bind((bind_addr, port))
        except socket.error as e:
            logging.error("Can't bind socket: {0}".format(str(e)))
            raise e
        self.listen(50)

        logging.info("Starting cluster {0}".format(cluster_info['name']))
        logging.info("Listening on port {0}.".format(port))
        logging.info("{0} nodes found in configuration".format(len(cluster_info['nodes'])))
        logging.info("Synchronization interval: {0}".format(cluster_info['interval']))


    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logging.info("Accepted connection from host {0}".format(addr[0]))
            handler = WazuhClusterHandler(sock, addr[0], self.key, self.node_type, self.requests_queue, 
                                         self.finished_clients, self.restart_after_sync, 
                                         self.connected_clients, self.config_cluster, self.cluster_items)
        return

    def handle_error(self):
        nil, t, v, tbinfo = asyncore.compact_traceback()
        self.close()
        raise t(v)


def restart_manager():
    if run_logtest():
        try:
            logging.info("Restarting manager...")
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect("{0}/queue/alerts/execq".format(common.ossec_path))
            sock.send("restart-ossec0 cluster restart")
        except CalledProcessError as e:
            logging.warning("Could not restart manager: {0}.".format(str(e)))


def crontab_sync_master(interval, config_cluster, requests_queue, connected_clients, finished_clients):
    def sleep_handler(n_signal, frame):
        logging.debug("Sleeping for {}{}...".format(interval_number, interval_measure))
        sleep(interval_number if interval_measure == 's' else interval_number*60)

    interval_number  = int(search('\d+', interval).group(0))
    interval_measure = interval[-1]
    cluster_items = get_cluster_items()
    signal(SIGUSR1, sleep_handler)
    while True:
        logging.debug("Elements in requests queue: {}".format(requests_queue.items()))
        if len(requests_queue.values()) == 0 or not reduce(or_, requests_queue.values()):
            logging.debug("Crontab: starting to sync")
            try:
                sync(debug=False, config_cluster=config_cluster, cluster_items=cluster_items)
            except Exception as e:
                logging.error(str(e))
                kill(child_pid, SIGINT)

            remote_nodes = get_remote_nodes(config_cluster)
            connected_clients.value = len(remote_nodes)
            finished_clients.value = 0
            for node in remote_nodes:
                # ask clients to send updates
                error, response = send_request(host=node, port=config_cluster["port"], key=config_cluster['key'],
                                    data="ready {0}".format('-'*(common.cluster_protocol_plain_size - len("ready "))))

        else:
            logging.debug("Receiving data...")

        if connected_clients.value == 0:
            sleep_handler(0,0)
        else:
            pause()


def crontab_sync_client(config_cluster, restart_after_sync):
    def sync_handler(n_signal, frame):
        logging.debug("Starting to send files to the master node")
        master = get_remote_nodes(config_cluster)[0]
        sync_one_node(debug=False, node=master, config_cluster=config_cluster, cluster_items=cluster_items)
        if restart_after_sync.value == 'T':
            restart_after_sync.value = 'F'
            cluster_socket = connect_to_db_socket()
            send_to_socket(cluster_socket, "delres")
            receive_data_from_db_socket(cluster_socket)
            send_to_socket(cluster_socket, "insertres 1")
            receive_data_from_db_socket(cluster_socket)
            cluster_socket.close()
            restart_manager()
        else:
            error, response = send_request(host=master, port=config_cluster['port'], key=config_cluster['key'],
                            data="finished {}".format('-'*(common.cluster_protocol_plain_size - len("finished "))))


    cluster_socket = connect_to_db_socket()
    send_to_socket(cluster_socket, "selres")
    restart_str = receive_data_from_db_socket(cluster_socket)
    restart = True if restart_str == '1' else False
    if restart:
        logging.info("Client restarted")
        send_to_socket(cluster_socket, "delres")
        receive_data_from_db_socket(cluster_socket)
        send_to_socket(cluster_socket, "insertres 0")
        receive_data_from_db_socket(cluster_socket)
        cluster_socket.close()
        master = get_remote_nodes(config_cluster)[0]
        error, response = send_request(host=master, port=config_cluster['port'], key=config_cluster['key'],
                            data="finished {}".format('-'*(common.cluster_protocol_plain_size - len("finished "))))
    else:
        cluster_socket.close()


    signal(SIGUSR1, sync_handler)
    cluster_items = get_cluster_items()
    while True:
        pause()


def signal_handler(n_signal, frame):
    def strsignal(n_signal):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        strsignal_proto = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_int)
        strsignal_c = strsignal_proto(("strsignal", libc), ((1,),))

        return strsignal_c(n_signal)

    logging.info("Signal [{0}-{1}] received. Exit cleaning...".format(n_signal,
                                                               strsignal(n_signal)))
    # received Cntrl+C
    if n_signal == SIGINT or n_signal == SIGTERM:
        # kill C daemon if it's running
        try:
            pid = int(check_output(["pidof","{0}/bin/wazuh-clusterd-internal".format(ossec_path)]))
            kill(pid, SIGINT)
        except Exception:
            pass

        if child_pid != 0:
            # kill child
            kill(child_pid, SIGTERM)
            # remove pid files
            delete_pid("wazuh-clusterd", getpid())
    exit(1)

def run_internal_daemon(debug):
    call_list = ["{0}/bin/wazuh-clusterd-internal".format(ossec_path), "-t{0}".format(cluster_config['node_type'])]
    if debug:
        call_list.append("-ddd")
    check_call(call_list)

if __name__ == '__main__':
    args = parser.parse_args()
    if args.V:
        check_output(["{0}/bin/wazuh-clusterd-internal".format(ossec_path), '-V'])
        exit(0)

    # Capture Cntrl + C
    signal(SIGINT, signal_handler)
    signal(SIGTERM, signal_handler)

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

    # execute C cluster daemon (database & inotify) if it's not running
    try:
        exit_code = check_call(["ps", "-C", "wazuh-clusterd-internal"], stdout=open(devnull, 'w'))
        pid = check_output(["pidof", "{0}/bin/wazuh-clusterd-internal".format(common.ossec_path)]).split(" ")
        for p in pid:
            p = p[:-1] if '\n' in p else p
            check_call(["kill", p])

        run_internal_daemon(args.d)
    except CalledProcessError:
        run_internal_daemon(args.d)

    # Drop privileges to ossec
    pwdnam_ossec = getpwnam('ossec')
    setgid(pwdnam_ossec.pw_gid)
    seteuid(pwdnam_ossec.pw_uid)

    create_pid("wazuh-clusterd", getpid())

    if not args.d:
        logging.getLogger('').setLevel(logging.INFO)

    try:
        check_cluster_config(cluster_config)
    except WazuhException as e:
        logging.error(str(e))
        kill(getpid(), SIGINT)

    cluster_items = get_cluster_items()

    logging.info("Cleaning database before starting service...")
    clear_file_status(cluster_config, cluster_items)

    m = Manager()
    requests_queue = m.dict([(node_ip, False) for node_ip in set(cluster_config['nodes']) - set(get_localhost_ips())])
    finished_clients = Value('i',0)
    connected_clients = Value('i',0)
    restart_after_sync = Value('c','F')


    if cluster_config['node_type'] == 'master':
        # execute an independent process to "crontab" the sync interval
        p = Process(target=crontab_sync_master, args=(cluster_config['interval'],cluster_config,requests_queue,connected_clients,finished_clients,))
        if not args.f:
            p.daemon=True
        p.start()
        child_pid = p.pid
    else:
        # execute an independent process to "crontab" the sync interval
        p = Process(target=crontab_sync_client, args=(cluster_config,restart_after_sync,))
        if not args.f:
            p.daemon=True
        p.start()
        child_pid = p.pid

    server = WazuhClusterServer('' if cluster_config['bind_addr'] == '0.0.0.0' else cluster_config['bind_addr'],
                                int(cluster_config['port']), cluster_config['key'], cluster_config['node_type'],
                                requests_queue, finished_clients, restart_after_sync, connected_clients, 
                                cluster_config, cluster_items)
    asyncore.loop()
