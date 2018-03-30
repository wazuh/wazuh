#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
try:
    import asyncore
    import socket
    import json
    from sys import argv, exit, path
    from os.path import dirname
    from os import seteuid, setgid, getpid, kill
    from multiprocessing import Process
    from re import search
    from time import sleep
    from pwd import getpwnam
    from signal import signal, pause, alarm, SIGINT, SIGTERM, SIGUSR1, SIGALRM
    import ctypes
    import ctypes.util
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
        from wazuh.cluster.wazuh_server import WazuhClusterServer, send_client_files_to_master
        from wazuh.cluster.cluster import read_config, check_cluster_config
        from wazuh.exception import WazuhException
        from wazuh.pyDaemonModule import pyDaemon, create_pid, delete_pid
    except Exception as e:
        print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
        exit()

    import logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s',
                        filename="{0}/logs/cluster.log".format(common.ossec_path))
except Exception as e:
    print("wazuh-clusterd: Python 2.7 required. Exiting. {}".format(str(e)))
    exit()


def master_main():
    def sync_handler(n_signal, frame):
        logging.debug("[Master] Signal received - deprecated.")

    try:
        signal(SIGUSR1, sync_handler)
        while True:
            logging.info("[Master] Waiting for client requests.")
            pause()

    except Exception as e:
        error_msg = "[Master] Error: {}".format(str(e))
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
            send_client_files_to_master(cluster_config, "Client interval")
        except Exception as e:
            logging.error("[Client] Error synchronizing: '{0}'.".format(str(e)))

        alarm(1)
        pause()


def signal_handler(n_signal, frame):
    def strsignal(n_signal):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        strsignal_proto = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_int)
        strsignal_c = strsignal_proto(("strsignal", libc), ((1,),))

        return strsignal_c(n_signal)

    logging.info("[wazuh-clusterd] Signal [{0}-{1}] received. Exit cleaning...".format(n_signal, strsignal(n_signal)))

    # received Cntrl+C
    if n_signal == SIGINT or n_signal == SIGTERM:

        if child_pid != 0:
            try:
                # kill child
                kill(child_pid, SIGTERM)
                # remove pid files
                delete_pid("wazuh-clusterd", getpid())
            except Exception as e:
                logging.error("[wazuh-clusterd] Error killing child process: {}".format(str(e)))
                if args.d:
                    raise
        else:
            for connections in common.cluster_connections.values():
                try:
                    logging.debug("[wazuh-clusterd] Closing socket {}...".format(connections.socket.getpeername()))
                    connections.socket.close()
                except socket.error as e:
                    if e.errno == socket.errno.EBADF:
                        logging.debug("[wazuh-clusterd] Socket already closed: {}".format(str(e)))
                    else:
                        logging.error("[wazuh-clusterd] Could not close socket: {}".format(str(e)))
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
            logging.info("[wazuh-clusterd] Cluster disabled. Exiting...")
            kill(getpid(), SIGINT)

        # Drop privileges to ossec
        if not args.r:
            pwdnam_ossec = getpwnam('ossec')
            setgid(pwdnam_ossec.pw_gid)
            seteuid(pwdnam_ossec.pw_uid)

        create_pid("wazuh-clusterd", getpid())

        # Get cluster configuration
        try:
            check_cluster_config(cluster_config)
        except WazuhException as e:
            logging.error(str(e))
            kill(getpid(), SIGINT)


        if cluster_config['node_type'] == 'master':
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
        server = WazuhClusterServer(cluster_config, child_pid)

        asyncore.loop()

    except Exception as e:
        logging.error("[wazuh-clusterd] Error: {}".format(str(e)))
        if args.d:
            raise
