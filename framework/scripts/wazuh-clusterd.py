#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

#
# Imports
#
try:
    import asyncore
    import threading
    import time
    import argparse
    import logging
    import ctypes
    import ctypes.util
    import socket
    from signal import signal, SIGINT, SIGTERM
    from pwd import getpwnam
    from sys import argv, exit, path
    from os.path import dirname
    from os import seteuid, setgid, getpid, kill, unlink

    # Import framework
    try:
        # Search path
        path.append(dirname(argv[0]) + '/../framework')

        # Import and Initialize
        from wazuh import Wazuh
        myWazuh = Wazuh(get_init=True)

        from wazuh import common
        from wazuh.exception import WazuhException
        from wazuh.pyDaemonModule import pyDaemon, create_pid, delete_pid
        from wazuh.cluster.cluster import read_config, check_cluster_config
        from wazuh.cluster.master import MasterManager, MasterKeepAliveThread, MasterInternalSocketHandler
        from wazuh.cluster.client import ClientManager, ClientIntervalThread, ClientInternalSocketHandler
        from wazuh.cluster.communication import InternalSocketThread

    except Exception as e:
        print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
        exit()
except Exception as e:
    print("wazuh-clusterd: Python 2.7 required. Exiting. {0}".format(str(e)))
    exit()


#
# Aux functions
#

def set_logging(foreground_mode=False, debug_mode=False):
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s',
                        filename="{0}/logs/cluster.log".format(common.ossec_path))

    if not debug_mode:
        logging.getLogger('').setLevel(logging.INFO)

    if foreground_mode:
        # define a Handler which writes INFO messages or higher to the sys.stderr
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        # set a format which is simpler for console use
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
        # tell the handler to use this format
        console.setFormatter(formatter)
        # add the handler to the root logger
        logging.getLogger('').addHandler(console)


def clean_exit(reason, error=False):
    msg = "[wazuh-clusterd] Exiting. Reason: '{0}'.".format(reason)

    if error:
        logging.error(msg)
    else:
        logging.info(msg)

    delete_pid("wazuh-clusterd", getpid())
    exit(1)


def signal_handler(n_signal, frame):
    def strsignal(n_signal):
        libc = ctypes.CDLL(ctypes.util.find_library('c'))
        strsignal_proto = ctypes.CFUNCTYPE(ctypes.c_char_p, ctypes.c_int)
        strsignal_c = strsignal_proto(("strsignal", libc), ((1,),))

        return strsignal_c(n_signal)

    if n_signal == SIGINT or n_signal == SIGTERM:
        clean_exit(reason="Signal [{0}-{1}] received.".format(n_signal, strsignal(n_signal)))


#
# Master main
#
def master_main(cluster_configuration):
    # ToDo: Add it in ossec.conf
    cluster_configuration['ka_interval'] = 60  # seconds

    # Initiate master
    master = MasterManager(cluster_config=cluster_configuration)

    # Send keep alive
    ka_thread = MasterKeepAliveThread(master)
    ka_thread.start()

    # Internal socket
    internal_socket_thread = InternalSocketThread("c-internal")
    internal_socket_thread.start()
    internal_socket_thread.setmanager(master, MasterInternalSocketHandler)

    # Loop
    asyncore.loop(timeout=1, use_poll=False, map=master.map, count=None)


#
# Client main
#
def client_main(cluster_configuration):
    # ToDo: Add it in ossec.conf
    cluster_configuration['reconnect_time'] = 10  # seconds
    # ToDo: Get in the proper way
    cluster_configuration['interval'] = 120  # seconds

    # Create threads
    interval_thread = ClientIntervalThread()
    interval_thread.start()

    # Internal socket
    internal_socket_thread = InternalSocketThread("c-internal")
    internal_socket_thread.start()

    # Loop
    while True:
        client = ClientManager(cluster_config=cluster_configuration)

        interval_thread.setclient(client)
        internal_socket_thread.setmanager(client, ClientInternalSocketHandler)

        asyncore.loop(timeout=1, use_poll=False, map=client.map, count=None)

        logging.error("[wazuh-clusterd] Client disconnected. Trying to connect again in {0}s.".format(cluster_configuration['reconnect_time']))

        time.sleep(cluster_configuration['reconnect_time'])


#
# Main
#
if __name__ == '__main__':
    # Signals
    signal(SIGINT, signal_handler)
    signal(SIGTERM, signal_handler)

    # Parse args
    parser =argparse.ArgumentParser()
    parser.add_argument('-f', help="Run in foreground", action='store_true')
    parser.add_argument('-d', help="Enable debug messages", action='store_true')
    parser.add_argument('-V', help="Print version", action='store_true')
    parser.add_argument('-r', help="Run as root", action='store_true')
    args = parser.parse_args()

    # Set logger
    set_logging(foreground_mode=args.f, debug_mode=args.d)

    # Foreground/Daemon
    if not args.f:
        res_code = pyDaemon()

    # Get cluster config
    try:
        cluster_config = read_config()
    except WazuhException as e:
        cluster_config = None

    if not cluster_config or cluster_config['disabled'] == 'yes':
        clean_exit(reason="Cluster disabled", error=True)

    # Drop privileges to ossec
    if not args.r:
        pwdnam_ossec = getpwnam('ossec')
        setgid(pwdnam_ossec.pw_gid)
        seteuid(pwdnam_ossec.pw_uid)

    # Creating pid file
    create_pid("wazuh-clusterd", getpid())
    logging.info("[wazuh-clusterd] PID: {0}".format(getpid()))

    # Validate config
    try:
        check_cluster_config(cluster_config)
    except WazuhException as e:
        clean_exit(reason="Invalid configuration: '{0}'".format(str(e)), error=True)

    # Main
    try:

        if cluster_config['node_type'] == "master":
            master_main(cluster_config)
        elif cluster_config['node_type'] == "client":
            client_main(cluster_config)
        else:
            clean_exit(reason="Node type '{0}' not valid.".format(cluster_config['node_type']), error=True)

    except Exception as e:
        if args.d:
            raise
        clean_exit(reason="Unkown exception: '{0}'".format(str(e)), error=True)
