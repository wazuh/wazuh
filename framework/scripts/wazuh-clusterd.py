#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

# Necessary imports to enable logging
try:
    from sys import argv, exit, path, version_info

    if version_info[0] == 2 and version_info[1] < 7:
        raise Exception("Error starting wazuh-clusterd. Minimal Python version required is 2.7. Found version is {0}.{1}".\
            format(version_info[0], version_info[1]))

    import argparse
    import logging
    from os.path import dirname

    # Import framework
    # Search path
    path.append(dirname(argv[0]) + '/../framework')

    # Import and Initialize
    from wazuh import Wazuh

    myWazuh = Wazuh(get_init=True)

    from wazuh import common
except Exception as e:
    print ("Error starting wazuh-clusterd: {0}".format(e))
    exit(1)


# Rest of imports. If an exception is raised, it will be logged using logging.
error_msg = ""
try:
    from signal import signal, SIGINT, SIGTERM
    import asyncore
    import threading
    import time
    import ctypes
    import ctypes.util
    import socket
    from os import seteuid, setgid, getpid, chown, chmod

    from wazuh.exception import WazuhException
    from wazuh.pyDaemonModule import pyDaemon, create_pid, delete_pid
    from wazuh.cluster import __version__, __author__, __ossec_name__, __licence__
    from wazuh.cluster.cluster import read_config, check_cluster_config, clean_up, get_cluster_items, CustomFileRotatingHandler
    from wazuh.cluster.master import MasterManager, MasterInternalSocketHandler
    from wazuh.cluster.worker import WorkerManager, WorkerInternalSocketHandler
    from wazuh.cluster.internal_socket import InternalSocketThread
    from wazuh import configuration as config
    from wazuh.manager import status

except Exception as e:
    error_msg = str(e)


logger = logging.getLogger()

#
# Aux functions
#

def set_logging(foreground_mode=False, debug_mode=0):
    # configure logger
    fh = CustomFileRotatingHandler(filename="{}/logs/cluster.log".format(common.ossec_path), when='midnight')
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    if foreground_mode:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # add a new debug level
    logging.DEBUG2 = 5
    def debug2(self, message, *args, **kws):
        if self.isEnabledFor(logging.DEBUG2):
            self._log(logging.DEBUG2, message, args, **kws)

    def error(self, msg, *args, **kws):
        if self.isEnabledFor(logging.ERROR):
            kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
            self._log(logging.ERROR, msg, args, **kws)

    logging.addLevelName(logging.INFO, "INFO    ")
    logging.addLevelName(logging.WARNING, "WARNING ")
    logging.addLevelName(logging.ERROR, "ERROR   ")
    # logging.addLevelName(logging.CRITICAL, "CRITICAL")
    logging.addLevelName(logging.DEBUG, "DEBUG   ")
    logging.addLevelName(logging.DEBUG2, "DEBUG2  ")

    logging.Logger.debug2 = debug2
    logging.Logger.error = error

    debug_level = logging.DEBUG2 if debug_mode == 2 else logging.DEBUG if \
                  debug_mode == 1 else logging.INFO

    logger.setLevel(debug_level)


def print_version():
    print("\n{} {} - {}\n\n{}".format(__ossec_name__, __version__, __author__, __licence__))


def clean_exit(reason, error=False):
    global processing_exit

    if not processing_exit:
        processing_exit = True

        msg = "[{0}] Exiting. Reason: '{1}'.".format(manager_tag, reason)

        if error:
            logger.error(msg)
        else:
            logger.info(msg)

        if manager:
            manager.exit()

        delete_pid("wazuh-clusterd", getpid())

        exit(1)
    else:
        logger.debug2("[{0}] clean_exit was already executed. Skipping.".format(manager_tag))


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
    global manager

    # Initiate master
    manager = MasterManager(cluster_config=cluster_configuration)

    # Internal socket
    internal_socket_thread = InternalSocketThread("c-internal", tag="[Master ]")
    internal_socket_thread.start()
    internal_socket_thread.setmanager(manager, MasterInternalSocketHandler)
    manager.handler.isocket_handler = internal_socket_thread.internal_socket

    # Loop
    asyncore.loop(timeout=1, use_poll=False, map=manager.map, count=None)


#
# Worker main
#
def worker_main(cluster_configuration):
    global manager
    connection_retry_interval = get_cluster_items()['intervals']['worker']['connection_retry']

    # Internal socket
    internal_socket_thread = InternalSocketThread("c-internal", tag="[Worker ]")
    internal_socket_thread.start()

    # Loop
    while True:
        try:
            manager = WorkerManager(cluster_config=cluster_configuration)

            internal_socket_thread.setmanager(manager, WorkerInternalSocketHandler)

            manager.handler.isocket_handler = internal_socket_thread.internal_socket

            asyncore.loop(timeout=1, use_poll=False, map=manager.handler.map, count=None)

            logger.error("[{0}] Disconnected. Trying to connect again in {1}s.".format(manager_tag, connection_retry_interval))

            manager.exit()
        except socket.gaierror as e:
            logger.error("[Worker ] Could not connect to master: {}. Review if the master's hostname or IP is correct. Trying to connect again in {}s".format(e, connection_retry_interval))
        except socket.error as e:
            logger.error("[Worker ] Could not connect to master: {}. Trying to connect again in {}s.".format(e, connection_retry_interval))

        time.sleep(connection_retry_interval)


#
# Main
#
if __name__ == '__main__':
    manager = None
    manager_tag = "wazuh-clusterd"
    processing_exit = False

    # Parse args
    parser =argparse.ArgumentParser()
    parser.add_argument('-f', help="Run in foreground", action='store_true')
    parser.add_argument('-d', help="Enable debug messages", action='count')
    parser.add_argument('-V', help="Print version", action='store_true')
    parser.add_argument('-r', help="Run as root", action='store_true')
    args = parser.parse_args()

    if args.V:
        print_version()

    # Set logger
    try:
        debug_mode = config.get_internal_options_value('wazuh_clusterd','debug',2,0) or args.d
    except Exception:
        debug_mode = 0

    set_logging(foreground_mode=args.f, debug_mode=debug_mode)

    # set appropiate permissions to the cluster.log file
    chown('{0}/logs/cluster.log'.format(common.ossec_path), common.ossec_uid, common.ossec_gid)
    chmod('{0}/logs/cluster.log'.format(common.ossec_path), 0o660)

    if error_msg:
        logger.error(error_msg)
        if not args.f:
            print ("Error starting wazuh-clusterd: {0}".format(error_msg))
        exit(1)

    # Signals
    signal(SIGINT, signal_handler)
    signal(SIGTERM, signal_handler)

    # Check if it is already running
    if status()['wazuh-clusterd'] == 'running':
        clean_exit(reason="wazuh_clusterd is already running", error=True)

    # Foreground/Daemon
    if not args.f:
        res_code = pyDaemon()

    # Get cluster config
    try:
        cluster_config = read_config()
    except WazuhException as e:
        clean_exit(reason=str(e), error=True)

    if not cluster_config or cluster_config['disabled'] == 'yes':
        clean_exit(reason="Cluster disabled", error=True)

    # Drop privileges to ossec
    if not args.r:
        setgid(common.ossec_gid)
        seteuid(common.ossec_uid)

    # Creating pid file
    create_pid("wazuh-clusterd", getpid())

    # Validate config
    try:
        check_cluster_config(cluster_config)
    except WazuhException as e:
        clean_exit(reason="Invalid configuration: '{0}'".format(str(e)), error=True)

    # Clean all temporary files before starting
    clean_up()

    # Main
    try:

        if cluster_config['node_type'] == "master":
            manager_tag = "Master "
            logger.info("[{0}] PID: {1}".format(manager_tag, getpid()))

            try:
                master_main(cluster_config)
            except socket.error as e:
                if e.args[0] == socket.errno.EADDRINUSE:
                    logger.error("There is another wazuh-clusterd instance running. Please, close it. '{0}'.".format(str(e)))
                else:
                    logger.error("{0}".format(str(e)))

        elif cluster_config['node_type'] == "worker":
            manager_tag = "Worker "
            logger.info("[{0}] PID: {1}".format(manager_tag, getpid()))

            worker_main(cluster_config)
        else:
            clean_exit(reason="Node type '{0}' not valid.".format(cluster_config['node_type']), error=True)

    except Exception as e:
        if args.d:
            raise
        clean_exit(reason="Unknown exception: '{0}'".format(str(e)), error=True)
