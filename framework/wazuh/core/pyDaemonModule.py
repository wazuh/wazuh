# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import glob
import logging
import os
import signal
import sys
from os import path

import psutil

from wazuh.core import common
from wazuh.core.exception import WazuhInternalError

API_MAIN_PROCESS = 'wazuh-apid'
API_LOCAL_REQUEST_PROCESS = 'wazuh-apid_exec'
API_SECURITY_EVENTS_PROCESS = 'wazuh-apid_events'
API_AUTHENTICATION_PROCESS = 'wazuh-apid_auth'


def pyDaemon():
    """
    Do the UNIX double-fork magic, see Stevens' "Advanced
    Programming in the UNIX Environment" for details (ISBN 0201563177)
    http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
    """
    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(
            "fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    os.setsid()

    # Do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(
            "fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open('/dev/null', 'r')
    so = open('/dev/null', 'a+')
    se = open('/dev/null', 'ab+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # Decouple from parent environment
    os.chdir('/')


def create_pid(name: str, pid: int):
    """Create pidfile.

    Parameters
    ----------
    name : str
        Process name.
    pid : int
        Process ID.

    Raises
    ------
    WazuhInternalError(3002)
        Error creating pidfile.
    """
    filename = path.join(common.WAZUH_PATH, common.OS_PIDFILE_PATH, f'{name}-{pid}.pid')

    with open(filename, 'a') as fp:
        try:
            fp.write(f'{pid}\n')
            os.chmod(filename, 0o640)
        except OSError as e:
            raise WazuhInternalError(3002, str(e))


def delete_pid(name: str, pid: int):
    """Unlink pidfile.

    Parameters
    ----------
    name : str
        Process name.
    pid : int
        Process ID.
    """
    filename = path.join(common.WAZUH_PATH, common.OS_PIDFILE_PATH, f'{name}-{pid}.pid')

    try:
        if path.exists(filename):
            os.unlink(filename)
    except OSError:
        pass


def delete_child_pids(name: str, ppid: int, logger: logging.Logger):
    """Delete all childs from a process given its PID.

    Parameters
    ----------
    name : str
        Process name.
    ppid : int
        Parent process ID.
    logger : logging.Logger
        Logger object.
    """
    filenames = glob.glob(path.join(common.WAZUH_PATH, common.OS_PIDFILE_PATH, f'{name}*.pid'))

    for process in psutil.Process(ppid).children(recursive=True):
        try:
            process.kill()
        except psutil.Error:
            logger.error(f'Error while trying to terminate the process with ID {process.pid}.')
        except Exception as exc:
            logger.error(f'Unhandled exception while trying to terminate the process with ID {process.pid}: {exc}')
        for filename in filenames[:]:
            if str(process.pid) in filename:
                try:
                    path.exists(filename) and os.unlink(filename)
                except OSError:
                    pass
                filenames.remove(filename)


def spawn_process_pool_worker(process_name: str) -> None:
    """Spawn process pool worker.

    Parameters
    ----------
    process_name : str
        Process name.
    """

    process_pid = os.getpid()
    create_pid(process_name, process_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)
