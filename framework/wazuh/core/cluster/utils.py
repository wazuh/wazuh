# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import contextlib
import fcntl
import json
import logging
import os
import re
import select
import signal
import socket
import threading
import time
import typing
from contextvars import ContextVar
from functools import lru_cache
from glob import glob
from operator import setitem

from wazuh.core import common, pyDaemonModule
from wazuh.core.configuration import get_manager_conf
from wazuh.core.exception import WazuhError, WazuhException, WazuhInternalError
from wazuh.core.results import WazuhResult
from wazuh.core.utils import temporary_cache
from wazuh.core.wlogging import WazuhLogger

logger = logging.getLogger('wazuh')
# Lockfile for preventing concurrent API restart/reload operations
api_operation_lockfile = os.path.join(common.WAZUH_PATH, "var", "run", ".api_operation_lock")
# Privileged helper the control module runs; the same protocol is used when the control socket is unavailable.
SERVICE_CONTROL_NAME = 'wazuh-manager-service-control'
SERVICE_CONTROL_STATUS_FD = 3
SERVICE_CONTROL_TIMEOUT = 5
# Seconds an accepted request waits for the helper's own check, and how often it looks; together with the acceptance
# timeout this stays within the API's default request timeout (10 seconds).
SERVICE_CONTROL_CHECK_TIMEOUT = 4
SERVICE_CONTROL_POLL_INTERVAL = 0.05
SERVICE_CONTROL_MAX_OUTPUT = 4096


def read_cluster_config(config_file=None) -> typing.Dict:
    """Read the cluster configuration from etc/wazuh-manager.conf.

    The section comes from the effective document: every option the file omits takes the default of the schema
    (the same one the C daemons and the engine use), so there is no separate default table here.

    Parameters
    ----------
    config_file : str
        Path to configuration file. Default: common.MANAGER_CONF.

    Raises
    ------
    WazuhError(3006)
        The configuration could not be read or is invalid.

    Returns
    -------
    config_cluster : dict
        Dictionary with cluster configuration.
    """
    try:
        config_cluster = get_manager_conf(section='cluster', conf_file=config_file or common.MANAGER_CONF)['cluster']
    except WazuhException as e:
        raise WazuhError(3006, extra_message=e.message)
    except Exception as e:
        raise WazuhError(3006, extra_message=str(e))

    # Types and ranges (port, node_type, key...) are guaranteed by the schema; check_cluster_config() keeps only
    # what the schema cannot express (reserved addresses).
    return config_cluster


@temporary_cache()
def get_manager_status(cache=False) -> typing.Dict:
    """Get the current status of each process of the manager.

    Raises
    ------
    WazuhInternalError(1913)
        If /proc directory is not found or permissions to see its status are not granted.

    Returns
    -------
    data : dict
        Dict whose keys are daemons and the values are the status. The API daemon is only included on master nodes.
    """
    # Check /proc directory availability
    proc_path = "/proc"
    try:
        os.stat(proc_path)
    except (PermissionError, FileNotFoundError) as e:
        raise WazuhInternalError(1913, extra_message=str(e))

    processes = ['wazuh-manager-analysisd', 'wazuh-manager-authd',
                 'wazuh-manager-remoted', 'wazuh-manager-clusterd',
                 'wazuh-manager-modulesd', 'wazuh-manager-db']

    # The API daemon is only started on the master node (src/init/wazuh-server.sh).
    if read_config()['node_type'] == 'master':
        processes.append('wazuh-manager-apid')

    data, pidfile_regex, run_dir = {}, re.compile(r'.+\-(\d+)\.pid$'), os.path.join(common.WAZUH_PATH, "var", "run")
    for process in processes:
        pidfile = glob(os.path.join(run_dir, f"{process}-*.pid"))
        if os.path.exists(os.path.join(run_dir, f"{process}.failed")):
            data[process] = 'failed'
        elif os.path.exists(os.path.join(run_dir, ".restart")):
            data[process] = 'restarting'
        elif os.path.exists(os.path.join(run_dir, f"{process}.start")):
            data[process] = 'starting'
        elif pidfile:
            # Iterate on pidfiles looking for the pidfile which has his pid in /proc,
            # if the loop finishes, all pidfiles exist but their processes are not running,
            # it means each process crashed and was not able to remove its own pidfile.
            data[process] = 'failed'
            for pid in pidfile:
                if os.path.exists(os.path.join(proc_path, pidfile_regex.match(pid).group(1))):
                    data[process] = 'running'
                    break

        else:
            data[process] = 'stopped'

    return data


def get_cluster_status() -> typing.Dict:
    """Get cluster status.

    Returns
    -------
    dict
        Cluster status.
    """
    try:
        cluster_status = {"running": "yes" if get_manager_status()['wazuh-manager-clusterd'] == 'running' else "no"}
    except WazuhInternalError:
        cluster_status = {"running": "no"}

    return cluster_status


def _reap_service_control(pid: int, stderr_fd: int, action: str, output: bytes = b'') -> None:
    """Wait for an accepted service-control helper and log how it ended.

    The helper's standard error is drained until every holder closes it, so the helper (and what it runs) never
    blocks or fails on a full or broken pipe while this process lives.

    Parameters
    ----------
    pid : int
        PID of the helper.
    stderr_fd : int
        Read end of the helper's standard error.
    action : str
        Action the helper runs ('restart' or 'reload').
    output : bytes
        What the helper wrote to its standard error before this was called.
    """
    try:
        while chunk := os.read(stderr_fd, 4096):
            output = (output + chunk)[-SERVICE_CONTROL_MAX_OUTPUT:]
    except OSError:
        pass
    finally:
        os.close(stderr_fd)

    try:
        _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        return

    exit_code = os.waitstatus_to_exitcode(status)
    if exit_code != 0:
        reason = output.decode(errors='replace').strip()
        logger.error(f"The manager {action} run by {SERVICE_CONTROL_NAME} failed (exit code {exit_code})"
                     f"{f': {reason}' if reason else ''}")


def _run_service_control(action: str) -> None:
    """Ask the privileged service-control helper to restart or reload the manager.

    This is the path the control module takes, used directly when the control socket is unavailable (modulesd is
    not running). The helper reports acceptance by writing '1' on descriptor 3 before it runs the action; it runs in
    its own process group so that stopping this daemon, which the action does, does not stop it. A refusal of the
    check it runs after accepting is reported too, when it comes within `SERVICE_CONTROL_CHECK_TIMEOUT` seconds.

    The helper is spawned with `os.posix_spawn`, the only primitive that both places the status pipe on descriptor 3
    and runs no Python code in the child. It gets a new process group (`setpgroup`), not a new session: `setsid`
    needs POSIX_SPAWN_SETSID, which the bundled interpreter is built without (it raises NotImplementedError). This
    daemon has no controlling terminal and nothing signals its session, so the process group detaches it equally.

    Parameters
    ----------
    action : str
        Action to run ('restart' or 'reload').

    Raises
    ------
    WazuhInternalError(1903)
        If the helper cannot be run.
    WazuhError(1904)
        If the helper refused the action (its check included) or did not accept it in time.
    """
    helper = os.path.join(common.WAZUH_PATH, 'bin', SERVICE_CONTROL_NAME)
    status_r = status_w = stderr_r = stderr_w = devnull = None
    try:
        status_r, status_w = os.pipe()
        stderr_r, stderr_w = os.pipe()
        # Keep the child's descriptors away from 0-3, so that no DUP2 below targets its own source (a DUP2 onto
        # itself would leave the close-on-exec flag set).
        status_w = _move_fd_high(status_w)
        stderr_w = _move_fd_high(stderr_w)
        devnull = _move_fd_high(os.open(os.devnull, os.O_RDWR))
        pid = os.posix_spawn(helper, [helper, action], {},
                             file_actions=[(os.POSIX_SPAWN_DUP2, devnull, 0),
                                           (os.POSIX_SPAWN_DUP2, devnull, 1),
                                           (os.POSIX_SPAWN_DUP2, stderr_w, 2),
                                           (os.POSIX_SPAWN_DUP2, status_w, SERVICE_CONTROL_STATUS_FD)],
                             setpgroup=0)
    except (OSError, NotImplementedError) as e:
        # NotImplementedError: a spawn attribute the interpreter was built without.
        for fd in (status_r, stderr_r):
            if fd is not None:
                os.close(fd)
        raise WazuhInternalError(1903, extra_message=f"{helper}: {getattr(e, 'strerror', None) or e}")
    finally:
        for fd in (status_w, stderr_w, devnull):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)

    try:
        ready, _, _ = select.select([status_r], [], [], SERVICE_CONTROL_TIMEOUT)
        accepted = os.read(status_r, 1) if ready else None
    finally:
        os.close(status_r)

    output = b''
    exit_code = None
    if accepted == b'1':
        # On a systemd host the helper checks the configuration and credentials after accepting and before it
        # hands the action to systemctl, which it then becomes (exec). Wait a bounded time for that verdict: a
        # refusal (the helper exits non-zero) is answered as such; once the helper has become something else, or
        # the wait is over, the action is under way and its outcome is only logged.
        deadline = time.monotonic() + SERVICE_CONTROL_CHECK_TIMEOUT
        while exit_code is None and _is_service_control(pid) and time.monotonic() < deadline:
            output = _read_available(stderr_r, output, timeout=SERVICE_CONTROL_POLL_INTERVAL)
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                exit_code = os.waitstatus_to_exitcode(status)

        if exit_code is None:
            logger.info(f"Manager {action} accepted by {SERVICE_CONTROL_NAME}")
            threading.Thread(target=_reap_service_control, args=(pid, stderr_r, action, output), daemon=True).start()
            return
        if exit_code == 0:
            os.close(stderr_r)
            logger.info(f"Manager {action} run by {SERVICE_CONTROL_NAME}")
            return
    else:
        if accepted is None:
            os.kill(pid, signal.SIGKILL)
        _, status = os.waitpid(pid, 0)
        exit_code = os.waitstatus_to_exitcode(status)

    output = _read_available(stderr_r, output, timeout=0)
    os.close(stderr_r)
    reason = output.decode(errors='replace').strip()

    if accepted is None:
        detail = f"no answer within {SERVICE_CONTROL_TIMEOUT} seconds"
    else:
        detail = f"exit code {exit_code}"
    raise WazuhError(1904, extra_message={'action': action,
                                          'detail': f"{detail}{f': {reason}' if reason else ''}"})


def _is_service_control(pid: int) -> bool:
    """Whether the process is still the service-control helper, i.e. has not replaced itself with what it runs.

    Parameters
    ----------
    pid : int
        PID of the helper.

    Returns
    -------
    bool
        True while the process runs the helper's own image (the kernel keeps 15 characters of its name).
    """
    try:
        with open(f'/proc/{pid}/comm') as comm:
            return comm.read().strip() == SERVICE_CONTROL_NAME[:15]
    except OSError:
        return False


def _read_available(fd: int, output: bytes, timeout: float) -> bytes:
    """Append to `output` what `fd` has to read within `timeout` seconds, keeping the last bytes only.

    Parameters
    ----------
    fd : int
        Descriptor to read.
    output : bytes
        What was read so far.
    timeout : float
        Seconds to wait for the descriptor to be readable.

    Returns
    -------
    bytes
        `output` followed by what was read, at most `SERVICE_CONTROL_MAX_OUTPUT` bytes.
    """
    try:
        while select.select([fd], [], [], timeout)[0]:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            output = (output + chunk)[-SERVICE_CONTROL_MAX_OUTPUT:]
            timeout = 0
    except OSError:
        pass

    return output


def _move_fd_high(fd: int) -> int:
    """Move a descriptor above the standard and status descriptors.

    Parameters
    ----------
    fd : int
        Descriptor to move; it is closed.

    Returns
    -------
    int
        Close-on-exec duplicate of `fd`, numbered 10 or higher.
    """
    try:
        return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
    finally:
        os.close(fd)


def _send_control_command(msg: str) -> None:
    """Send a command to the Wazuh manager control socket.

    When the socket does not exist or refuses the connection (modulesd is not running), the command is run through
    the privileged service-control helper instead, as the control module itself would.

    Parameters
    ----------
    msg : str
        Command to send ('restart' or 'reload').

    Raises
    ------
    WazuhInternalError(1903)
        If the control socket is unavailable and the service-control helper cannot be run.
    WazuhError(1904)
        If the control socket is unavailable and the service-control helper refused the command.
    WazuhInternalError(1014)
        If there is a socket communication error.
    """
    lock_file = open(api_operation_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        socket_path = common.CONTROL_SOCKET
        conn = None
        if os.path.exists(socket_path):
            conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                conn.connect(socket_path)
            except socket.error as e:
                conn.close()
                conn = None
                logger.warning(f"{WazuhInternalError(1902, extra_message=str(e)).message}. "
                               f"Using {SERVICE_CONTROL_NAME}")
        else:
            logger.warning(f"{WazuhInternalError(1901).message}. Using {SERVICE_CONTROL_NAME}")

        if conn is None:
            _run_service_control(msg)
            return

        try:
            conn.send(msg.encode())
            response = conn.recv(1024).decode().strip()
            conn.close()

            if not response.startswith('ok'):
                raise WazuhInternalError(1014, extra_message=response)
        except socket.error as e:
            raise WazuhInternalError(1014, extra_message=str(e))
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()
        read_config.cache_clear()


def manager_restart() -> WazuhResult:
    """Restart Wazuh manager.

    Send 'restart' command to common.CONTROL_SOCKET socket, or run it through the service-control helper when the
    socket is unavailable.

    Raises
    ------
    WazuhInternalError(1903)
        If the control socket is unavailable and the service-control helper cannot be run.
    WazuhError(1904)
        If the control socket is unavailable and the service-control helper refused the command.
    WazuhInternalError(1014)
        If there is a socket communication error.

    Returns
    -------
    WazuhResult
        Confirmation message.
    """
    _send_control_command('restart')
    return WazuhResult({'message': 'Restart request sent'})


def manager_reload() -> WazuhResult:
    """Reload Wazuh manager.

    Send 'reload' command to common.CONTROL_SOCKET socket, or run it through the service-control helper when the
    socket is unavailable.

    Raises
    ------
    WazuhInternalError(1903)
        If the control socket is unavailable and the service-control helper cannot be run.
    WazuhError(1904)
        If the control socket is unavailable and the service-control helper refused the command.
    WazuhInternalError(1014)
        If there is a socket communication error.

    Returns
    -------
    WazuhResult
        Confirmation message.
    """
    _send_control_command('reload')
    return WazuhResult({'message': 'Reload request sent'})


@lru_cache()
def get_cluster_items():
    """Load and return the content of cluster.json file as a dict.

    Returns
    -------
    cluster_items : dict
        Dictionary with the information inside cluster.json file.
    """
    try:
        here = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(common.WAZUH_PATH, here, 'cluster.json')) as f:
            cluster_items = json.load(f)
        # Rebase permissions.
        list(map(lambda x: setitem(x, 'permissions', int(x['permissions'], base=0)),
                 filter(lambda x: 'permissions' in x, cluster_items['files'].values())))
        return cluster_items
    except Exception as e:
        raise WazuhError(3005, str(e))

@lru_cache()
def safe_join(base_path: str, *paths: str) -> str:
    """Join two paths and ensure the resulting path is within the base path.
    Parameters
    ----------
    base_path : str
        The base directory path.
    paths : str
        The paths to be joined with the base path. Absolute paths will be treated as relative to the base path.
    Returns
    -------
    str
        The safely joined path.
    Raises
    ------
    WazuhInternalError
        If the resulting path is outside the base path.
    """

    safe_paths = [p.lstrip(os.sep).lstrip("/") for p in paths]

    base = os.path.normpath(base_path)
    final_path = os.path.normpath(os.path.join(base, *safe_paths))

    if os.path.commonpath([base, final_path]) != base:
        raise WazuhInternalError(3003, extra_message=f"unsafe path '{final_path}'")

    return final_path



# Prefix of the cluster wire paths (cluster.json keys and file names exchanged between nodes) that name a file of the
# configuration directory. The wire keeps the historical '<home>/etc' layout byte-identical across versions, while the
# directory itself is common.CONF_PATH (a fixed absolute path outside the home on an installed manager).
_WIRE_CONF_PREFIX = 'etc'


def local_path(rel: str) -> str:
    """Translate a cluster wire path into the local absolute path.

    Wire paths under 'etc' are rooted at common.CONF_PATH; every other one at common.WAZUH_PATH. Both are joined with
    safe_join(), so a path escaping its root (e.g. 'etc/../x') is refused instead of being re-rooted elsewhere.

    Parameters
    ----------
    rel : str
        Wire path, relative to the manager home (a leading separator is ignored, as safe_join() does).

    Raises
    ------
    WazuhInternalError(3003)
        If the resulting path is outside its root.

    Returns
    -------
    str
        Normalized absolute local path.
    """
    stripped = rel.lstrip(os.sep).lstrip('/')
    if stripped == _WIRE_CONF_PREFIX or stripped.startswith(_WIRE_CONF_PREFIX + '/'):
        return safe_join(common.CONF_PATH, stripped[len(_WIRE_CONF_PREFIX):])
    return safe_join(common.WAZUH_PATH, rel)


def wire_path(abs_path: str) -> str:
    """Translate a local absolute path into its cluster wire path (the inverse of local_path()).

    A trailing separator in `abs_path` is kept in the result, so directory keys keep the 'etc/' and 'etc/shared/'
    shape of cluster.json.

    Parameters
    ----------
    abs_path : str
        Absolute path under common.CONF_PATH or common.WAZUH_PATH.

    Raises
    ------
    WazuhInternalError(3003)
        If the path is under neither root.

    Returns
    -------
    str
        Wire path: 'etc[/<path relative to CONF_PATH>]' or the path relative to WAZUH_PATH.
    """
    trailing = '/' if abs_path.endswith(os.sep) else ''
    target = os.path.normpath(abs_path)
    conf_base = os.path.normpath(common.CONF_PATH)
    home_base = os.path.normpath(common.WAZUH_PATH)

    # The configuration directory is checked first: in a repository checkout it lies inside WAZUH_PATH.
    if os.path.commonpath([conf_base, target]) == conf_base:
        rel = os.path.relpath(target, conf_base)
        wire = _WIRE_CONF_PREFIX if rel == '.' else f'{_WIRE_CONF_PREFIX}/{rel}'
    elif os.path.commonpath([home_base, target]) == home_base and target != home_base:
        wire = os.path.relpath(target, home_base)
    else:
        raise WazuhInternalError(3003, extra_message=f"unsafe path '{target}'")

    return wire + trailing

@lru_cache()
def read_config(config_file=None):
    """Get the cluster configuration.

    Parameters
    ----------
    config_file : str
        Path to configuration file.

    Returns
    -------
    dict
        Dictionary with cluster configuration.
    """
    return read_cluster_config(config_file=config_file)


# Context vars
context_tag: ContextVar[str] = ContextVar('tag', default='')


class ClusterFilter(logging.Filter):
    """
    Add cluster related information into cluster logs.
    """

    def __init__(self, tag: str, subtag: str, name: str = ''):
        """Class constructor.

        Parameters
        ----------
        tag : str
            First tag to show in the log - Usually describes class.
        subtag : str
            Second tag to show in the log - Usually describes function.
        name : str
            If name is specified, it names a logger which, together with its children, will have its events
            allowed through the filter. If name is the empty string, allows every event.
        """
        super().__init__(name=name)
        self.tag = tag
        self.subtag = subtag

    def filter(self, record):
        record.tag = context_tag.get() if context_tag.get() != '' else self.tag
        record.subtag = self.subtag
        return True


class ClusterLogger(WazuhLogger):
    """
    Define the logger used by wazuh-manager-clusterd.
    """

    def setup_logger(self):
        """
        Set ups cluster logger. In addition to super().setup_logger() this method adds:
            * A filter to add tag and subtags to cluster logs
            * Sets log level based on the "debug_level" parameter received from wazuh-manager-clusterd binary.
        """
        super().setup_logger()
        self.logger.addFilter(ClusterFilter(tag='Cluster', subtag='Main'))
        debug_level = logging.DEBUG2 if self.debug_level == 2 else \
            logging.DEBUG if self.debug_level == 1 else logging.INFO

        self.logger.setLevel(debug_level)


def log_subprocess_execution(logger_instance: logging.Logger, logs: dict):
    """Log messages returned by functions that are executed in cluster's subprocesses.

    Parameters
    ----------
    logger_instance: Logger object
        Instance of the used logger.
    logs: dict
        Dict containing messages of different logging level.
    """
    if 'debug' in logs and logs['debug']:
        logger_instance.debug(f"{dict(logs['debug'])}")
    if 'debug2' in logs and logs['debug2']:
        logger_instance.debug2(f"{dict(logs['debug2'])}")
    if 'warning' in logs and logs['warning']:
        logger_instance.warning(f"{dict(logs['warning'])}")
    if 'error' in logs and logs['error']:
        logger_instance.error(f"{dict(logs['error'])}")
    if 'generic_errors' in logs and logs['generic_errors']:
        for error in logs['generic_errors']:
            logger_instance.error(error, exc_info=False)


def process_spawn_sleep(child):
    """Task to force the cluster pool spawn all its children and create their PID files.

    Parameters
    ----------
    child: int
        Process child number.
    """
    pid = os.getpid()
    pyDaemonModule.create_pid(f'wazuh-manager-clusterd_child_{child}', pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    # Add a delay to force each child process to create its own PID file, preventing multiple calls
    # executed by the same child
    time.sleep(0.1)


async def forward_function(func: callable, f_kwargs: dict = None, request_type: str = 'local_master',
                           nodes: list = None, broadcasting: bool = False, is_async: bool = False):
    """Distribute function to master node.

    Parameters
    ----------
    func : callable
        Function to execute on master node.
    f_kwargs : dict
        Function kwargs.
    request_type : str
        Request type.
    nodes : list
        System cluster nodes.
    broadcasting : bool
        Whether the function will be broadcasted or not.
    is_async : bool
        Whether the function is asynchronous.

    Returns
    -------
    Return either a dict or `WazuhResult` instance in case the execution did not fail. Return an exception otherwise.
    """

    import concurrent
    from asyncio import run

    from wazuh.core.cluster.dapi.dapi import DistributedAPI
    dapi = DistributedAPI(f=func, f_kwargs=f_kwargs, request_type=request_type,
                          is_async=is_async, wait_for_complete=True, logger=logger, nodes=nodes,
                          broadcasting=broadcasting)
    pool = concurrent.futures.ThreadPoolExecutor()
    return pool.submit(run, dapi.distribute_function()).result()


def raise_if_exc(result: object) -> None:
    """Check if a specified object is an exception and raise it.

    Raises
    ------
    Exception

    Parameters
    ----------
    result : object
        Object to be checked.
    """
    if isinstance(result, Exception):
        raise result
