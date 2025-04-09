import fcntl
import json
import logging
import os
import re
import socket
import typing
from contextvars import ContextVar
from glob import glob
from pathlib import Path

from wazuh.core import common
from wazuh.core.exception import WazuhInternalError
from wazuh.core.results import WazuhResult
from wazuh.core.utils import temporary_cache
from wazuh.core.wazuh_socket import create_wazuh_socket_message
from wazuh.core.wlogging import WazuhLogger

EXECQ_LOCKFILE = common.WAZUH_RUN / '.api_execq_lock'
# Context vars
context_tag: ContextVar[str] = ContextVar('tag', default='')


class ServerFilter(logging.Filter):
    """Add server related information into server logs."""

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
        """Filter log record."""
        record.tag = context_tag.get() if context_tag.get() != '' else self.tag
        record.subtag = self.subtag
        return True

    def update_tag(self, new_tag: str):
        """Update log tag with new tag."""
        self.tag = new_tag

    def update_subtag(self, new_subtag: str):
        """Update log subtag with new subtag."""
        self.subtag = new_subtag


class ServerLogger(WazuhLogger):
    """Define the logger used by the Server main process."""

    def setup_logger(self):
        """Set up server logger. In addition to super().setup_logger() this method adds:
        * A filter to add tag and subtags to server logs
        * Sets log level based on the "debug_level" parameter received from wazuh-server binary.
        """
        super().setup_logger()
        self.logger.addFilter(ServerFilter(tag='Server', subtag='Main'))
        debug_level = (
            logging.DEBUG2 if self.debug_level == 2 else logging.DEBUG if self.debug_level == 1 else logging.INFO
        )

        self.logger.setLevel(debug_level)


def ping_unix_socket(socket_path: Path, timeout: int = 1):
    """Ping a UNIX socket to check if it's available.

    Parameters
    ----------
    socket_path : Path
        Path to the UNIX socket file.
    timeout : int
        Connection timeout in seconds.

    Returns
    -------
    bool
        True if the socket is reachable, False otherwise.
    """
    if not socket_path.exists():
        return False

    try:
        # Create a testing UNIX socket client to connect to the server socket.
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(timeout)
        client.connect(str(socket_path))
        client.close()
        return True
    except (socket.timeout, socket.error):
        return False


def print_version():
    """Return Wazuh version from metadata."""
    from wazuh.core.server import __author__, __licence__, __version__, __wazuh_name__

    print('\n{} {} - {}\n\n{}'.format(__wazuh_name__, __version__, __author__, __licence__))


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
        Dict whose keys are daemons and the values are the status.
    """
    # Check /proc directory availability
    proc_path = '/proc'
    try:
        os.stat(proc_path)
    except (PermissionError, FileNotFoundError) as e:
        raise WazuhInternalError(1913, extra_message=str(e))

    processes = ['wazuh-server', 'wazuh-engined', 'wazuh-server-management-apid', 'wazuh-comms-apid']

    data, pidfile_regex, run_dir = {}, re.compile(r'.+\-(\d+)\.pid$'), common.WAZUH_RUN
    for process in processes:
        pidfile = glob(os.path.join(run_dir, f'{process}-*.pid'))
        if os.path.exists(os.path.join(run_dir, f'{process}.failed')):
            data[process] = 'failed'
        elif os.path.exists(os.path.join(run_dir, '.restart')):
            data[process] = 'restarting'
        elif os.path.exists(os.path.join(run_dir, f'{process}.start')):
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


def manager_restart() -> WazuhResult:
    """Restart Wazuh manager.

    Send JSON message with the 'restart-wazuh' command to common.EXECQ_SOCKET socket.

    Raises
    ------
    WazuhInternalError(1901)
        If the socket path doesn't exist.
    WazuhInternalError(1902)
        If there is a socket connection error.
    WazuhInternalError(1014)
        If there is a socket communication error.

    Returns
    -------
    WazuhResult
        Confirmation message.
    """
    lock_file = open(EXECQ_LOCKFILE, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        # execq socket path
        socket_path = common.EXECQ_SOCKET
        # json msg for restarting Wazuh manager
        msg = json.dumps(
            create_wazuh_socket_message(
                origin={'module': common.origin_module.get()},
                command=common.RESTART_WAZUH_COMMAND,
                parameters={'extra_args': [], 'alert': {}},
            )
        )
        # initialize socket
        if os.path.exists(socket_path):
            try:
                conn = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                conn.connect(socket_path)
            except socket.error:
                raise WazuhInternalError(1902)
        else:
            raise WazuhInternalError(1901)

        try:
            conn.send(msg.encode())
            conn.close()
        except socket.error as e:
            raise WazuhInternalError(1014, extra_message=str(e))
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()

    return WazuhResult({'message': 'Restart request sent'})
