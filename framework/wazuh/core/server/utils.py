import logging
import socket
from contextvars import ContextVar
from pathlib import Path

from wazuh.core.wlogging import WazuhLogger

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
