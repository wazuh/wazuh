import logging
from contextvars import ContextVar

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
