import os
from json import dumps, loads
from typing import List

from wazuh.core import common
from wazuh.core.wazuh_socket import create_wazuh_socket_message, WazuhSocket

RELOAD_RULESET_COMMAND = "reload-ruleset"

def is_ruleset_file(filename: str) -> bool:
    """Check if a file belongs to the ruleset directories.

    Determines if the given filename is located inside any of the ruleset directories:
    USER_LISTS_PATH, USER_RULES_PATH, or USER_DECODERS_PATH.

    If `filename` is already an absolute path and includes `common.WAZUH_PATH`, it will be normalized and used as is.
    Otherwise, it will be joined with `common.WAZUH_PATH`.

    Parameters
    ----------
    filename : str
        Relative or absolute path to the file to check.

    Returns
    -------
    bool
        True if the file is part of the ruleset, False otherwise.
    """
    if os.path.isabs(filename):
        full_path = os.path.normpath(filename)
    else:
        full_path = os.path.normpath(os.path.join(common.WAZUH_PATH, filename))

    ruleset_paths = [
        os.path.normpath(common.USER_LISTS_PATH),
        os.path.normpath(common.USER_RULES_PATH),
        os.path.normpath(common.USER_DECODERS_PATH)
    ]

    return any(
        os.path.commonpath([full_path, path]) == path
        for path in ruleset_paths
    )

class RulesetReloadResponse:
    """
    Encapsulates the response from a ruleset reload operation.

    Parses the response dictionary returned by `send_reload_ruleset_msg` and provides
    access to success status, warnings, and errors.

    Attributes
    ----------
    success : bool
        True if the reload was successful, False otherwise.
    message : str
        Message returned in the response.
    warnings : list of str
        List of warning messages if present.
    errors : list of str
        List of error messages if present.
    """

    def __init__(self, response: dict):
        """
        Initialize a RulesetReloadResponse instance.

        Parameters
        ----------
        response : dict
            Response dictionary from `send_reload_ruleset_msg`.
        """
        self.success = response['error'] == 0
        self.message = response.get('message', '')

        self.warnings: List[str] = []
        self.errors: List[str] = []

        data = response.get('data', '')
        if self.success:
            self.warnings = data if len(data) > 0 else []
        else:
            self.errors = data if len(data) > 0 else []

    def has_warnings(self) -> bool:
        """
        Check if the response contains any warnings.

        Returns
        -------
        bool
            True if there are warnings, False otherwise.
        """
        return len(self.warnings) > 0

    def is_ok(self) -> bool:
        """
        Check if the reload operation was successful.

        Returns
        -------
        bool
            True if successful, False otherwise.
        """
        return self.success

def send_reload_ruleset_msg(origin: dict[str, str]) -> RulesetReloadResponse:
    """Send the reload ruleset command to Analysisd socket.

    Parameters
    ----------
    origin: dict[str, str]
        Origin of the message

    Returns
    -------
    dict
        Response from the socket
    """
    msg = create_wazuh_socket_message(origin=origin, command=RELOAD_RULESET_COMMAND)

    socket = WazuhSocket(common.ANALYSISD_SOCKET)
    socket.send(dumps(msg).encode())

    data = loads(socket.receive().decode())
    socket.close()

    return RulesetReloadResponse(data)
