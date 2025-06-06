from json import dumps, loads
from wazuh.core.common import ANALYSISD_SOCKET
from wazuh.core.wazuh_socket import create_wazuh_socket_message, WazuhSocket

RELOAD_RULESET_COMMAND = "reload-ruleset"

def send_reload_ruleset_msg(origin: dict[str, str]) -> dict:
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

    socket = WazuhSocket(ANALYSISD_SOCKET)
    socket.send(dumps(msg).encode())

    data = loads(socket.receive().decode())
    socket.close()

    return data
