import json
import socket

from wazuh import WazuhError

MSG_HEADER = '1:API-Webhook:'
SOCKET_PATH = '/var/ossec/queue/sockets/queue'  # TODO: find better way to get WAZUH_PATH


def send_event_to_analysisd(events: list) -> None:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        sock.connect(SOCKET_PATH)
        for event in events:
            sock.send(f'{MSG_HEADER}{json.dumps(event)}'.encode())
    except Exception as e:
        raise WazuhError(1000, extra_message=str(e))
    finally:
        sock.close()
