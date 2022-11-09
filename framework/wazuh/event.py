import socket

from wazuh import WazuhError


def send_event_to_analysisd(event: str = ""):
    msg_header = "1:Wazuh-AWS:"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        s.connect("/var/ossec/queue/sockets/queue")
        s.send(f"{msg_header}{event}".encode())
    except Exception as e:
        raise WazuhError(1000, extra_message=str(e))
    finally:
        s.close()

    result = {"message": "ok"}
    return result
