import json
import socket

from wazuh.core.common import QUEUE_SOCKET
from wazuh.core.results import WazuhResult
from wazuh.rbac.decorators import expose_resources
from wazuh import WazuhError

MSG_HEADER = '1:API-Webhook:'


@expose_resources(actions=["event:ingest"], resources=["*:*:*"], post_proc_func=None)
def send_event_to_analysisd(events: list) -> WazuhResult:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    try:
        sock.connect(QUEUE_SOCKET)
        for event in events:
            sock.send(f'{MSG_HEADER}{json.dumps(event)}'.encode())
    except Exception as e:
        raise WazuhError(1000, extra_message=str(e))
    finally:
        sock.close()

    return WazuhResult({'message': 'The events were forwarded to analisysd'})
