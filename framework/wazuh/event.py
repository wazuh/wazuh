from wazuh.core.common import QUEUE_SOCKET
from wazuh.core.results import WazuhResult
from wazuh.core.wazuh_queue import WazuhAnalysisdQueue
from wazuh.rbac.decorators import expose_resources

MSG_HEADER = '1:API-Webhook:'


@expose_resources(actions=["event:ingest"], resources=["*:*:*"], post_proc_func=None)
def send_event_to_analysisd(events: list) -> WazuhResult:
    """_summary_

    Parameters
    ----------
    events : list
        _description_

    Returns
    -------
    WazuhResult
        _description_
    """

    with WazuhAnalysisdQueue(QUEUE_SOCKET) as queue:
        for event in events:
            queue.send_msg(msg_header=MSG_HEADER, msg=event)

    return WazuhResult({'message': 'The events were forwarded to analisysd'})
