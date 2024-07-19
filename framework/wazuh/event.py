# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.common import QUEUE_SOCKET
from wazuh.core.exception import WazuhError
from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
from wazuh.core.wazuh_queue import WazuhAnalysisdQueue
from wazuh.rbac.decorators import expose_resources

MSG_HEADER = '1:API-Webhook:'


@expose_resources(actions=["event:ingest"], resources=["*:*:*"], post_proc_func=None)
def send_event_to_analysisd(events: list) -> WazuhResult:
    """Send events to analysisd through the socket.

    Parameters
    ----------
    events : list
        List of events to send.

    Returns
    -------
    WazuhResult
        Confirmation message.
    """
    result = AffectedItemsWazuhResult(
        all_msg="All events were forwarded to analisysd",
        some_msg="Some events were forwarded to analisysd",
        none_msg="No events were forwarded to analisysd"
    )

    with WazuhAnalysisdQueue(QUEUE_SOCKET) as queue:
        for event in events:
            try:
                queue.send_msg(msg_header=MSG_HEADER, msg=event)
                result.affected_items.append(event)
            except WazuhError as error:
                result.add_failed_item(event, error=error)

    result.total_affected_items = len(result.affected_items)
    return result
