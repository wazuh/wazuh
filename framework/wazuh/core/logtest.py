# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.wazuh_socket import OssecSocketJSON


def send_logtest_msg(msg: dict):
    """Connect and send a message to the logtest socket.

    Parameters
    ----------
    msg : dict
        Message that will be sent to the logtest socket.

    Returns
    -------
    dict
        Response from the logtest socket.
    """
    logtest_socket = OssecSocketJSON(common.LOGTEST_SOCKET)
    logtest_socket.send(msg)
    response = logtest_socket.receive(raw=True)
    logtest_socket.close()

    return response
