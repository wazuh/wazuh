# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from wazuh.core import common
from wazuh.core.ossec_socket import OssecSocket


def send_logtest_msg(msg: str):
    """Connect and send a message to the logtest socket.

    Parameters
    ----------
    msg : str
        Message that will be sent to the logtest socket.

    Returns
    -------
    str or dict
        Response from the logtest socket.
    """
    logtest_socket = OssecSocket(common.LOGTEST_SOCKET)
    logtest_socket.send(msg)
    data = logtest_socket.receive()
    logtest_socket.close()

    return data.rstrip(b'\x00').decode()
