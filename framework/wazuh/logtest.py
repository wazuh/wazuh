# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
import json

from wazuh import WazuhError
from wazuh.core.logtest import send_logtest_msg


# TODO add RBAC
def get_logtest_output(**kwargs):
    """Get the logtest output after sending a JSON to its socket.

    Parameters
    ----------
    kwargs : dict of str
        Dict of parameters. They must be token, event, log_format and location.

    Raises
    ------
    WazuhError(7000)
        If there are more kwargs than expected.

    Returns
    -------
    dict
        Logtest result after analyzing the event.
    """
    for kwarg in kwargs.keys():
        if kwarg not in ['token', 'event', 'log_format', 'location']:
            # kwargs are not valid
            raise WazuhError(7000)

    response = send_logtest_msg(json.dumps({param: value for param, value in kwargs.items() if value is not None}))

    return json.loads(response)


def end_logtest_session(token: str = None):
    # TODO Core-team must confirm what kind of message will end the session
    raise NotImplemented
