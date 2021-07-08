# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from datetime import datetime

from wazuh.core import common
from wazuh.core.exception import WazuhInternalError, WazuhError
from wazuh.core.wazuh_socket import WazuhSocket


def get_daemons_stats_from_socket(agent_id, daemon):
    """Get a daemon stats from an agent or manager.

    Parameters
    ----------
    agent_id : string
        Id of the agent to get stats from.
    daemon : string
        Name of the service to get stats from.

    Returns
    -------
    Dict
        Object with daemon's stats.
    """
    if not agent_id or not daemon:
        raise WazuhError(1307)

    sockets_path = os.path.join(common.wazuh_path, "queue", "sockets")

    if str(agent_id).zfill(3) == '000':
        # Some daemons do not exist in agent 000
        if daemon in {'agent'}:
            raise WazuhError(1310)
        dest_socket = os.path.join(sockets_path, daemon)
        command = "getstate"
    else:
        dest_socket = os.path.join(sockets_path, "request")
        command = f"{str(agent_id).zfill(3)} {daemon} getstate"

    # Socket connection
    try:
        s = WazuhSocket(dest_socket)
    except Exception:
        raise WazuhInternalError(1121)

    # Send message
    s.send(command.encode())

    # Receive response
    try:
        rec_msg = s.receive().decode()
    except ValueError:
        raise WazuhInternalError(1118, extra_message="Data could not be received")

    s.close()

    # Format response
    try:
        data = json.loads(rec_msg)['data']
        [d.update((k, datetime.strptime(v, "%Y/%m/%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ"))
                  for k, v in d.items() if k in {'last_keepalive', 'last_ack'}) for d in data['data']]
        return data
    except Exception:
        rec_msg = rec_msg.split(" ", 1)[1]
        raise WazuhError(1117, extra_message=rec_msg)
