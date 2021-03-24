# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import socket
from typing import Union

from wazuh.core.exception import WazuhInternalError, WazuhError
from wazuh.core.wazuh_socket import create_wazuh_socket_message


class WazuhQueue:
    """
    WazuhQueue Object.
    """

    # Messages
    HC_SK_RESTART = "syscheck restart"  # syscheck restart
    RESTART_AGENTS = "restart-ossec0"  # Agents, not manager (000)
    RESTART_AGENTS_JSON = json.dumps(create_wazuh_socket_message(origin={'module': 'api/framework'},
                                                                 command="restart-wazuh0",
                                                                 parameters={"extra_args": [],
                                                                             "alert": {}}))  # Agents, not manager (000)

    # Types
    AR_TYPE = "ar-message"

    # Sizes
    OS_MAXSTR = 6144  # OS_SIZE_6144
    MAX_MSG_SIZE = OS_MAXSTR + 256

    def __init__(self, path):
        self.path = path
        self._connect()

    def _connect(self):
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.socket.connect(self.path)
            length_send_buffer = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            if length_send_buffer < WazuhQueue.MAX_MSG_SIZE:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, WazuhQueue.MAX_MSG_SIZE)
        except Exception:
            raise WazuhInternalError(1010, self.path)

    def _send(self, msg):
        try:
            sent = self.socket.send(msg)

            if sent == 0:
                raise WazuhInternalError(1011, self.path)
        except Exception:
            raise WazuhInternalError(1011, self.path)

    def close(self):
        self.socket.close()

    def send_msg_to_agent(self, msg: Union[str, dict] = '', agent_id: str = '', msg_type: str = '') -> str:
        """Send message to agent.

        Active-response
          Agents: /var/ossec/queue/alerts/ar
            - Existing command:
              - (msg_to_agent) [] NNS 001 restart-ossec0 arg1 arg2 arg3
              - (msg_to_agent) [] ANN (null) restart-ossec0 arg1 arg2 arg3
            - Custom command:
              - (msg_to_agent) [] NNS 001 !test.sh arg1 arg2 arg3
              - (msg_to_agent) [] ANN (null) !test.sh arg1 arg2 arg3
          Agents with version >= 4.2.0:
            - Existing and custom commands:
              - (msg_to_agent) [] NNS 001 {JSON message}
          Manager: /var/ossec/queue/alerts/execq
            - Existing or custom command:
              - {JSON message}

        Parameters
        ----------
        msg : str
            Message to be sent to the agent.
        agent_id : str
            ID of the agent we want to send the message to.
        msg_type : str
            Message type.

        Raises
        ------
        WazuhError(1652)
            If it was unable to run the command.
        WazuhInternalError(1012)
            If the message was invalid to queue.
        WazuhError(1601)
            If it was unable to run the syscheck scan on the agent because it is a non active agent.
        WazuhError(1702)
            If it was unable to restart the agent.

        Returns
        -------
        str
            Message confirming the message has been sent.
        """

        # Build message
        ALL_AGENTS_C = 'A'
        NONE_C = 'N'
        SPECIFIC_AGENT_C = 'S'
        NO_AR_C = '!'

        if agent_id:
            str_all_agents = NONE_C
            str_agent = SPECIFIC_AGENT_C
            str_agent_id = agent_id
        else:
            str_all_agents = ALL_AGENTS_C
            str_agent = NONE_C
            str_agent_id = "(null)"

        # AR
        if msg_type == WazuhQueue.AR_TYPE:

            if agent_id != "000":
                # Example restart 'msg': restart-ossec0 - null (from_the_server) (no_rule_id)
                socket_msg = "{0} {1}{2}{3} {4} {5}".format("(msg_to_agent) []", str_all_agents, NONE_C, str_agent,
                                                            str_agent_id, msg)
            elif agent_id == "000":
                socket_msg = msg

            # Send message
            try:
                self._send(socket_msg.encode())
            except Exception:
                raise WazuhError(1652)

            return "Command sent."

        # Legacy: Restart syscheck, restart agents
        else:
            if msg == WazuhQueue.HC_SK_RESTART:
                socket_msg = "{0} {1}{2}{3} {4} {5}".format("(msg_to_agent) []", str_all_agents, NO_AR_C, str_agent,
                                                            str_agent_id, WazuhQueue.HC_SK_RESTART)
            elif msg == WazuhQueue.RESTART_AGENTS or msg == WazuhQueue.RESTART_AGENTS_JSON:
                socket_msg = "{0} {1}{2}{3} {4} {5} - {6} (from_the_server) (no_rule_id)".format("(msg_to_agent) []",
                                                                                                 str_all_agents, NONE_C,
                                                                                                 str_agent,
                                                                                                 str_agent_id,
                                                                                                 msg, "null")
            else:
                raise WazuhInternalError(1012, msg)

            # Send message
            try:
                self._send(socket_msg.encode())
            except:
                if msg == WazuhQueue.HC_SK_RESTART:
                    if agent_id:
                        raise WazuhError(1601, "on agent")
                    else:
                        raise WazuhError(1601, "on all agents")
                elif msg == WazuhQueue.RESTART_AGENTS:
                    raise WazuhError(1702)

            # Return message
            if msg == WazuhQueue.HC_SK_RESTART:
                return "Restarting Syscheck on agent" if agent_id else "Restarting Syscheck on all agents"
            elif msg == WazuhQueue.RESTART_AGENTS:
                return "Restarting agent" if agent_id else "Restarting all agents"
