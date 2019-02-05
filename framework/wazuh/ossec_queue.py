#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.exception import WazuhException
from wazuh import common
import socket

class OssecQueue:
    """
    OssecQueue Object.
    """

    # Messages
    HC_SK_RESTART = "syscheck restart"  # syscheck and rootcheck restart
    RESTART_AGENTS = "restart-ossec0"  # Agents, not manager (000)

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
            if length_send_buffer < OssecQueue.MAX_MSG_SIZE:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, OssecQueue.MAX_MSG_SIZE)
        except:
            raise WazuhException(1010, self.path)

    def _send(self, msg):
        try:
            sent = self.socket.send(msg)

            if sent == 0:
                raise WazuhException(1011, self.path)
        except:
            raise WazuhException(1011, self.path)

    def close(self):
        self.socket.close()

    def send_msg_to_agent(self, msg, agent_id=None, msg_type=None):
        # Active-response
        #   Agents: /var/ossec/queue/alerts/ar
        #     - Existing command:
        #       - (msg_to_agent) [] NNS 001 restart-ossec0 arg1 arg2 arg3
        #       - (msg_to_agent) [] ANN (null) restart-ossec0 arg1 arg2 arg3
        #     - Custom command:
        #       - (msg_to_agent) [] NNS 001 !test.sh arg1 arg2 arg3
        #       - (msg_to_agent) [] ANN (null) !test.sh arg1 arg2 arg3
        #   Manager: /var/ossec/queue/alerts/execq
        #     - Existing command:
        #       - restart-ossec0 arg1 arg2 arg3
        #     - Custom command:
        #       - !test.sh Hello World

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
        if msg_type == OssecQueue.AR_TYPE:

            if not agent_id:
                raise WazuhException(1653)

            if agent_id != "000":
                # Example restart 'msg': restart-ossec0 - null (from_the_server) (no_rule_id)
                socket_msg = "{0} {1}{2}{3} {4} {5}".format("(msg_to_agent) []", str_all_agents, NONE_C, str_agent, str_agent_id, msg)
            elif agent_id == "000":
                socket_msg = msg

            # Send message
            try:
                self._send(socket_msg.encode())
            except:
                raise WazuhException(1652)

            return "Command sent."

        # Legacy: Restart syscheck, restart agents
        else:
            if msg == OssecQueue.HC_SK_RESTART:
                socket_msg = "{0} {1}{2}{3} {4} {5}".format("(msg_to_agent) []", str_all_agents, NO_AR_C, str_agent, str_agent_id, OssecQueue.HC_SK_RESTART)
            elif msg == OssecQueue.RESTART_AGENTS:
                socket_msg = "{0} {1}{2}{3} {4} {5} - {6} (from_the_server) (no_rule_id)".format("(msg_to_agent) []", str_all_agents, NONE_C, str_agent, str_agent_id, OssecQueue.RESTART_AGENTS, "null")
            else:
                raise WazuhException(1012, msg)

            # Send message
            try:
                self._send(socket_msg.encode())
            except:
                if msg == OssecQueue.HC_SK_RESTART:
                    if agent_id:
                        raise WazuhException(1601, "on agent")
                    else:
                        raise WazuhException(1601, "on all agents")
                elif msg == OssecQueue.RESTART_AGENTS:
                    raise WazuhException(1702)

            # Return message
            if msg == OssecQueue.HC_SK_RESTART:
                return "Restarting Syscheck/Rootcheck on agent" if agent_id else "Restarting Syscheck/Rootcheck on all agents"
            elif msg == OssecQueue.RESTART_AGENTS:
                return "Restarting agent" if agent_id else "Restarting all agents"
