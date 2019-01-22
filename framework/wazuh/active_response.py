#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.exception import WazuhException
from wazuh.agent import Agent
from wazuh.ossec_queue import OssecQueue


def get_commands():
    ar_conf_path = '{0}/etc/shared/ar.conf'.format(common.ossec_path)

    commands = []
    with open(ar_conf_path) as f:
        for line in f:
            cmd = line.split(" - ")[0]
            commands.append(cmd)

    return commands


def shell_escape(command):
    """
    Escapes some characters in the command before sending it
    """
    shell_escapes = ['"', '\'', '\t', ';', '`', '>', '<', '|', '#', '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')']
    for shell_esc_char in shell_escapes:
        command = command.replace(shell_esc_char, "\\"+shell_esc_char)
    
    return command


def run_command(agent_id=None, command=None, arguments=[], custom=False):
    """
    Run AR command.

    :param agent_id: Run AR command in the agent.
    :return: Message.
    """
    if not command:
        raise WazuhException(1650, "Command not specified")

    if not agent_id:
        raise WazuhException(1650, "Agent ID not specified")

    commands = get_commands()
    if not custom and command not in commands:
        raise WazuhException(1650, "Command not available")

    # Create message
    msg_queue = command
    if custom:
        msg_queue = "!{}".format(command)

    if arguments:
        msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments)
    else:
        msg_queue += " - -"

    # Send
    if agent_id == "000" or agent_id == "all":
        oq = OssecQueue(common.EXECQ)
        ret_msg = oq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=OssecQueue.AR_TYPE)
        oq.close()

    if agent_id != "000" or agent_id == "all":

        if agent_id != "all":
            # Check if agent exists and it is active
            agent_info = Agent(agent_id).get_basic_information()

            if agent_info['status'].lower() != 'active':
                raise WazuhException(1651)

        if agent_id == "all":
            agent_id = None

        oq = OssecQueue(common.ARQUEUE)
        ret_msg = oq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=OssecQueue.AR_TYPE)
        oq.close()

    return ret_msg
