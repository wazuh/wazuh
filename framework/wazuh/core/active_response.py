# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.ossec_queue import OssecQueue
from wazuh.core.exception import WazuhError
from wazuh.core.agent import Agent


def create_message(command, custom, arguments):
    """Create the message that will be sent

    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :param custom: Whether the specified command is a custom command or not
    :param arguments: Command arguments
    :return: WazuhResult.
    """
    if not command:
        raise WazuhError(1650)

    commands = get_commands()
    if not custom and command not in commands:
        raise WazuhError(1652)

    msg_queue = "!{}".format(command) if custom else command
    msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) if arguments else " - -"

    return msg_queue


def get_commands():
    """Gets the available commands"""
    ar_conf_path = '{0}/etc/shared/ar.conf'.format(common.ossec_path)

    commands = list()
    with open(ar_conf_path) as f:
        for line in f:
            cmd = line.split(" - ")[0]
            commands.append(cmd)

    return commands


def shell_escape(command):
    """Escapes some characters in the command before sending it

    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :return: Command with escapes characters
    """
    shell_escapes = \
        ['"', '\'', '\t', ';', '`', '>', '<', '|', '#', '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')']
    for shell_esc_char in shell_escapes:
        command = command.replace(shell_esc_char, "\\" + shell_esc_char)

    return command


def send_command(msg_queue, oq, agent_id):
    """Send the message to the agent

    :param msg_queue: Message previously created, contains what is necessary to launch the active response command
    in the agent.
    :param agent_id: Run AR command in the agent.
    :return: WazuhResult.
    """
    agent_info = Agent(agent_id).get_basic_information()
    if agent_info['status'].lower() != 'active':
        raise WazuhError(1651)
    agent_conf = Agent(agent_id).getconfig('com', 'active-response')
    if agent_conf['active-response']['disabled'] == 'yes':
        raise WazuhError(1750)
    oq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=OssecQueue.AR_TYPE)
