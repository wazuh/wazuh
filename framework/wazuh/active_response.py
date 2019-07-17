

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.agent import Agent
from wazuh.exception import WazuhError
from wazuh.ossec_queue import OssecQueue
from wazuh.results import WazuhResult


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
    """Run AR command in a specific agent

    :param agent_id: Run AR command in the agent.
    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :type command: str
    :param custom: Whether the specified command is a custom command or not
    :type custom: bool
    :param arguments: Command arguments
    :type arguments: str

    :return: Message.
    """
    if not command:
        raise WazuhError(1650)

    commands = get_commands()
    if not custom and command not in commands:
        raise WazuhError(1652)

    # Create message
    msg_queue = command
    if custom:
        msg_queue = "!{}".format(command)

    if arguments:
        msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments)
    else:
        msg_queue += " - -"

    # Send
    if agent_id == "000":
        oq = OssecQueue(common.EXECQ)
        ret_msg = oq.send_msg_to_agent(msg=msg_queue, agent_id="000", msg_type=OssecQueue.AR_TYPE)
        oq.close()
    else:
        # Check if agent exists and it is active
        agent_info = Agent(agent_id).get_basic_information()

        if agent_info['status'].lower() != 'active':
            raise WazuhError(1651)

        # Check if agent has active-response disabled
        agent_conf = Agent.get_config(agent_id, 'com', 'active-response')
        if agent_conf['active-response']['disabled'] == 'yes':
            raise WazuhError(1750)
        else:
            oq = OssecQueue(common.ARQUEUE)
            ret_msg = oq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=OssecQueue.AR_TYPE)
            oq.close()

    return WazuhResult({'message': ret_msg})


def run_command_all(command=None, arguments=[], custom=False):
    """Run AR command in all agents

    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :type command: str
    :param custom: Whether the specified command is a custom command or not
    :type custom: bool
    :param arguments: Command arguments
    :type arguments: str

    :return: Message.
    """
    if not command:
        raise WazuhError(1650)

    commands = get_commands()
    if not custom and command not in commands:
        raise WazuhError(1652)

    # Create message
    msg_queue = command
    if custom:
        msg_queue = "!{}".format(command)

    if arguments:
        msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments)
    else:
        msg_queue += " - -"

    # Send
    oq = OssecQueue(common.ARQUEUE)
    oq.send_msg_to_agent(msg=msg_queue, agent_id=None, msg_type=OssecQueue.AR_TYPE)
    oq.close()

    return WazuhResult({'message': 'Command sent to all agents.'})
