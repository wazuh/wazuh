# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.core import common
from wazuh.core.agent import Agent
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError
from wazuh.core.ossec_queue import OssecQueue
from wazuh.core.utils import WazuhVersion


def create_message(command, custom, arguments):
    """Create the message that will be sent

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts with !, then it refers to a script name instead of a command
        name
    custom : bool
        Whether the specified command is a custom command or not
    arguments : List[str]
        Command arguments

    Returns
    -------
    WazuhResult.
    """
    if not command:
        raise WazuhError(1650)

    commands = get_commands()
    if not custom and command not in commands:
        raise WazuhError(1652)

    msg_queue = "!{}".format(command) if custom else command
    msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) if arguments else " - -"

    return msg_queue


def create_json_message(command, arguments, alert):
    """Create the JSON message that will be sent. Function used when Wazuh agent version is >= 4.2.0

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts by !, then it refers to a script name instead of a command
        name
    arguments : List[str]
        Command arguments
    alert : dict
        Alert data that will be sent with the AR command

    Returns
    -------
    WazuhResult.
    """
    if not command:
        raise WazuhError(1650)

    cluster_enabled = not read_cluster_config()['disabled']
    node_name = get_node().get('node') if cluster_enabled else None

    msg_queue = {'version': 1, 'origin': {'name': node_name, 'module': 'api'}, 'command': command,
                 'parameters': {'extra_args': arguments if arguments else [], 'alert': alert if alert else {}}}

    return msg_queue


def send_ar_message(agent_id, oq, command, arguments, custom, alert):
    """Send the active response message to the agent.

    Parameters
    ----------
    agent_id : str
        ID specifying the agent where the msg_queue will be sent to
    oq : OssecQueue
        OssecQueue used for the active response messages
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a command name
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.
    """
    # Agent basic information
    agent_info = Agent(agent_id).get_basic_information()

    # Check if agent is active
    if agent_info['status'].lower() != 'active':
        raise WazuhError(1651, extra_message='{0}'.format(agent_info['status']))

    # Once we know the agent is active, store version
    agent_version = agent_info['version']

    # Check if AR is enabled
    agent_conf = Agent(agent_id).getconfig('com', 'active-response', agent_version)
    if agent_conf['active-response']['disabled'] == 'yes':
        raise WazuhError(1750)

    # Create classic msg or JSON msg depending on the agent version
    if WazuhVersion(agent_version) >= WazuhVersion('Wazuh v4.2.0'):
        msg_queue = create_json_message(command=command, arguments=arguments, alert=alert)
    else:
        msg_queue = create_message(command=command, arguments=arguments, custom=custom)

    oq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=OssecQueue.AR_TYPE)


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

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts by !, then it refers to a script name instead of a command
        name

    Returns
    -------
    command : str
        Command with escape characters
    """
    shell_escapes = \
        ['"', '\'', '\t', ';', '`', '>', '<', '|', '#', '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')']
    for shell_esc_char in shell_escapes:
        command = command.replace(shell_esc_char, "\\" + shell_esc_char)

    return command
