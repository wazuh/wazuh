# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import json

from wazuh.core import common
from wazuh.core.agent import Agent
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.utils import WazuhVersion
from wazuh.core.wazuh_socket import create_wazuh_socket_message


def create_message(command: str = '', custom: bool = False, arguments: list = None) -> str:
    """Create the message that will be sent.

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts with !, then it refers to a script name instead of a command
        name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.

    Raises
    ------
    WazuhError(1650)
        If the command is not specified.
    WazuhError(1652)
        If the command is not custom and the command is not one of the available commands.

    Returns
    -------
    str
        Message that will be sent to the socket.
    """
    if not command:
        raise WazuhError(1650)

    commands = get_commands()
    if not custom and command not in commands:
        raise WazuhError(1652)

    msg_queue = "!{}".format(command) if custom else command
    msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) if arguments else " - -"

    return msg_queue


def create_json_message(command: str = '', arguments: list = None, alert: dict = None) -> str:
    """Create the JSON message that will be sent. Function used when Wazuh agent version is >= 4.2.0.

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts by !, then it refers to a script name instead of a command
        name.
    arguments : list
        Command arguments.
    alert : dict
        Alert data that will be sent with the AR command.

    Raises
    ------
    WazuhError(1650)
        If the command is not specified.

    Returns
    -------
    str
        Message that will be sent to the socket.
    """
    if not command:
        raise WazuhError(1650)

    cluster_enabled = not read_cluster_config()['disabled']
    node_name = get_node().get('node') if cluster_enabled else None

    msg_queue = json.dumps(
        create_wazuh_socket_message(origin={'name': node_name, 'module': 'api/framework'}, command=command,
                                    parameters={'extra_args': arguments if arguments else [],
                                                'alert': alert if alert else {}}))

    return msg_queue


def send_ar_message(agent_id: str = '', wq: WazuhQueue = None, command: str = '', arguments: list = None,
                    custom: bool = False, alert: dict = None) -> None:
    """Send the active response message to the agent.

    Parameters
    ----------
    agent_id : str
        ID specifying the agent where the msg_queue will be sent to.
    wq : WazuhQueue
        WazuhQueue used for the active response messages.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Raises
    ------
    WazuhError(1651)
        If the agent with ID agent_id is not active.
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
    if WazuhVersion(agent_version) >= WazuhVersion(common.AR_LEGACY_VERSION):
        msg_queue = create_json_message(command=command, arguments=arguments, alert=alert)
    else:
        msg_queue = create_message(command=command, arguments=arguments, custom=custom)

    wq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=WazuhQueue.AR_TYPE)


def get_commands() -> list:
    """Get the available commands.

    Returns
    -------
    list
        List with the available commands.
    """
    commands = list()
    with open(common.ar_conf_path) as f:
        for line in f:
            cmd = line.split(" - ")[0]
            commands.append(cmd)

    return commands


def shell_escape(command: str = '') -> str:
    """Escape some characters in the command before sending it.

    Parameters
    ----------
    command : str
        Command running in the agent. If this value starts with !, then it refers to a script name instead of a
        command name.

    Returns
    -------
    str
        Command with escape characters.
    """
    shell_escapes = \
        ['"', '\'', '\t', ';', '`', '>', '<', '|', '#', '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')']
    for shell_esc_char in shell_escapes:
        command = command.replace(shell_esc_char, "\\" + shell_esc_char)

    return command
