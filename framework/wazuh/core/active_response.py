# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from wazuh.core import common
from wazuh.core.agent import Agent
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError
from wazuh.core.utils import WazuhVersion
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.wazuh_socket import create_wazuh_socket_message


def get_commands() -> list:
    """Get the available commands.

    Returns
    -------
    list
        List with the available commands.
    """
    commands = list()
    with open(common.AR_CONF) as f:
        for line in f:
            cmd = line.split(" - ")[0]
            commands.append(cmd)

    return commands


def get_command_names(command: str) -> list:
    """Get the names that ar.conf gives to the active responses that use a command.

    ar.conf names each active response as the command name followed by its timeout, so a command used by several
    active responses with different timeouts has several names.

    Parameters
    ----------
    command : str
        Command name as defined in the configuration, without the timeout.

    Returns
    -------
    list
        Sorted list with the names of ar.conf for the command.
    """
    names = set()
    with open(common.AR_CONF) as f:
        for line in f:
            fields = line.split(" - ")
            if fields[0] == command + fields[-1].strip():
                names.add(fields[0])

    return sorted(names)


def shell_escape(command: str) -> str:
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


class ARMessageBuilder:
    @staticmethod
    def can_handle(agent_version: str) -> bool:
        """Check if the message builder can handle the given agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        bool
            True if the message builder can handle the agent version, False otherwise.
        """
        raise NotImplementedError

    def create_message(self, command: str = '', arguments: list = None, alert: dict = None) -> str:
        """Create the message with the Active Response format that will be sent to the socket.

        Parameters
        ----------
        command : str
            Command running in the agent. If this value starts with !, then it refers to a script name instead of a
            command name.
        arguments : list
            Command arguments.
        alert : dict
            Alert data that will be sent with the AR command.

        Returns
        -------
        str
            Message that will be sent to the socket.
        """
        raise NotImplementedError

    @classmethod
    def choose_builder(cls, agent_version: str):
        """Choose the appropriate message builder based on the agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        ARMessageBuilder
            An instance of the chosen message builder.

        Raises
        ------
        WazuhError(1000)
            If no suitable message builder is found for the agent version.
        """

        for subclass in cls.__subclasses__():
            if subclass.can_handle(agent_version):
                return subclass()

        raise WazuhError(1000, "No suitable message builder found for agent version: {}".format(agent_version))

    def validate_command(self, command: str) -> str:
        """Validate the command for Active Response and resolve the name to send to the agent.

        Parameters
        ----------
        command : str
            Command running in the agent. It can be the name that ar.conf gives to the active response (command name
            followed by its timeout), the name of a command defined in the configuration if it is used by a single
            active response, or a script name preceded by !.

        Returns
        -------
        str
            Command name that the agent resolves.

        Raises
        ------
        WazuhError(1650)
            If the command is not specified.
        WazuhError(1652)
            If the command is not custom and the command is not one of the available commands.
        WazuhError(1653)
            If the command is used by several active responses with different timeouts.
        """
        if not command:
            raise WazuhError(1650)

        if command.startswith('!') or command in get_commands():
            return command

        names = get_command_names(command)
        if not names:
            raise WazuhError(1652)
        if len(names) > 1:
            raise WazuhError(1653, extra_remediation=', '.join(names))

        return names[0]


class ARStrMessage(ARMessageBuilder):
    @staticmethod
    def can_handle(agent_version: str) -> bool:
        """Check if the ARStrMessage can handle the given agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        bool
            True if ARStrMessage can handle the agent version, False otherwise.
        """
        return WazuhVersion(agent_version) < WazuhVersion(common.AR_LEGACY_VERSION)

    def create_message(self, command: str = '', arguments: list = None, alert: dict = None) -> str:
        """Create the message with the Active Response format that will be sent to the socket.

        Parameters
        ----------
        command : str
            Command running in the agent. If this value starts with !, then it refers to a script name instead of a command
            name.
        arguments : list
            Command arguments.
        alert : dict
            Alert data that will be sent with the AR command.

        Raises
        ------
        WazuhError(1650)
            If the command is not specified.
        WazuhError(1652)
            If the command is not custom and the command is not one of the available commands.
        WazuhError(1653)
            If the command is used by several active responses with different timeouts.

        Returns
        -------
        str
            Message that will be sent to the socket.
        """
        command = self.validate_command(command)

        msg_queue = command
        msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) if arguments else " - -"

        return msg_queue


class ARJsonMessage(ARMessageBuilder):
    @staticmethod
    def can_handle(agent_version: str) -> bool:
        """Check if the ARJsonMessage can handle the given agent version.

        Parameters
        ----------
        agent_version : str
            The version of the agent.

        Returns
        -------
        bool
            True if ARJsonMessage can handle the agent version, False otherwise.
        """
        return WazuhVersion(agent_version) >= WazuhVersion(common.AR_LEGACY_VERSION)

    def create_message(self, command: str = '', arguments: list = None, alert: dict = None) -> str:
        """Create the message with the Active Response format that will be sent to the socket.

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
        WazuhError(1652)
            If the command is not custom and the command is not one of the available commands.
        WazuhError(1653)
            If the command is used by several active responses with different timeouts.

        Returns
        -------
        str
            Message that will be sent to the socket.
        """
        command = self.validate_command(command)

        cluster_enabled = not read_cluster_config()['disabled']
        node_name = get_node().get('node') if cluster_enabled else None

        msg_queue = json.dumps(
            create_wazuh_socket_message(origin={'name': node_name, 'module': common.origin_module.get()},
                                        command=command,
                                        parameters={'extra_args': arguments if arguments else [],
                                                    'alert': alert if alert else {}}))

        return msg_queue


def send_ar_message(agent_id: str = '', agent_version = '', wq: WazuhQueue = None, command: str = '',
                    arguments: list = None, alert: dict = None) -> None:
    """Send the active response message to the agent.

    Parameters
    ----------
    agent_id : str
        ID specifying the agent where the msg_queue will be sent to.
    agent_version : str
        Agent version.
    wq : WazuhQueue
        Used for the active response messages.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Raises
    ------
    WazuhError(1750)
        If active response is disabled in the specified agent.
    """
    # Check if AR is enabled
    agent_conf = Agent(agent_id).get_config('com', 'active-response', agent_version)
    if agent_conf['active-response']['disabled'] == 'yes':
        raise WazuhError(1750)

    # Create classic msg or JSON msg depending on the agent version
    message_builder = ARMessageBuilder.choose_builder(agent_version)
    msg_queue = message_builder.create_message(command=command, arguments=arguments, alert=alert)

    wq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=WazuhQueue.AR_TYPE)
