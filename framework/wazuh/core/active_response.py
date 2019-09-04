# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.ossec_queue import OssecQueue
from wazuh.results import WazuhResult
from wazuh.exception import WazuhError


def create_message(command, custom, arguments):
    if not command:
        raise WazuhError(1650)

    commands = get_commands()
    if not custom and command not in commands:
        raise WazuhError(1652)

    msg_queue = "!{}".format(command) if custom else command
    msg_queue += " " + " ".join(shell_escape(str(x)) for x in arguments) if arguments else " - -"

    return msg_queue


def get_commands():
    ar_conf_path = '{0}/etc/shared/ar.conf'.format(common.ossec_path)

    commands = list()
    with open(ar_conf_path) as f:
        for line in f:
            cmd = line.split(" - ")[0]
            commands.append(cmd)

    return commands


def shell_escape(command):
    """Escapes some characters in the command before sending it"""
    shell_escapes = \
        ['"', '\'', '\t', ';', '`', '>', '<', '|', '#', '*', '[', ']', '{', '}', '&', '$', '!', ':', '(', ')']
    for shell_esc_char in shell_escapes:
        command = command.replace(shell_esc_char, "\\" + shell_esc_char)

    return command


def send_command(msg_queue, agent_id=None):
    oq = OssecQueue(common.ARQUEUE)
    ret_msg = oq.send_msg_to_agent(msg=msg_queue, agent_id=agent_id, msg_type=OssecQueue.AR_TYPE)
    oq.close()

    if agent_id is None:
        return WazuhResult({'message': 'Command sent to all agents.'})

    return WazuhResult({'message': ret_msg})
