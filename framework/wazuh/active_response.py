# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.fcore import active_response
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=['active_response:command'], resources='agent:id:{agent_id}')
def run_command(agent_id=None, command=None, arguments=None, custom=False):
    """Run AR command in a specific agent

    :param agent_id: Run AR command in the agent.
    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :param custom: Whether the specified command is a custom command or not
    :param arguments: Command arguments
    :return: WazuhResult.
    """
    msg_queue = active_response.create_message(command=command, arguments=arguments, custom=custom)

    return active_response.send_command(msg_queue=msg_queue, agent_id=agent_id)


@expose_resources(actions=['active_response:command'], resources='agent:id:*')
def run_command_all(command=None, arguments=None, custom=False):
    """Run AR command in a specific agent

    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :param custom: Whether the specified command is a custom command or not
    :param arguments: Command arguments
    :return: WazuhResult.
    """
    msg_queue = active_response.create_message(command=command, arguments=arguments, custom=custom)

    return active_response.send_command(msg_queue=msg_queue, agent_id=None)
