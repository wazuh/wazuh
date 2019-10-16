# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import common
from wazuh.core import active_response
from wazuh.ossec_queue import OssecQueue
from wazuh.rbac.decorators import expose_resources, list_handler_no_denied, list_handler_with_denied
from wazuh.exception import WazuhException, create_exception_dic


@expose_resources(actions=['active_response:command'], resources=['agent:id:{agent_list}'])
def run_command(agent_list=None, command=None, arguments=None, custom=False):
    """Run AR command in a specific agent

    :param agent_list: Run AR command in the agent.
    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :param custom: Whether the specified command is a custom command or not
    :param arguments: Command arguments
    :return: WazuhResult.
    """
    msg_queue = active_response.create_message(command=command, arguments=arguments, custom=custom)
    oq = OssecQueue(common.ARQUEUE)
    affected_items = list()
    failed_items = list()
    for agent_id in agent_list:
        try:
            active_response.send_command(msg_queue, oq, agent_id)
            affected_items.append(agent_id)
        except WazuhException as e:
            failed_items.append(create_exception_dic(agent_id, e))
    oq.close()

    return {'affected_items': affected_items,
            'failed_items': failed_items,
            'str_priority': ['Command sent to all agents',
                             'Could not send command to some agents',
                             'Could not send command to any agent']}


@expose_resources(actions=['active_response:command'], resources=['agent:id:*'])
def run_command_all(agent_list=None, command=None, arguments=None, custom=False):
    """Run AR command in a specific agent

    :param agent_list: Run AR command in the agent.
    :param command: Command running in the agent. If this value starts by !, then it refers to a script name instead of
    a command name
    :param custom: Whether the specified command is a custom command or not
    :param arguments: Command arguments
    :return: WazuhResult.
    """
    msg_queue = active_response.create_message(command=command, arguments=arguments, custom=custom)
    oq = OssecQueue(common.ARQUEUE)
    affected_items = list()
    for agent_id in agent_list:
        try:
            active_response.send_command(msg_queue, oq, agent_id)
            affected_items.append(agent_id)
        except WazuhException:
            pass
    oq.close()

    return {'affected_items': affected_items,
            'failed_items': list(),
            'str_priority': ['Command sent to shown agents',
                             '',
                             'Could not send command to any agent']}
