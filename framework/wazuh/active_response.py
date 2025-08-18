# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import active_response, common
from wazuh.core.agent import get_agents_info, get_rbac_filters, WazuhDBQueryAgents
from wazuh.core.exception import WazuhException, WazuhError, WazuhResourceNotFound
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources


@expose_resources(actions=['active-response:command'], resources=['agent:id:{agent_list}'],
                  post_proc_kwargs={'exclude_codes': [1701]})
def run_command(agent_list: list = None, command: str = '', arguments: list = None,
                alert: dict = None) -> AffectedItemsWazuhResult:
    """Run AR command in a specific agent.

    Parameters
    ----------
    agent_list : list
        Agents list that will run the AR command.
    command : str
        Command running in the agents. If this value starts with !, then it refers to a script name instead of a
        command name.
    custom : bool
        Whether the specified command is a custom command or not.
    arguments : list
        Command arguments.
    alert : dict
        Alert information depending on the AR executed.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg='AR command was sent to all agents',
                                      some_msg='AR command was not sent to some agents',
                                      none_msg='AR command was not sent to any agent'
                                      )
    if agent_list:
        system_agents = get_agents_info()

        for agent_id in set(agent_list) - system_agents:
            result.add_failed_item(id_=agent_id, error=WazuhResourceNotFound(1701))

        rbac_filters = get_rbac_filters(system_resources=system_agents, permitted_resources=agent_list)

        with WazuhDBQueryAgents(select=['id', 'status', 'version'], query="id!=000", **rbac_filters) as db_query:
            agents = db_query.run()['items']

        with WazuhQueue(common.AR_SOCKET) as wq:
            for agent in agents:
                try:
                    if agent['status'] != 'active':
                        raise WazuhError(1707)
                    
                    agent_id = agent['id']
                    agent_version = agent['version']

                    active_response.send_ar_message(agent_id, agent_version, wq, command, arguments, alert)
                    result.affected_items.append(agent_id)
                    result.total_affected_items += 1
                except WazuhException as e:
                    result.add_failed_item(id_=agent['id'], error=e)
            result.affected_items.sort(key=int)

    return result
