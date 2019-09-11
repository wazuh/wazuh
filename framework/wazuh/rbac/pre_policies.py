# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.agent import Agent
from wazuh.rbac.auth_context import RBAChecker


def convert_to_json_serializable(optimize_policies):
    for key, value in optimize_policies.items():
        for key_resource, value_resource in value.items():
            for key_effect, key_value in value_resource.items():
                if not isinstance(key_value, list):
                    optimize_policies[key][key_resource][key_effect] = list(key_value)

    return optimize_policies


def create_initial_dict(mode, resource, odict):
    if mode:
        odict[resource] = {
            'allow': {'*'},
            'deny': set()
        }
    else:
        odict[resource] = {
            'allow': set(),
            'deny': {'*'}
        }

    return odict


def white_process(resource_value, effect, odict):
    if effect == 'allow':
        if resource_value in odict['deny']:
            odict['deny'].remove(resource_value)
        if resource_value == '*':
            odict['deny'].clear()
            odict['allow'].clear()
        if '*' not in odict['allow']:
            odict['allow'].add(resource_value)
    elif effect == 'deny':
        if resource_value in odict['allow']:
            odict['allow'].remove(resource_value)
        if resource_value == '*':
            odict['deny'].clear()
            odict['allow'].clear()
        if '*' not in odict['deny']:
            odict['deny'].add(resource_value)


def black_process(resource_value, effect, odict):
    if effect == 'deny':
        if resource_value in odict['allow']:
            odict['allow'].remove(resource_value)
        elif resource_value == '*':
            odict['allow'].clear()
            odict['deny'].clear()
        if '*' not in odict['deny']:
            odict['deny'].add(resource_value)
    elif effect == 'allow':
        if resource_value in odict['deny']:
            odict['deny'].remove(resource_value)
        elif resource_value == '*':
            odict['allow'].clear()
            odict['deny'].clear()
        if '*' not in odict['allow']:
            odict['allow'].add(resource_value)


def modify_odict(mode, action, resources, effect, odict):
    for resource in resources:
        resource_name = ':'.join(resource.split(':')[0:-1])
        resource_value = resource.split(':')[-1]
        if resource_name not in odict[action].keys():
            create_initial_dict(mode, resource_name, odict[action])

        if mode:
            black_process(resource_value, effect, odict[action][resource_name])
        else:
            white_process(resource_value, effect, odict[action][resource_name])


def process_policy(mode, policy, odict):
    for action in policy['actions']:
        if action not in odict.keys():
            odict[action] = dict()
        modify_odict(mode, action, policy['resources'], policy['effect'], odict)


def expand_permissions(mode, odict):
    agents = Agent.get_agents_overview()
    agents_ids = list()
    for agent in agents['items']:
        agents_ids.append(agent['id'])

    for action, resource in odict.items():
        for res, value in resource.items():
            if '*' in value['allow']:
                value['allow'] = agents_ids
                value['allow'] = [agent_id for agent_id in value['allow'] if agent_id not in value['deny']]
            elif '*' in value['deny']:
                value['deny'] = agents_ids
                value['deny'] = [agent_id for agent_id in value['deny'] if agent_id not in value['allow']]

            if mode:
                value['allow'] = [agent_id for agent_id in agents_ids if agent_id not in value['deny']]
            else:
                value['deny'] = [agent_id for agent_id in agents_ids if agent_id not in value['allow']]

    return odict


def optimize_resources(mode=False):
    # For production
    # rbac = RBAChecker(auth_context='AUTHORIZATION CONTEXT (JSON)')
    # policies = rbac.run()

    # Testing
    policies = RBAChecker.run_testing()

    odict = dict()
    for policy in policies:
        process_policy(mode, policy, odict)
    odict = expand_permissions(mode, odict)
    convert_to_json_serializable(odict)

    return odict
