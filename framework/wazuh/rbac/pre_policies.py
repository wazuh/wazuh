# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

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


def list_manager(resource_value, effect, odict):
    if effect == 'allow':
        inverted_effect = 'deny'
    else:
        inverted_effect = 'allow'

    if resource_value in odict[inverted_effect]:
        odict[inverted_effect].remove(resource_value)
    if resource_value == '*':
        odict[inverted_effect].clear()
        odict[effect].clear()
    if '*' not in odict[effect]:
        odict[effect].add(resource_value)


def modify_odict(mode, action, resources, effect, odict):
    for resource in resources:
        resource_name = ':'.join(resource.split(':')[0:-1])
        resource_value = resource.split(':')[-1]
        if resource_name not in odict[action].keys():
            create_initial_dict(mode, resource_name, odict[action])

        list_manager(resource_value, effect, odict[action][resource_name])


def process_policy(mode, policy, odict):
    for action in policy['actions']:
        if action not in odict.keys():
            odict[action] = dict()
        modify_odict(mode, action, policy['resources'], policy['effect'], odict)


def optimize_resources(mode=False):
    # For production
    # rbac = RBAChecker(auth_context='AUTHORIZATION CONTEXT (JSON)')
    # policies = rbac.run()

    # Testing
    policies = RBAChecker.run_testing()

    odict = dict()
    for policy in policies:
        process_policy(mode, policy, odict)
    convert_to_json_serializable(odict)

    return odict
