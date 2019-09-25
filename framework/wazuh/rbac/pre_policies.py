# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.rbac.auth_context import RBAChecker


need_clean = dict()


def cleaner(odict):
    global need_clean
    actions_to_pop = set()
    if len(need_clean.keys()) > 0:
        for action, resources in need_clean.items():
            for resource in resources:
                odict[action].pop(resource)
            if len(odict[action].keys()) == 0:
                actions_to_pop.add(action)
        for action in actions_to_pop:
            odict.pop(action)
        need_clean = dict()


def mark_previous_elements(resource, action, odict):
    global need_clean
    resource_name = ':'.join(resource.split(':')[0:-1])
    for key in odict[action].keys():
        if key.startswith(resource_name) or key.startswith('agent:group'):
            if action not in need_clean.keys():
                need_clean[action] = list()
            need_clean[action].append(key)


def modify_odict(resources, effect, action, odict):
    for resource in resources:
        if resource.split(':')[-1] == '*':
            mark_previous_elements(resource, action, odict)
        odict[action][resource] = effect


def process_policy(policy, odict):
    for action in policy['actions']:
        if action not in odict.keys():
            odict[action] = dict()
        modify_odict(policy['resources'], policy['effect'], action, odict)


def optimize_resources():
    # For production
    # rbac = RBAChecker(auth_context='AUTHORIZATION CONTEXT (JSON)')
    # policies = rbac.run()

    # Testing
    policies = RBAChecker.run_testing()
    odict = dict()
    for policy in policies:
        process_policy(policy, odict)
    cleaner(odict)

    return odict

