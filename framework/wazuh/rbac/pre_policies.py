# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.rbac.auth_context import RBAChecker


need_clean = dict()


class PreProcessor:
    def __init__(self, odict):
        self.need_clean = dict()
        self.odict = odict

    def cleaner(self):
        actions_to_pop = set()
        if len(self.need_clean.keys()) > 0:
            for action, resources in self.need_clean.items():
                for resource in resources:
                    self.odict[action].pop(resource)
                if len(self.odict[action].keys()) == 0:
                    actions_to_pop.add(action)
            for action in actions_to_pop:
                self.odict.pop(action)
            self.need_clean = dict()

    def mark_previous_elements(self, resource, action):
        resource_name = ':'.join(resource.split(':')[0:-1])
        for key in self.odict[action].keys():
            if key.startswith(resource_name) or key.startswith('agent:group'):
                if action not in self.need_clean.keys():
                    self.need_clean[action] = list()
                self.need_clean[action].append(key)

    def modify_odict(self, resources, effect, action):
        for resource in resources:
            if resource.split(':')[-1] == '*':
                self.mark_previous_elements(resource, action)
            self.odict[action][resource] = effect

    def process_policy(self, policy):
        for action in policy['actions']:
            if action not in self.odict.keys():
                self.odict[action] = dict()
            self.modify_odict(policy['resources'], policy['effect'], action)

    def get_optimize_dict(self):
        return self.odict


def optimize_resources():
    # For production
    # rbac = RBAChecker(auth_context='AUTHORIZATION CONTEXT (JSON)')
    # policies = rbac.run()

    # Testing
    policies = RBAChecker.run_testing()
    preprocessor = PreProcessor(odict=dict())
    for policy in policies:
        preprocessor.process_policy(policy)
    preprocessor.cleaner()

    return preprocessor.get_optimize_dict()
