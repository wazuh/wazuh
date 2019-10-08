# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.rbac.auth_context import RBAChecker


need_clean = dict()


class PreProcessor:
    def __init__(self, odict):
        self.need_clean = dict()
        self.odict = odict

    def remove_previous_elements(self, resource, action):
        resource_name = ':'.join(resource.split(':')[0:-1])
        if resource.split(':')[-1] == '*':
            for key in list(self.odict[action].keys()):
                if key.startswith(resource_name) or key.startswith('agent:group'):
                    self.odict[action].pop(key)
        else:
            self.odict[action].pop(resource, None)

    def process_policy(self, policy):
        for action in policy['actions']:
            if action not in self.odict.keys():
                self.odict[action] = dict()
            for resource in policy['resources']:
                self.remove_previous_elements(resource, action)
                self.odict[action][resource] = policy['effect']

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

    return preprocessor.get_optimize_dict()
