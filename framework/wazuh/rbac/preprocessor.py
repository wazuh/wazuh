# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.rbac.auth_context import RBAChecker


need_clean = dict()


class PreProcessor:
    def __init__(self):
        self.need_clean = dict()
        self.odict = dict()

    def remove_previous_elements(self, resource, action):
        """Remove previous incompatible resources

        :param resource: Resource to be deleted
        :param action: Action that covers the resource
        """
        split_resource = resource.split(':')
        resource_name = ':'.join(resource.split(':')[0:-1]) if len(split_resource) > 1 else '*:*:*'
        if split_resource[-1] == '*':
            for key in list(self.odict[action].keys()):
                if key.startswith(resource_name) or key.startswith('agent:group'):
                    self.odict[action].pop(key)
        else:
            self.odict[action].pop(resource, None)

    def process_policy(self, policy):
        """Receives an unprocessed policy and transforms it into a specific format for
        treatment in the decorator.

        :param policy: Policy of the user
        """
        for action in policy['actions']:
            if action not in self.odict.keys():
                self.odict[action] = dict()
            for resource in policy['resources']:
                resource = resource if resource != '*' else '*:*:*'
                self.remove_previous_elements(resource, action)
                self.odict[action][resource] = policy['effect']

    def get_optimize_dict(self):
        """This function preprocess the policies of the user for a more easy treatment
        in the decorator of the RBAC
        """
        return self.odict


def optimize_resources():
    """This function preprocess the policies of the user for a more easy treatment in the decorator of the RBAC
    """
    # For production
    # rbac = RBAChecker(auth_context='{}')
    # policies = rbac.run()

    # Testing
    policies = RBAChecker.run_testing()

    preprocessor = PreProcessor()
    for policy in policies:
        preprocessor.process_policy(policy)

    return preprocessor.get_optimize_dict()
