# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from wazuh.exception import WazuhError
from wazuh.rbac.auth_context import RBAChecker


class PreProcessor:
    def __init__(self):
        self.odict = dict()

    def remove_previous_elements(self, resource, action, combination=False):
        """Remove previous incompatible resources

        :param resource: Resource to be deleted
        :param action: Action that covers the resource
        :param combination: this flags indicate if the resource is a combination of resources
        """
        if len(resource) > 1:  # Combination
            for actual_resource in list(self.odict[action].keys()):
                actual_split_resource = actual_resource.split('&')
                if len(actual_split_resource) == len(resource):  # It's possible they're the same
                    counter = 0
                    for actual, new in zip(actual_split_resource, resource):
                        new_split = new.split(':')
                        if new_split[-1] == '*' or actual == new:
                            counter += 1
                    if counter == len(actual_split_resource):
                        self.odict[action].pop(actual_resource)
        else:  # Individual
            result = self.odict[action].pop(resource[0], False)
            if not result:
                split_resource = resource[0].split(':')
                if split_resource[-1] == '*':
                    for key in list(self.odict[action].keys()):
                        resource_name = ':'.join(resource[0].split(':')[0:-1]) if len(split_resource) > 1 else '*:*:*'
                        if (key.startswith(resource_name) or key.startswith('agent:group')) \
                                and len(key.split('&')) == 1:
                            self.odict[action].pop(key)

    @staticmethod
    def is_combination(resource):
        split_resource = resource.split('&')
        if len(split_resource) > 1:
            return True, split_resource

        return False, [resource]

    def process_policy(self, policy):
        """Receives an unprocessed policy and transforms it into a specific format for
        treatment in the decorator.

        :param policy: Policy of the user
        """
        resource_regex = \
            r'^(\*)|' \
            r'(([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*]+\&)+([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*]+))|' \
            r'([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*]+)$'
        for action in policy['actions']:
            if action not in self.odict.keys():
                self.odict[action] = dict()
            for resource in policy['resources']:
                if not re.match(resource_regex, resource):
                    raise WazuhError(4999)
                resource_type = PreProcessor.is_combination(resource)
                if len(resource_type[1]) > 2:
                    raise WazuhError(4998)
                resource = resource_type[1] if resource != '*' else ['*:*:*']
                self.remove_previous_elements(resource, action, resource_type[0])
                self.odict[action]['&'.join(resource)] = policy['effect']

    def get_optimize_dict(self):
        """This function preprocess the policies of the user for a more easy treatment
        in the decorator of the RBAC
        """
        return self.odict


def optimize_resources():
    """This function preprocess the policies of the user for a more easy treatment in the decorator of the RBAC
    """
    # For production
    rbac = RBAChecker(auth_context='{}')
    policies = rbac.run()

    # Testing
    policies = RBAChecker.run_testing()

    preprocessor = PreProcessor()
    for policy in policies:
        preprocessor.process_policy(policy)

    return preprocessor.get_optimize_dict()
