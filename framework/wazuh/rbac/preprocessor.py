# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from wazuh.core.exception import WazuhError
from wazuh.rbac.auth_context import RBAChecker
from wazuh.rbac.orm import AuthenticationManager
from wazuh.core.results import WazuhResult


class PreProcessor:
    def __init__(self):
        self.odict = dict()

    def remove_previous_elements(self, resource, action):
        """Remove previous incompatible resources

        :param resource: New resource that will be compared with the previous ones
        :param action: Action that covers the new resource
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
        else:  # Single
            self.odict[action].pop(resource[0], None)
            split_resource = resource[0].split(':')
            if split_resource[-1] == '*':
                for key in list(self.odict[action].keys()):
                    resource_name = ':'.join(resource[0].split(':')[0:-1]) if len(split_resource) > 1 else '*:*:*'
                    if (key.startswith(resource_name) or key.startswith('agent:group')) \
                            and len(key.split('&')) == 1:
                        self.odict[action].pop(key)

    @staticmethod
    def is_combination(resource):
        """This function checks whether a given resource is a combination or not.

        :param resource: Resource to be checked
        :return Tuple with a flag that indicates whether it is a combination or not and if so,
        the list of separate resources
        """
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
            r'(([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*/-]+\&)+' \
            r'([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*/-]+))|' \
            r'([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*/-]+)$'
        for action in policy['actions']:
            if action not in self.odict.keys():
                self.odict[action] = dict()
            for resource in policy['resources']:
                if not re.match(resource_regex, resource):
                    raise WazuhError(4500)
                resource_type = PreProcessor.is_combination(resource)
                if len(resource_type[1]) > 2:
                    raise WazuhError(4500, extra_remediation="The maximum length for permission combinations is two")
                resource = resource_type[1] if resource != '*' else ['*:*:*']
                self.remove_previous_elements(resource, action)
                self.odict[action]['&'.join(resource)] = policy['effect']

    def get_optimize_dict(self):
        """This function preprocess the policies of the user for a more easy treatment
        in the decorator of the RBAC
        """
        return self.odict


def optimize_resources(auth_context=None, user_id=None):
    """This function preprocess the policies of the user for a more easy treatment in the decorator of the RBAC

    :param auth_context: Authorization context of the current user
    :param user_id: Username of the current user
    """
    # For production
    rbac = RBAChecker(auth_context=auth_context)
    # Authorization Context method
    if auth_context:
        policies = rbac.run_auth_context()
    # User-role link method
    else:
        policies = rbac.run_user_role_link(user_id)

    preprocessor = PreProcessor()
    for policy in policies:
        preprocessor.process_policy(policy)

    return preprocessor.get_optimize_dict()


def get_permissions(user_id=None, auth_context=None):
    with AuthenticationManager() as auth:
        if auth.user_auth_context(user_id):
            # Add dummy rbac_policies for developing here
            return WazuhResult(optimize_resources(auth_context=auth_context))

    return WazuhResult(optimize_resources(user_id=user_id))
