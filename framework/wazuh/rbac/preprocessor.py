# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from typing import Union

from wazuh.core.common import rbac_manager
from wazuh.core.exception import WazuhError, WazuhPermissionError
from wazuh.core.indexer.models.rbac import Policy, Role
from wazuh.core.rbac import RBACManager
from wazuh.core.results import WazuhResult
from wazuh.rbac.auth_context import RBAChecker


class PreProcessor:
    """Transform, optimize and sanitize the information before its evaluation."""

    def __init__(self):
        self.odict = dict()

    def remove_previous_elements(self, resource: str, action: str):
        """Remove previous incompatible resources.

        Parameters
        ----------
        resource : str
            New resource that will be compared with the previous ones.
        action : str
            Action that covers the new resource.
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
                    if (key.startswith(resource_name) or key.startswith('agent:group')) and len(key.split('&')) == 1:
                        self.odict[action].pop(key)

    @staticmethod
    def is_combination(resource: str) -> tuple:
        """Check whether a given resource is a combination or not.

        resource : str
            Resource to be checked.

        Returns
        -------
        tuple
            Tuple with a flag that indicates whether it is a combination or not and if so, the list of separate
            resources.
        """
        split_resource = resource.split('&')
        if len(split_resource) > 1:
            return True, split_resource

        return False, [resource]

    def process_policy(self, policy: Policy):
        """Receive an unprocessed policy and transforms it into a specific format for treatment in the decorator.

        Parameters
        ----------
        policy : dict
            Policy of the user.

        Raises
        ------
        WazuhError(4500)
            The specified resources are invalid.
        """
        resource_regex = (
            r'^(\*)|'
            r'(([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*/-]+\&)+'
            r'([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*/-]+))|'
            r'([a-zA-Z0-9_.]+:[a-zA-Z0-9_.]+:[a-zA-Z0-9_.*/-]+)$'
        )
        for action in policy.actions:
            if action not in self.odict.keys():
                self.odict[action] = dict()
            for resource in policy.resources:
                if not re.match(resource_regex, resource):
                    raise WazuhError(4500)
                resource_type = PreProcessor.is_combination(resource)
                if len(resource_type[1]) > 2:
                    raise WazuhError(4500, extra_remediation='The maximum length for permission combinations is two')
                resource = resource_type[1] if resource != '*' else ['*:*:*']
                self.remove_previous_elements(resource, action)
                self.odict[action]['&'.join(resource)] = policy.effect

    def get_optimized_dict(self) -> dict:
        """Get the optimized dictionary.

        Returns
        -------
        dict
            Optimized dictionary.
        """
        return self.odict


def optimize_resources(roles: list[Role] = None) -> dict:
    """Preprocess the policies of the user for a more easy treatment in the decorator of the RBAC.

    Parameters
    ----------
    roles : list[Role]
        Roles of the current user.

    Returns
    -------
    dict
        Final dictionary.
    """
    preprocessor = PreProcessor()
    for role in roles:
        for policy in role.policies:
            preprocessor.process_policy(policy)

    return preprocessor.get_optimized_dict()


async def get_roles(rbac_manager: RBACManager, auth_context: Union[dict, str] = None, user_id: int = None) -> list[str]:
    """Obtain the roles of a user using auth_context or user_id.

    Parameters
    ----------
    rbac_manager : RBACManager
        RBAC manager.
    auth_context : dict or str
        Authorization context of the current user.
    user_id : int
        Username of the current user.

    Returns
    -------
    list[Role]
        List of roles.
    """
    user = rbac_manager.get_user_by_name(user_id)
    rbac = RBAChecker(rbac_manager=rbac_manager, auth_context=auth_context, user_id=user.id)

    # Authorization Context method
    if auth_context:
        roles = rbac.run_auth_context_roles()
    # User-role link method
    else:
        roles = rbac.run_user_role_link_roles(user.id)

    return [role.name for role in roles]


async def get_permissions(user_id: int = None, auth_context: Union[dict, str] = None) -> WazuhResult:
    """Obtain the permissions of a user using auth_context or user_id.

    Parameters
    ----------
    auth_context : dict or str
        Authorization context of the current user.
    user_id : int
        Username of the current user.

    Raises
    ------
    WazuhPermissionError(6004)
        If the current user does not have authentication enabled through authorization context.

    Returns
    -------
    WazuhResult
        WazuhResult object with the user permissions.
    """
    manager: RBACManager = rbac_manager.get()

    user = manager.get_user_by_name(user_id)
    if not user.allow_run_as and auth_context:
        raise WazuhPermissionError(6004)
    elif user.allow_run_as:
        roles = await get_roles(rbac_manager=manager, auth_context=auth_context, user_id=user_id)
    else:
        roles = await get_roles(rbac_manager=manager, user_id=user_id)

    return WazuhResult({'roles': roles})
