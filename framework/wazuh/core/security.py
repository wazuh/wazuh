# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import os
import yaml


import api.configuration as configuration
import api.middlewares as middlewares

from api.authentication import change_secret
from api.constants import SECURITY_CONFIG_PATH
from wazuh import WazuhInternalError, WazuhError
from wazuh.rbac.orm import RolesManager, TokenManager


def update_security_conf(new_config):
    """Update dict and write it in the configuration file.

    Parameters
    ----------
    new_config : dict
        Dictionary with the new configuration.
    """
    if new_config:
        try:
            with open(SECURITY_CONFIG_PATH, 'w+') as f:
                yaml.dump(new_config, f)
        except IOError:
            raise WazuhInternalError(1005)
    else:
        raise WazuhError(4021)
    if 'max_login_attempts' in new_config.keys():
        middlewares.ip_stats = dict()
        middlewares.ip_block = set()
    if 'max_request_per_minute' in new_config.keys():
        middlewares.request_counter = 0


def check_relationships(roles: list = None):
    """Check the users related with the specified list of roles

    Parameters
    ----------
    roles : list
        List of affected roles

    Returns
    -------
    Set with all affected users
    """
    users_affected = set()
    if roles:
        for role in roles:
            with RolesManager() as rm:
                users_affected.update(set(rm.get_role_id(role)['users']))

    return users_affected


def invalid_run_as_tokens():
    """Add the necessary rules to invalidate all affected run_as's tokens
    """
    with TokenManager() as tm:
        tm.add_user_roles_rules(run_as=True)


def invalid_users_tokens(users: list = None):
    """Add the necessary rules to invalidate all affected user's tokens

    Parameters
    ----------
    users : list
        List of modified users
    """
    with TokenManager() as tm:
        tm.add_user_roles_rules(users=set(users))


def invalid_roles_tokens(roles: list = None):
    """Add the necessary rules to invalidate all affected role's tokens

    Parameters
    ----------
    roles : list
        List of modified roles
    """
    with TokenManager() as tm:
        tm.add_user_roles_rules(roles=set(roles))


def revoke_tokens():
    """Revoke all tokens in current node."""
    change_secret()
    with TokenManager() as tm:
        tm.delete_all_rules()

    return {'result': 'True'}