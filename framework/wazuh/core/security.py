# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import os
from functools import lru_cache

import yaml
from wazuh.core.authentication import generate_keypair
from wazuh.rbac.orm import DB_FILE, RolesManager, TokenManager, check_database_integrity

from api import __path__ as api_path

REQUIRED_FIELDS = ['id']
SORT_FIELDS = ['id', 'name']
SORT_FIELDS_GET_USERS = ['id', 'username']


@lru_cache(maxsize=None)
def load_spec():
    with open(os.path.join(api_path[0], 'spec', 'spec.yaml'), 'r', encoding='utf-8') as stream:
        return yaml.safe_load(stream)


def check_relationships(roles: list = None) -> set:
    """Check the users related with the specified list of roles.

    Parameters
    ----------
    roles : list
        List of affected roles.

    Returns
    -------
    set
        Set with all affected users.
    """
    users_affected = set()
    if roles:
        for role in roles:
            with RolesManager() as rm:
                users_affected.update(set(rm.get_role_id(role)['users']))

    return users_affected


def invalid_run_as_tokens():
    """Add the necessary rules to invalidate all affected run_as's tokens."""
    with TokenManager() as tm:
        tm.add_user_roles_rules(run_as=True)


def invalid_users_tokens(users: list = None):
    """Add the necessary rules to invalidate all affected user's tokens.

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


def revoke_tokens() -> dict:
    """Revoke all tokens in current node.

    Returns
    -------
    dict
        Confirmation message.
    """
    generate_keypair()
    with TokenManager() as tm:
        tm.delete_all_rules()

    return {'result': 'True'}


def sanitize_rbac_policy(policy):
    # Sanitize actions
    if 'actions' in policy:
        policy['actions'] = [action for action in map(str.lower, policy['actions'])]

    # Sanitize resources
    if 'resources' in policy:
        for i, resource in enumerate(policy['resources']):
            sanitized_resources = list()
            for nested_resource in resource.split('&'):
                split_resource = nested_resource.split(':')
                sanitized_resources.append(':'.join([r.lower() for r in split_resource[:-1]] + split_resource[-1:]))

            policy['resources'][i] = '&'.join(sanitized_resources)

    # Sanitize effect
    if 'effect' in policy:
        policy['effect'] = policy['effect'].lower()


def rbac_db_factory_reset():
    """Reset the RBAC database to default values."""
    try:
        os.remove(DB_FILE)
    except FileNotFoundError:
        pass

    check_database_integrity()
    revoke_tokens()
    return {'reset': True}
