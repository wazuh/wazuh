# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import os
from functools import lru_cache

import yaml

import api.middlewares as middlewares
from api import __path__ as api_path
from api.authentication import change_keypair
from api.constants import SECURITY_CONFIG_PATH
from wazuh import WazuhInternalError, WazuhError
from wazuh.core.decorators import dapi_allower
from wazuh.rbac.orm import AuthenticationManager, TokenManager, check_database_integrity, DB_FILE, \
    PreseededPasswordsError, load_preseeded_passwords

REQUIRED_FIELDS = ['id']
SORT_FIELDS = ['id', 'name']
SORT_FIELDS_GET_USERS = ['id', 'username']


@lru_cache(maxsize=None)
def load_spec():
    with open(os.path.join(api_path[0], 'spec', 'spec.yaml'), 'r', encoding='utf-8') as stream:
        return yaml.safe_load(stream)


def update_security_conf(new_config: dict):
    """Update dict and write it in the configuration file.

    Parameters
    ----------
    new_config : dict
        Dictionary with the new configuration.

    Raises
    ------
    WazuhInternalError(1005)
        Error reading security conf file.
    WazuhError(4021)
        No new_config provided.
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

@dapi_allower()
def revoke_tokens() -> dict:
    """Revoke all tokens in current node.

    Returns
    -------
    dict
        Confirmation message.
    """
    change_keypair()
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


@dapi_allower()
def ensure_rbac_database():
    """Create the RBAC database if it is missing, seeding it exactly as the first API start would.

    Exists so that a caller forwarding over the cluster protocol reaches the same seeding path, pre-seed
    file included, rather than leaving a node whose API has never run without a database. Exposed because
    a request made on a worker without `--local` is decoded on the master, which refuses a callable that
    is not marked.

    Guarded on the file being absent rather than always running `check_database_integrity()`, which also
    migrates the schema of an existing database and replaces it through `safe_move`. Changing a password
    must not carry that: a database that exists but is unusable is recovered by the API start that owns
    the migration, not here.

    Returns
    -------
    dict
        Confirmation message. Required, not optional: `forward_function` wraps the result in a
        `WazuhResult`, which rejects `None` with error 1000.
    """
    if not os.path.exists(DB_FILE):
        check_database_integrity()

    return {'ensured': True}


@dapi_allower()
def rbac_db_factory_reset():
    """Reset the RBAC database to default values.

    Exposed for the same reason as `ensure_rbac_database`: `rbac_control factory-reset` forwards it as a
    `local_master` request, which a worker sends to the master, and the master refuses to decode a
    callable that is not marked.

    Seeds through the same path a first start takes, so the credentials the node is provisioned with are
    what it comes back on.

    Raises
    ------
    WazuhError(5012)
        When the node is not provisioned with credentials this manager can seed from. Validated, not
        merely looked for: a file that exists but cannot be used would pass the check and fail during
        seeding, with the database already gone and every RBAC resource on the node lost with it.
    """
    try:
        load_preseeded_passwords()
    except PreseededPasswordsError as exc:
        raise WazuhError(5012, extra_message=str(exc))

    try:
        os.remove(DB_FILE)
    except FileNotFoundError:
        pass

    check_database_integrity()
    revoke_tokens()
    return {'reset': True}
