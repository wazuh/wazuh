# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import os
from functools import lru_cache
from shutil import chown

import yaml

import api.middlewares as middlewares
from api import __path__ as api_path
from api.authentication import change_keypair
from api.constants import SECURITY_CONFIG_PATH
from wazuh import WazuhInternalError, WazuhError
from wazuh.core.common import wazuh_uid, wazuh_gid
from wazuh.core.decorators import dapi_allower
from wazuh.rbac.orm import TokenManager, check_database_integrity, DB_FILE, DEFAULT_PASSWORDS_FILE

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


def rbac_db_factory_reset():
    """Reset the RBAC database to default values."""
    try:
        os.remove(DB_FILE)
    except FileNotFoundError:
        pass

    disclose_default_passwords(check_database_integrity())
    revoke_tokens()
    return {'reset': True}


_DEFAULT_PASSWORDS_FILE_HEADER = ("# Generated at installation. Retrieve these once, then change them with\n"
                                  "# 'bin/rbac_control change-password', and delete this file.\n")


def disclose_default_passwords(passwords: dict):
    """Write the plaintext password of freshly generated default users to a restricted-permission file.

    A no-op when `passwords` is empty: nothing was generated, either because the database already
    existed (a migration preserves the current password) or every default user was pre-seeded.

    Parameters
    ----------
    passwords : dict
        Username to plaintext password mapping, as returned by `check_database_integrity()`.
    """
    if not passwords:
        return

    content = _DEFAULT_PASSWORDS_FILE_HEADER + ''.join(f"{username}: {password}\n"
                                                        for username, password in passwords.items())

    # Always start from a clean file: a leftover from a previous disclosure is mode 0o400 (no write
    # bit), so truncating it in place would fail for the same non-root user that created it.
    try:
        os.remove(DEFAULT_PASSWORDS_FILE)
    except FileNotFoundError:
        pass

    fd = os.open(DEFAULT_PASSWORDS_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    try:
        os.write(fd, content.encode())
    finally:
        os.close(fd)

    # Defensive: covers the API running as root, where os.open()'s mode argument is not final.
    chown(DEFAULT_PASSWORDS_FILE, wazuh_uid(), wazuh_gid())
    os.chmod(DEFAULT_PASSWORDS_FILE, 0o400)


def clear_disclosed_default_password(username: str):
    """Remove one username from the disclosure file, deleting it once no password is left in it.

    Called whenever a default user's password is changed, so the file - and the warning it drives -
    never claims a password is still undisclosed once the operator has already picked their own.

    Parameters
    ----------
    username : str
        Name of the default user whose password was just changed.
    """
    if not os.path.exists(DEFAULT_PASSWORDS_FILE):
        return

    with open(DEFAULT_PASSWORDS_FILE) as f:
        remaining = {line.split(':', 1)[0].strip(): line.split(':', 1)[1].strip()
                    for line in f if line.strip() and not line.startswith('#')
                    and line.split(':', 1)[0].strip() != username}

    os.remove(DEFAULT_PASSWORDS_FILE)
    disclose_default_passwords(remaining)


def get_users_with_default_password() -> list:
    """Get the default users whose randomly generated password has not been retrieved yet.

    Returns
    -------
    list
        Names of the default users still listed in the disclosure file, in the order they appear
        in it. Empty once the file has been read and removed, or every default password was
        pre-seeded or already changed.
    """
    if not os.path.exists(DEFAULT_PASSWORDS_FILE):
        return []

    with open(DEFAULT_PASSWORDS_FILE) as f:
        return [line.split(':', 1)[0].strip() for line in f if line.strip() and not line.startswith('#')]
