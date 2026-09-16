# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import logging
import os
from functools import lru_cache
from shutil import chown
from tempfile import mkstemp

import yaml

import api.middlewares as middlewares
from api import __path__ as api_path
from api.authentication import change_keypair
from api.constants import SECURITY_CONFIG_PATH
from wazuh import WazuhInternalError, WazuhError
from wazuh.core.common import wazuh_uid, wazuh_gid
from wazuh.core.decorators import dapi_allower
from wazuh.rbac.orm import AuthenticationManager, TokenManager, check_database_integrity, DB_FILE, \
    DEFAULT_PASSWORDS_FILE, GENERATED_MARKER_FILE

logger = logging.getLogger("wazuh-api")

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


def clear_stale_disclosure():
    """Remove a disclosure file that no longer describes the passwords in effect.

    Called when the database was created without generating anything, i.e. every default user was
    pre-seeded. A file left by a previous installation would name passwords that no longer authenticate.
    """
    try:
        os.remove(DEFAULT_PASSWORDS_FILE)
    except FileNotFoundError:
        pass
    except OSError as exc:
        logger.warning(f"Could not remove the stale '{DEFAULT_PASSWORDS_FILE}': {exc}")


def ensure_rbac_database():
    """Create the RBAC database if it is missing, disclosing any password generated in the process.

    Callers that forward over the cluster protocol must use this rather than `check_database_integrity()`
    directly: it keeps the pairing with `disclose_default_passwords()` in one place, so a generated password
    cannot be dropped, and keeps the plaintext on the node that generated it.

    Returns
    -------
    dict
        Confirmation message. Required, not optional: `forward_function` wraps the result in a
        `WazuhResult`, which rejects `None` with error 1000.
    """
    disclose_default_passwords(check_database_integrity())
    return {'ensured': True}


def rbac_db_factory_reset():
    """Reset the RBAC database to default values."""
    try:
        os.remove(DB_FILE)
    except FileNotFoundError:
        pass

    # A reset removes the database on purpose, so the regeneration is expected, not the accident warned about.
    clear_stale_disclosure()
    disclose_default_passwords(check_database_integrity(), expected_rotation=True)
    revoke_tokens()
    return {'reset': True}


_DEFAULT_PASSWORDS_FILE_HEADER = ("# Generated at installation. Retrieve these once, then change them with\n"
                                  "# 'bin/rbac_control change-password', and delete this file.\n")


def disclose_default_passwords(passwords: dict, expected_rotation: bool = False):
    """Write the plaintext password of freshly generated default users to a restricted-permission file.

    A no-op when `passwords` is empty: nothing was generated, either because the database already
    existed (a migration preserves the current password) or every default user was pre-seeded.

    Parameters
    ----------
    passwords : dict
        Username to plaintext password mapping, as returned by `check_database_integrity()`.
    expected_rotation : bool
        Whether the caller removed the database on purpose. Suppresses the accidental-loss warning.
    """
    if not passwords:
        return

    # A marker on disk means these users had a generated password before, so this is a rotation rather than
    # the first issue. Nothing else can tell them apart: the disclosure file is gone by design once read.
    rotated = os.path.exists(GENERATED_MARKER_FILE) and not expected_rotation

    _write_disclosure_file(passwords)

    if rotated:
        logger.warning(f"The password of the default API users was regenerated because '{DB_FILE}' was "
                       f"missing. Any client holding the previous credential - the Wazuh dashboard in "
                       f"particular - stops authenticating until it is updated from "
                       f"'{DEFAULT_PASSWORDS_FILE}'")
    else:
        _mark_passwords_generated()


def _write_disclosure_file(passwords: dict):
    """Write the disclosure file atomically, replacing whatever was there.

    Renamed over the target from a sibling temporary file: removing it first would leave a window with no
    disclosure, and mode 0o400 cannot be truncated in place. Mode and ownership are set before the rename.

    Parameters
    ----------
    passwords : dict
        Username to plaintext password mapping to write.
    """
    content = _DEFAULT_PASSWORDS_FILE_HEADER + ''.join(f"{username}: {password}\n"
                                                        for username, password in passwords.items())

    fd, tmp_path = mkstemp(dir=os.path.dirname(DEFAULT_PASSWORDS_FILE))
    try:
        try:
            os.write(fd, content.encode())
        finally:
            os.close(fd)
        chown(tmp_path, wazuh_uid(), wazuh_gid())
        os.chmod(tmp_path, 0o400)
        os.replace(tmp_path, DEFAULT_PASSWORDS_FILE)
    except Exception:
        os.path.exists(tmp_path) and os.remove(tmp_path)
        raise


def _mark_passwords_generated():
    """Record that a password has been generated on this installation at least once."""
    try:
        os.close(os.open(GENERATED_MARKER_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400))
        chown(GENERATED_MARKER_FILE, wazuh_uid(), wazuh_gid())
    except FileExistsError:
        pass
    except OSError as exc:
        # Losing the marker only costs the ability to tell a later regeneration from a first install.
        logger.debug(f"Could not write '{GENERATED_MARKER_FILE}': {exc}")


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

    # A line without a colon is not an entry: the operator may have annotated the file. An IndexError here
    # would surface as a 500 on a password change that already succeeded.
    with open(DEFAULT_PASSWORDS_FILE) as f:
        entries = (line.split(':', 1) for line in f
                   if line.strip() and not line.startswith('#') and ':' in line)
        remaining = {name.strip(): password.strip() for name, password in entries
                     if name.strip() != username}

    # Not `disclose_default_passwords`: rewriting after a password change is not a rotation.
    if remaining:
        _write_disclosure_file(remaining)
    else:
        os.remove(DEFAULT_PASSWORDS_FILE)


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


# Password these users shipped with before generation. The RBAC migration preserves the default users, so an
# installation created back then keeps it, and this check has to outlive its removal from `users.yaml`.
_LEGACY_DEFAULT_PASSWORDS = {'wazuh': 'wazuh', 'wazuh-wui': 'wazuh-wui'}


def get_users_with_legacy_password() -> list:
    """Get the default users that still authenticate with the password the packages used to ship.

    Returns
    -------
    list
        Names of the default users whose password is still the pre-generation literal. Always empty on an
        installation created after that password stopped being shipped.
    """
    with AuthenticationManager() as auth:
        return [username for username, password in _LEGACY_DEFAULT_PASSWORDS.items()
                if auth.check_user(username, password)]
