# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import sys
from os import path
from signal import signal, SIGINT

try:
    from wazuh import WazuhError
    from wazuh.core.cluster import utils as cluster_utils
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    sys.exit(1)

# How the installation supplies a password instead of having one generated. Through the environment and
# never through an argument: the process list is readable by every account on the host, the environment of
# a process is not. A default user missing from this mapping is always generated.
PASSWORD_ENVIRONMENT_VARIABLES = {'wazuh': 'WAZUH_API_PASSWORD', 'wazuh-wui': 'WAZUH_WUI_PASSWORD'}


def signal_handler(n_signal, frame):
    print("")
    sys.exit(1)


def read_source(source: str) -> str:
    """Read the whole content of a file, or of the standard input if the source is `-`.

    Parameters
    ----------
    source : str
        Path of the file to read, or `-` to read the standard input.

    Returns
    -------
    str
        Content read.
    """
    if source == '-':
        return sys.stdin.read()

    with open(source) as f:
        return f.read()


def read_new_passwords(script_args, default_users: list) -> dict:
    """Resolve the new password of each default user from the script arguments.

    Without any argument, the passwords are prompted for and an empty answer leaves that user's
    password unchanged. Passwords are never taken from the command line so that they are not
    exposed in the process list.

    Parameters
    ----------
    script_args : argparse.Namespace
        Arguments given to the script.
    default_users : list
        Names of the RBAC default users, in the order they are declared in the default users file.

    Raises
    ------
    ValueError
        If the given arguments do not resolve to a valid set of default users and passwords.

    Returns
    -------
    dict
        New password of each user to update, keyed by username. Users whose password must be left
        unchanged are not included.
    """
    import json
    from getpass import getpass

    def validate_user(username: str):
        if username not in default_users:
            raise ValueError(f"'{username}' is not an RBAC default user. "
                             f"Default users: {', '.join(default_users)}")

    if script_args.passwords_file:
        if script_args.user or script_args.password_file:
            raise ValueError("'--passwords-file' cannot be combined with '--user' or '--password-file'")

        try:
            new_passwords = json.loads(read_source(script_args.passwords_file))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read the passwords file: {exc}") from exc

        if not isinstance(new_passwords, dict) or not new_passwords:
            raise ValueError("The passwords file must hold a non-empty JSON object mapping default usernames "
                             "to their new passwords")

        for username, new_password in new_passwords.items():
            validate_user(username)
            # An empty password means "leave it unchanged" when prompting, but a caller that went
            # through the trouble of writing a file expects every password in it to be applied.
            if not isinstance(new_password, str) or new_password == "":
                raise ValueError(f"The new password of '{username}' must be a non-empty string")

        return new_passwords

    if script_args.user:
        validate_user(script_args.user)

    if script_args.password_file:
        if not script_args.user:
            raise ValueError("'--password-file' needs the user it applies to ('--user'). Use '--passwords-file' "
                             "to update several users at once")

        try:
            # Only the first line is the password: a trailing newline is expected in a text file and
            # would be rejected by the password policy, which does not allow line breaks.
            new_password = read_source(script_args.password_file).split('\n')[0].rstrip('\r')
        except OSError as exc:
            raise ValueError(f"Could not read the password file: {exc}") from exc

        if new_password == "":
            raise ValueError("The password file does not hold a password")

        return {script_args.user: new_password}

    new_passwords = {}
    for username in [script_args.user] if script_args.user else default_users:
        new_password = getpass(f"New password for '{username}' (skip): ")
        if new_password != "":
            new_passwords[username] = new_password

    return new_passwords


async def restore_default_passwords(script_args):
    """Update the passwords of the RBAC default users, either interactively or from a file."""
    import yaml
    from wazuh.core.common import DEFAULT_RBAC_RESOURCES
    from wazuh.security import update_user

    default_users_file = path.join(DEFAULT_RBAC_RESOURCES, 'users.yaml')
    with open(default_users_file) as f:
        users = yaml.safe_load(f)

    # The default users are inserted in the order they are declared in `users.yaml`, so their ID is
    # their position in that file.
    user_ids = {username: str(user_id) for user_id, username in enumerate(users['default_users'], start=1)}

    try:
        new_passwords = read_new_passwords(script_args, list(user_ids))
    except ValueError as exc:
        print(f"\t{exc}")
        sys.exit(1)

    # Checked here and not only by `update_user`, which rejects it after the fact: the interactive prompt
    # would accept a password it cannot apply, and a file naming several users would apply the ones read
    # before the offending entry.
    from wazuh.rbac.orm import USER_PASSWORD_MAX_LENGTH, USER_PASSWORD_MIN_LENGTH, USER_PASSWORD_POLICY, \
        USER_POLICY_SYMBOLS

    for username, new_password in new_passwords.items():
        if not USER_PASSWORD_MIN_LENGTH <= len(new_password) <= USER_PASSWORD_MAX_LENGTH \
                or not USER_PASSWORD_POLICY.match(new_password):
            print(f"\tThe password of '{username}' does not satisfy the API password policy: "
                  f"{USER_PASSWORD_MIN_LENGTH} to {USER_PASSWORD_MAX_LENGTH} characters, with a lowercase "
                  f"letter, an uppercase letter, a digit and one of '{USER_POLICY_SYMBOLS}'")
            sys.exit(1)

    # `local_master` resolves to the master from anywhere, which is where the credential in use lives.
    # `--local` targets this node instead: a worker's `rbac.db` is never synchronized, and only becomes
    # live if the node is promoted.
    request_type = "local_any" if script_args.local else "local_master"

    if new_passwords:
        from wazuh.core.security import ensure_rbac_database

        # A node whose apid has never run (a worker: apid is master-only) has no 'rbac.db', and
        # 'update_user' would fail against it. Seeded through the same path the first API start uses, so
        # the users it does not overwrite end up on what that node was provisioned with, or on a generated
        # password when it was provisioned with nothing.
        ensure_response = await cluster_utils.forward_function(ensure_rbac_database, request_type=request_type)
        if isinstance(ensure_response, Exception):
            print(f"\tCould not ensure the RBAC database exists: {ensure_response}")
            sys.exit(1)

    results = {}
    for username, new_password in new_passwords.items():
        # The default users hold reserved IDs, and `update_user` only lets another reserved user
        # modify those. This script runs locally as root, on behalf of the user being updated.
        response = await cluster_utils.forward_function(update_user, f_kwargs={'user_id': user_ids[username],
                                                                               'password': new_password,
                                                                               'current_user': username},
                                                        request_type=request_type)

        results[username] = f'FAILED | {str(response)}' if isinstance(response, Exception) else 'UPDATED'

    for user, status in results.items():
        print(f"\t{user}: {status}")

    # The exit status is what a caller such as the passwords tool checks to know whether every
    # requested password was applied.
    if any(status != 'UPDATED' for status in results.values()):
        sys.exit(1)


def _read_provisioned_passwords(default_users: list) -> dict:
    """Read the passwords the node is already provisioned with.

    Only the default users are kept: an entry naming anything else, left by another tool, would survive
    every merge and would make the API refuse the file at every start, with no call to this script able to
    correct it.

    Parameters
    ----------
    default_users : list
        Names of the RBAC default users.

    Returns
    -------
    dict
        Username to password mapping, empty when nothing is provisioned yet.
    """
    import os

    import yaml
    from wazuh.rbac.orm import PRESEEDED_PASSWORDS_FILE, PreseededPasswordsError, \
        _assert_preseed_source_is_trusted

    if not os.path.exists(PRESEEDED_PASSWORDS_FILE):
        return {}

    provisioned = {}
    try:
        # Checked as the API checks it, and through the descriptor that gets read: a file this script
        # merged would otherwise reach the API vouched for, whatever it was before.
        with open(os.open(PRESEEDED_PASSWORDS_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK),
                  encoding='utf-8') as f:
            _assert_preseed_source_is_trusted(f.fileno())
            document = yaml.safe_load(f) or {}
        if not isinstance(document, dict):
            raise ValueError('it does not hold a YAML mapping')
        for entry in document.get('manager') or []:
            if entry['name'] in default_users:
                provisioned[entry['name']] = entry['password']
    except (OSError, KeyError, TypeError, ValueError, yaml.YAMLError, PreseededPasswordsError) as exc:
        # The parser's own message echoes the line it failed on, password included.
        reason = exc if isinstance(exc, PreseededPasswordsError) else type(exc).__name__
        print(f"\tCould not read '{PRESEEDED_PASSWORDS_FILE}': {reason}. Remove it and set every "
              f"default user's password again")
        sys.exit(1)

    return provisioned


def _write_provisioned_passwords(provisioned: dict):
    """Write the file the API seeds from, reporting a failure the way an installer can chain on.

    Parameters
    ----------
    provisioned : dict
        Username to password mapping to write.
    """
    from wazuh.rbac.orm import PRESEEDED_PASSWORDS_FILE, write_preseeded_passwords

    try:
        write_preseeded_passwords(provisioned)
    except Exception as exc:
        print(f"\tCould not write '{PRESEEDED_PASSWORDS_FILE}': {exc}. This command must run as root or as "
              f"the Wazuh user")
        sys.exit(1)


async def provision_default_passwords(script_args):
    """Provision a password for every default user that has none, and disclose all of them.

    Run by the installation once the package is in place. A user whose environment variable is set takes
    that password, the rest are generated, and a user already provisioned is left alone, so a second run
    neither regenerates nor overwrites what an earlier `set-password` wrote.

    Writes the same file `set-password` writes and touches no database, so it runs with every daemon
    stopped, which is the window the installation has.
    """
    import os

    import yaml
    from wazuh.core.common import DEFAULT_RBAC_RESOURCES
    from wazuh.rbac.orm import DB_FILE, PRESEEDED_PASSWORDS_FILE, USER_PASSWORD_MAX_LENGTH, \
        USER_PASSWORD_MIN_LENGTH, USER_PASSWORD_POLICY, USER_POLICY_SYMBOLS, generate_default_password

    with open(path.join(DEFAULT_RBAC_RESOURCES, 'users.yaml')) as f:
        default_users = list(yaml.safe_load(f)['default_users'])

    # The password in use is in the database, and this script cannot read it. Provisioning here would write
    # a file that never applies and report credentials that do not authenticate.
    if os.path.exists(DB_FILE):
        print(f"\t'{DB_FILE}' already exists: its users keep the password they were created with, and this "
              f"command cannot read it. Use 'change-password' with the manager running to change it")
        return

    provisioned = _read_provisioned_passwords(default_users)
    origin = {}

    for username in default_users:
        if username in provisioned:
            origin[username] = 'ALREADY PROVISIONED'
            continue

        variable = PASSWORD_ENVIRONMENT_VARIABLES.get(username)
        supplied = os.environ.get(variable) if variable else None

        if supplied is None:
            provisioned[username] = generate_default_password()
            origin[username] = 'GENERATED'
            continue

        if not USER_PASSWORD_MIN_LENGTH <= len(supplied) <= USER_PASSWORD_MAX_LENGTH \
                or not USER_PASSWORD_POLICY.match(supplied):
            print(f"\tThe password of '{username}', taken from {variable}, does not satisfy the API "
                  f"password policy: {USER_PASSWORD_MIN_LENGTH} to {USER_PASSWORD_MAX_LENGTH} characters, "
                  f"with a lowercase letter, an uppercase letter, a digit and one of "
                  f"'{USER_POLICY_SYMBOLS}'")
            sys.exit(1)

        provisioned[username] = supplied
        origin[username] = f'TAKEN FROM {variable}'

    _write_provisioned_passwords(provisioned)

    for username in default_users:
        print(f"\t{username}: {origin[username]}")

    # The installation output is how the operator, and whatever installs the rest of the deployment, get
    # the credential the dashboard authenticates with. It is the only place a password is printed: the
    # manager never writes one to its own log.
    print("\nServer API credentials of this node:\n")
    for username in default_users:
        print(f"\t{username}: {provisioned[username]}")
    print(f"\nThey are also in '{PRESEEDED_PASSWORDS_FILE}', which only root and the Wazuh group can read. "
          f"Store them elsewhere and remove that file.")


async def preseed_default_password(script_args):
    """Write the password of one default user to the file the API seeds the RBAC database from.

    Writes a file instead of touching `rbac.db`, so it works with every daemon stopped, which is the only
    window an installer has: between installing the package and the first manager start. It does not go
    through the cluster protocol either, so it needs no node to be reachable.
    """
    import os

    import yaml
    from wazuh.core.common import DEFAULT_RBAC_RESOURCES
    from wazuh.rbac.orm import DB_FILE, USER_PASSWORD_MAX_LENGTH, USER_PASSWORD_MIN_LENGTH, \
        USER_PASSWORD_POLICY, USER_POLICY_SYMBOLS

    with open(path.join(DEFAULT_RBAC_RESOURCES, 'users.yaml')) as f:
        default_users = list(yaml.safe_load(f)['default_users'])

    if script_args.user not in default_users:
        print(f"\t'{script_args.user}' is not an RBAC default user. Default users: {', '.join(default_users)}")
        sys.exit(1)

    # Only from the standard input: a password given as an argument is visible to every account on the
    # host through the process list. Only the first line, since a trailing newline is expected from `echo`
    # and the policy does not allow one.
    password = sys.stdin.readline().rstrip('\n').rstrip('\r')

    if not USER_PASSWORD_MIN_LENGTH <= len(password) <= USER_PASSWORD_MAX_LENGTH \
            or not USER_PASSWORD_POLICY.match(password):
        print(f"\tThe password of '{script_args.user}' does not satisfy the API password policy: "
              f"{USER_PASSWORD_MIN_LENGTH} to {USER_PASSWORD_MAX_LENGTH} characters, with a lowercase "
              f"letter, an uppercase letter, a digit and one of '{USER_POLICY_SYMBOLS}'")
        sys.exit(1)

    # Merged rather than overwritten: one user is set per execution, and an entry this call does not name
    # would otherwise be dropped and generated again when the database is created.
    provisioned = _read_provisioned_passwords(default_users)
    provisioned[script_args.user] = password
    _write_provisioned_passwords(provisioned)

    print(f"\t{script_args.user}: SET")

    missing = set(default_users) - set(provisioned)
    if missing:
        print(f"\tStill missing: {', '.join(sorted(missing))}. The API generates a password for it when it "
              f"creates the database, and leaves it in the same file")

    if os.path.exists(DB_FILE):
        print(f"\t'{DB_FILE}' already exists, so this does not change the password in use. It applies only "
              f"if that database is created again. Use 'change-password' with the manager running instead")


async def reset_rbac_database(script_args):
    """Attempt to fully wipe the RBAC database to restore factory values. Input confirmation is required."""
    if not script_args.reset_force and input("This action will completely wipe your RBAC configuration and restart it "
                                             "to default values. Type RESET to proceed: ") != "RESET":
        print("\tRBAC database reset aborted.")
        sys.exit(0)

    from wazuh.core.security import rbac_db_factory_reset

    # Same routing as `change-password`: `local_master` resolves to the master from anywhere, and `--local`
    # acts on the node the command runs on, which is the only way to reset a worker's own database.
    request_type = "local_any" if script_args.local else "local_master"

    response = await cluster_utils.forward_function(rbac_db_factory_reset, request_type=request_type)

    if isinstance(response, Exception):
        # Through the exit status too: an installer chains this call, and the reset is now refused whenever
        # the node has not been provisioned again.
        print(f"\tRBAC database reset failed | {str(response)}")
        sys.exit(1)

    print("\tSuccessfully reset RBAC database")


def get_script_arguments():
    arg_parser = argparse.ArgumentParser(description="Wazuh RBAC tool: manage resources from the Wazuh RBAC database")
    arg_parser._positionals.title = "Arguments"
    arg_subparsers = arg_parser.add_subparsers()

    change_password_parser = arg_subparsers.add_parser("change-password",
                                                       help="Change the password for each default user. Without any "
                                                            "option the passwords are prompted for, and empty values "
                                                            "will leave the password unchanged.")
    change_password_parser.add_argument("-u", "--user", action="store", dest="user", default=None,
                                        help="Change the password of this default user only.")
    change_password_parser.add_argument("-p", "--password-file", action="store", dest="password_file", default=None,
                                        help="Read the new password from the first line of this file, or from the "
                                             "standard input if it is '-'. Requires '--user'.")
    change_password_parser.add_argument("--local", action="store_true", dest="local", default=False,
                                        help="Apply the change to this node's own RBAC database instead of the "
                                             "master's. Needed to align a worker, whose database is not "
                                             "synchronized and only becomes live if it is promoted to master.")
    change_password_parser.add_argument("--passwords-file", action="store", dest="passwords_file", default=None,
                                        help="Read a JSON object mapping default usernames to their new passwords "
                                             "from this file, or from the standard input if it is '-', and change "
                                             "all of them in a single execution.")
    change_password_parser.set_defaults(func=restore_default_passwords)
    preseed_parser = arg_subparsers.add_parser("set-password",
                                               help="Provision the password of a default API user for the "
                                                    "first API start, writing it where "
                                                    "'wazuh-manager-apid' seeds the RBAC database from. "
                                                    "Runs with every daemon stopped, and does not change "
                                                    "the password of a database that already exists. The "
                                                    "password is read from the first line of the standard "
                                                    "input, which keeps it out of the process list.")
    preseed_parser.add_argument("-u", "--user", action="store", dest="user", required=True,
                                help="Default user whose password to provision.")
    preseed_parser.set_defaults(func=preseed_default_password)
    provision_parser = arg_subparsers.add_parser("provision-passwords",
                                                 help="Provision a password for every default API user "
                                                      "that has none and print the credentials. Each one "
                                                      "is generated unless its environment variable "
                                                      "(WAZUH_API_PASSWORD, WAZUH_WUI_PASSWORD) supplies "
                                                      "it. Run by the installation before the first "
                                                      "manager start; it does nothing once the RBAC "
                                                      "database exists.")
    provision_parser.set_defaults(func=provision_default_passwords)
    reset_parser = arg_subparsers.add_parser("factory-reset",
                                             help="Reset the RBAC database to its default state. This will "
                                                  "completely wipe your custom RBAC information. The default users "
                                                  "come back on the passwords provisioned in "
                                                  "'wazuh-preseeded-passwords.yml', and on a generated one for "
                                                  "every user that file does not name.")
    reset_parser.add_argument("-f", "--force", action="store_true", dest="reset_force", default=False,
                              help="Do not ask for confirmation for the RBAC database factory reset.")
    reset_parser.add_argument("--local", action="store_true", dest="local", default=False,
                              help="Reset this node's own RBAC database instead of the master's. Without "
                                   "it the reset runs on the master wherever it is typed, so a worker's "
                                   "database is left untouched.")
    reset_parser.set_defaults(func=reset_rbac_database)

    if not len(sys.argv) > 1:
        arg_parser.print_help()
        sys.exit(0)

    return arg_parser.parse_args()


async def main():
    signal(SIGINT, signal_handler)

    await args.func(args)
    sys.exit(0)


if __name__ == "__main__":
    args = get_script_arguments()

    try:
        asyncio.run(main())
    except WazuhError as e:
        print(f"Error {e.code}: {e.message}")
        sys.exit(1)
    except Exception as e:
        print(f"Internal error: {e}")
        sys.exit(1)
