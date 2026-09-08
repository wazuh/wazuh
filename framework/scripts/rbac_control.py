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

    results = {}
    for username, new_password in new_passwords.items():
        # The default users hold reserved IDs, and `update_user` only lets another reserved user
        # modify those. This script runs locally as root, on behalf of the user being updated.
        response = await cluster_utils.forward_function(update_user, f_kwargs={'user_id': user_ids[username],
                                                                               'password': new_password,
                                                                               'current_user': username},
                                                        request_type="local_master")

        results[username] = f'FAILED | {str(response)}' if isinstance(response, Exception) else 'UPDATED'

    for user, status in results.items():
        print(f"\t{user}: {status}")

    # The exit status is what a caller such as the passwords tool checks to know whether every
    # requested password was applied.
    if any(status != 'UPDATED' for status in results.values()):
        sys.exit(1)


async def reset_rbac_database(script_args):
    """Attempt to fully wipe the RBAC database to restore factory values. Input confirmation is required."""
    if not script_args.reset_force and input("This action will completely wipe your RBAC configuration and restart it "
                                             "to default values. Type RESET to proceed: ") != "RESET":
        print("\tRBAC database reset aborted.")
        sys.exit(0)

    from wazuh.core.security import rbac_db_factory_reset

    response = await cluster_utils.forward_function(rbac_db_factory_reset, request_type="local_master")

    print(f"\tRBAC database reset failed | {str(response)}" if isinstance(response, Exception)
          else "\tSuccessfully reset RBAC database")


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
    change_password_parser.add_argument("--passwords-file", action="store", dest="passwords_file", default=None,
                                        help="Read a JSON object mapping default usernames to their new passwords "
                                             "from this file, or from the standard input if it is '-', and change "
                                             "all of them in a single execution.")
    change_password_parser.set_defaults(func=restore_default_passwords)
    reset_parser = arg_subparsers.add_parser("factory-reset",
                                             help="Reset the RBAC database to its default state. This will completely"
                                                  " wipe your custom RBAC information, and restore the default users'"
                                                  " shipped passwords.")
    reset_parser.add_argument("-f", "--force", action="store_true", dest="reset_force", default=False,
                              help="Do not ask for confirmation for the RBAC database factory reset.")
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
    except Exception as e:
        print(f"Internal error: {e}")
