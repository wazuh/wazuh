# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import sys
from os import path
from signal import SIGINT, signal

try:
    from wazuh import WazuhError
    from wazuh.core.cluster import utils as cluster_utils
except Exception as e:
    print("Error importing 'Wazuh' package.\n\n{0}\n".format(e))
    sys.exit(1)


def signal_handler(n_signal, frame):
    print('')
    sys.exit(1)


async def restore_default_passwords(script_args):
    """Try to update all RBAC default users passwords with console prompt."""
    from getpass import getpass

    import yaml
    from wazuh.core.common import DEFAULT_RBAC_RESOURCES
    from wazuh.security import update_user

    default_users_file = path.join(DEFAULT_RBAC_RESOURCES, 'users.yaml')
    with open(default_users_file) as f:
        users = yaml.safe_load(f)

    results = {}
    for user_id, username in enumerate(users['default_users']):
        new_password = getpass(f"New password for '{username}' (skip): ")
        if new_password == '':
            continue

        response = await cluster_utils.forward_function(
            update_user, f_kwargs={'user_id': str(user_id + 1), 'password': new_password}, request_type='local_master'
        )

        results[username] = f'FAILED | {str(response)}' if isinstance(response, Exception) else 'UPDATED'

    for user, status in results.items():
        print(f'\t{user}: {status}')


async def reset_rbac_database(script_args):
    """Attempt to fully wipe the RBAC database to restore factory values. Input confirmation is required."""
    if (
        not script_args.reset_force
        and input(
            'This action will completely wipe your RBAC configuration and restart it '
            'to default values. Type RESET to proceed: '
        )
        != 'RESET'
    ):
        print('\tRBAC database reset aborted.')
        sys.exit(0)

    from wazuh.core.security import rbac_db_factory_reset

    response = await cluster_utils.forward_function(rbac_db_factory_reset, request_type='local_master')

    print(
        f'\tRBAC database reset failed | {str(response)}'
        if isinstance(response, Exception)
        else '\tSuccessfully reset RBAC database'
    )


def get_script_arguments():
    arg_parser = argparse.ArgumentParser(description='Wazuh RBAC tool: manage resources from the Wazuh RBAC database')
    arg_parser._positionals.title = 'Arguments'
    arg_subparsers = arg_parser.add_subparsers()

    change_password_parser = arg_subparsers.add_parser(
        'change-password',
        help='Change the password for each default user. Empty values will leave the password unchanged.',
    )
    change_password_parser.set_defaults(func=restore_default_passwords)
    reset_parser = arg_subparsers.add_parser(
        'factory-reset',
        help='Reset the RBAC database to its default state. This will completely wipe your custom RBAC information.',
    )
    reset_parser.add_argument(
        '-f',
        '--force',
        action='store_true',
        dest='reset_force',
        default=False,
        help='Do not ask for confirmation for the RBAC database factory reset.',
    )
    reset_parser.set_defaults(func=reset_rbac_database)

    if not len(sys.argv) > 1:
        arg_parser.print_help()
        sys.exit(0)

    return arg_parser.parse_args()


async def main():
    signal(SIGINT, signal_handler)

    await args.func(args)
    sys.exit(0)


if __name__ == '__main__':
    args = get_script_arguments()

    try:
        asyncio.run(main())
    except WazuhError as e:
        print(f'Error {e.code}: {e.message}')
    except Exception as e:
        print(f'Internal error: {e}')
