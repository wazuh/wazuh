# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import asyncio
import json
import sys
from os.path import join

from tabulate import tabulate

from wazuh import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult


async def validate_resource(resource: dict, r_type: str):
    """Validate the resource body using custom API models.

    Parameters
    ----------
    resource : dict
        Resource body.
    r_type : str
        Resource type.

    Raises
    ------
    WazuhError1018
        Raised if there was a JSONDecodeError parsing the body.

    Returns
    -------
    dict
        Complete resource body adding any missing fields with `None` value.
    """
    from api.models.security_model import RoleModel, RuleModel, PolicyModel, CreateUserModel, UpdateUserModel

    resource_body = {
        'user': CreateUserModel,
        'role': RoleModel,
        'policy': PolicyModel,
        'rule': RuleModel,
        'update_user': UpdateUserModel
    }

    try:
        loaded_json = json.loads(resource)
        return await resource_body[r_type].validate_kwargs(loaded_json)
    except json.JSONDecodeError:
        raise WazuhError(1018)


async def forward_function(func: callable, f_kwargs: dict = None):
    """Distribute function to master node.

    Parameters
    ----------
    func : callable
        Function to execute on master node.
    f_kwargs : dict
        Function kwargs.

    Returns
    -------
    Return either a dict or `WazuhResult` instance in case the execution did not fail. Return an exception otherwise.
    """
    from wazuh.core.cluster import local_client
    from wazuh.core.cluster.common import WazuhJSONEncoder, as_wazuh_object

    lc = local_client.LocalClient()

    input_json = {
        'f': func,
        'from_cluster': False,
        'wait_for_complete': False
    }

    f_kwargs and input_json.update({'f_kwargs': f_kwargs})

    # Distribute function to master node
    response = json.loads(await lc.execute(command=b'dapi',
                                           data=json.dumps(input_json, cls=WazuhJSONEncoder).encode(),
                                           wait_for_complete=False),
                          object_hook=as_wazuh_object)

    return response


async def manage_reserved_security_resource(method: str, resource_type: str, f_arguments: dict):
    """Execute a mapped security method depending on the method and resource type.

    Parameters
    ----------
    method : str
        Resource method (add, update, delete...).
    resource_type : str
        Security resource type.
    f_arguments : dict
        Dictionary with the security function kwargs.

    Raises
    ------
    Exception
        Raise any exception caught during function distribution.

    Returns
    -------
    AffectedItemsWazuhResult
        Function execution result.
    """
    from wazuh.security import create_user, add_rule, add_role, add_policy, update_user, update_role, update_policy, \
        update_rule, remove_users, remove_roles, remove_policies, remove_rules, set_user_role, set_role_policy, \
        set_role_rule, remove_user_role, remove_role_policy, remove_role_rule

    from wazuh.rbac.orm import ResourceType

    func = {
        'add': {
            'user': create_user,
            'role': add_role,
            'policy': add_policy,
            'rule': add_rule
        },
        'update': {
            'user': update_user,
            'role': update_role,
            'policy': update_policy,
            'rule': update_rule
        },
        'remove': {
            'user': remove_users,
            'role': remove_roles,
            'policy': remove_policies,
            'rule': remove_rules
        },
        'link': {
            'user-role': set_user_role,
            'role-policy': set_role_policy,
            'role-rule': set_role_rule
        },
        'unlink': {
            'user-role': remove_user_role,
            'role-policy': remove_role_policy,
            'role-rule': remove_role_rule
        }
    }

    if method not in ('link', 'unlink'):
        f_arguments['resource_type'] = ResourceType.PROTECTED

    response = await forward_function(func[method][resource_type], f_kwargs=f_arguments)

    if isinstance(response, Exception):
        raise response

    return response


async def restore_default_passwords():
    """Try to update all RBAC default users passwords with console prompt."""
    import yaml
    from getpass import getpass

    from wazuh.core.common import default_rbac_resources
    from wazuh.rbac.orm import ResourceType
    from wazuh.security import update_user

    default_users_file = join(default_rbac_resources, 'users.yaml')
    with open(default_users_file) as f:
        users = yaml.safe_load(f)

    results = dict()
    for user_id, username in enumerate(users['default_users']):
        new_password = getpass(f"New password for '{username}' (skip): ")
        if not new_password:
            continue

        response = await forward_function(update_user, f_kwargs={'user_id': str(user_id + 1),
                                                                 'password': new_password,
                                                                 'resource_type': ResourceType.DEFAULT})

        results[username] = f'FAILED | {str(response)}' if isinstance(response, Exception) else 'UPDATED'

    for user, status in results.items():
        print(f"\t{user}: {status}")


async def reset_rbac_database():
    """Attempt to fully wipe the RBAC database to restore factory values. Input confirmation is required."""
    if input('This action will completely wipe your RBAC configuration and restart it to default values. Type '
             'RESET to proceed: ') != 'RESET':
        print('RBAC database reset aborted.')
        sys.exit(0)

    from wazuh.core.security import rbac_db_factory_reset

    response = await forward_function(rbac_db_factory_reset)

    print(f'RBAC database reset failed | {str(response)}' if isinstance(response, Exception)
          else '\tSuccessfully resetted RBAC database')


if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser(description='Wazuh RBAC protected resources manager',
                                         usage=
                                         '\nAdd resources\n\n'
                                         '-au \'{"username": "USERNAME", "password": "PASSWORD", '
                                         '"allow_run_as": TRUE/FALSE}\' \n'
                                         '-ar \'{"name": "ROLE_NAME"}\' \n'
                                         '-ap \'{"name": "POLICY_NAME", "policy": {"actions": ["agent:read"], '
                                         '"resources": ["agent:id:001"], "effect": "allow"}}\' \n'
                                         '-aru \'{"name": "RULE_NAME", "rule": {"MATCH": {"sample": "yes"}}}\' \n\n'
                                         'Update resources \n\n'
                                         '-uu <SAME_AS_ADD>\n'
                                         '-ur <SAME_AS_ADD>\n'
                                         '-up <SAME_AS_ADD>\n'
                                         '-uru <SAME_AS_ADD>\n\n'
                                         'Delete resources \n\n'
                                         '-ru [USER_IDs] \n'
                                         '-rr [ROLE_IDs] \n'
                                         '-rp [POLICY_IDs] \n'
                                         '-rru [RULE_IDs] \n\n'
                                         'Link resources \n\n'
                                         '-lur USER_ID [ROLE_IDs] \n'
                                         '-lrp ROLE_ID [POLICY_IDs] \n'
                                         '-lrru ROLE_ID [RULE_IDs] \n\n'
                                         'Unlink resources \n\n'
                                         '-unur USER_ID [ROLE_IDs] \n'
                                         '-unrp ROLE_ID [POLICY_IDs] \n'
                                         '-unrru ROLE_ID [RULE_ID]\n\n'
                                         'Change admin users passwords\n\n'
                                         '--change-passwords\n\n'
                                         'Reset RBAC database\n\n'
                                         '--factory-reset'
                                         )
    arg_parser.add_argument("-au", "--add-user", nargs='+', type=str, action='store', dest='add_user',
                            help="Add reserved security users.")
    arg_parser.add_argument("-ar", "--add-role", nargs='+', type=str, action='store', dest='add_role',
                            help="Add reserved security roles.")
    arg_parser.add_argument("-ap", "--add-policy", nargs='+', type=str, action='store', dest='add_policy',
                            help="Add reserved security policies.")
    arg_parser.add_argument("-aru", "--add-rule", nargs='+', type=str, action='store', dest='add_rule',
                            help="Add reserved security rules.")
    arg_parser.add_argument("-uu", "--update-user", nargs=2, type=str, action='store', dest='update_user',
                            help="Update reserved security users.")
    arg_parser.add_argument("-ur", "--update-role", nargs=2, type=str, action='store', dest='update_role',
                            help="Update reserved security roles.")
    arg_parser.add_argument("-up", "--update-policy", nargs=2, type=str, action='store', dest='update_policy',
                            help="Update reserved security policies.")
    arg_parser.add_argument("-uru", "--update-rule", nargs=2, type=str, action='store', dest='update_rule',
                            help="Update reserved security rules.")
    arg_parser.add_argument("-ru", "--remove-user", nargs='+', type=str, action='store', dest='remove_user',
                            help="Add reserved security users.")
    arg_parser.add_argument("-rr", "--remove-role", nargs='+', type=str, action='store', dest='remove_role',
                            help="Add reserved security roles.")
    arg_parser.add_argument("-rp", "--remove-policy", nargs='+', type=str, action='store', dest='remove_policy',
                            help="Add reserved security policies.")
    arg_parser.add_argument("-rru", "--remove-rule", nargs='+', type=str, action='store', dest='remove_rule',
                            help="Add reserved security rules.")
    arg_parser.add_argument("-lur", "--link-user-roles", nargs='+', type=str, action='store', dest='link_user-role',
                            help="Link reserved security user with roles.")
    arg_parser.add_argument("-lrp", "--link-role-policies", nargs='+', type=str, action='store',
                            dest='link_role-policy',
                            help="Link reserved security role with policies.")
    arg_parser.add_argument("-lrru", "--link-role-rules", nargs='+', type=str, action='store', dest='unlink_role-rule',
                            help="Link reserved security role with rules.")
    arg_parser.add_argument("-unur", "--unlink-user-roles", nargs='+', type=str, action='store',
                            dest='unlink_user-role',
                            help="Unlink reserved security user from roles.")
    arg_parser.add_argument("-unrp", "--unlink-role-policies", nargs='+', type=str, action='store',
                            dest='unlink_role-policy',
                            help="Unlink reserved security role from policies.")
    arg_parser.add_argument("-unrru", "--unlink-role-rules", nargs='+', type=str, action='store',
                            dest='unlink_role-rule',
                            help="Unlink reserved security role from rules.")
    arg_parser.add_argument("--change-passwords", action='store_true', dest='change_passwords',
                            help="Change the password for each default user. Empty values will leave the password "
                                 "unchanged.")
    arg_parser.add_argument("--factory-reset", action='store_true', dest='factory_reset',
                            help="Restart the RBAC database to its default state. This will completely wipe your custom"
                                 " RBAC information.")
    args = arg_parser.parse_args()

    if not len(sys.argv) > 1:
        arg_parser.print_help()
        sys.exit(0)

    try:
        if args.change_passwords:
            asyncio.run(restore_default_passwords())
            sys.exit(0)
        elif args.factory_reset:
            asyncio.run(reset_rbac_database())
            sys.exit(0)

        result_table = list()
        for key, values in args.__dict__.items():
            method, resource_name = key.split('_')
            result = AffectedItemsWazuhResult()
            try:
                # Add resource
                if method == 'add' and values:
                    for resource in values:
                        kwargs = asyncio.run(validate_resource(resource, resource_name))
                        result |= asyncio.run(manage_reserved_security_resource(method, resource_name, kwargs))
                # Update resource
                elif method == 'update' and values:
                    r_id, new_value = values
                    kwargs = asyncio.run(
                        validate_resource(new_value, resource_name if resource_name != 'user' else 'update_user'))
                    kwargs[f'{resource_name}_id'] = r_id
                    result |= asyncio.run(manage_reserved_security_resource(method, resource_name, kwargs))
                # Remove resource
                elif method == 'remove' and values:
                    if not all(map(str.isnumeric, values)):
                        raise WazuhError(10000, extra_message='Remove methods only allow IDs')
                    result |= asyncio.run(manage_reserved_security_resource(method, resource_name,
                                                                            {f'{resource_name}_ids': values}))
                # Link/unlink resources
                elif 'link' in method and values:
                    if len(values) < 2:
                        raise WazuhError(10000, extra_message='Link methods need at least 2 arguments. '
                                                              '<MAIN RESOURCE ID> <RELATED RESOURCE ID> '
                                                              '[<RELATED RESOURCE ID>]')
                    main_id, related_ids = values[0], values[1:]
                    main_r, related_r = resource_name.split('-')
                    kwargs = {f'{main_r}_id': main_id, f'{related_r}_ids': related_ids}
                    result |= asyncio.run(manage_reserved_security_resource(method, resource_name, kwargs))
            except WazuhError as e:
                if e.code in (10001, 10002):
                    result.add_failed_item(id_='Bad format', error=e)
                else:
                    for v in values:
                        result.add_failed_item(id_=str(v), error=e)

            # Construct result table
            if result.affected_items or result.failed_items:
                if not result.affected_items:
                    success = None
                elif 'link' in method:
                    item = result.affected_items[0]
                    key = {'role': 'roles', 'policy': 'policies', 'rule': 'rules'}[related_r]
                    success = f"{item['id']} - [{', '.join(map(str, item[key]))}]"
                else:
                    success = ', '.join([f"{item['id']} - {item.get('name', item.get('username', 'unknown'))}"
                                         for item in result.affected_items])

                result_table.append([resource_name.title(),
                                     method,
                                     success,
                                     '\n'.join(f"{', '.join(map(str, ids))} || {error}"
                                               for error, ids in result.failed_items.items())])

        table_headers = ['Resource', 'Method', 'Success', 'Failed']
        print(tabulate(result_table, headers=table_headers))
    except WazuhError as e:
        print(f"Error {e.code}: {e.message}")
    except Exception as e:
        print(f"Internal error: {e}")
