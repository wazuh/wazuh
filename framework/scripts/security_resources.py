import argparse
import asyncio
import json
import sys
from json import JSONDecodeError

from tabulate import tabulate

from wazuh import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult


async def validate_resource(resource, r_type):
    from api.models.security import RoleModel, RuleModel, PolicyModel, CreateUserModel, UpdateUserModel

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
    except JSONDecodeError:
        raise WazuhError(1018)


async def manage_reserved_security_resource(method, resource_type, f_arguments):
    from wazuh.security import create_user, add_rule, add_role, add_policy, update_user, update_role, update_policy, \
        update_rule, remove_users, remove_roles, remove_policies, remove_rules, set_user_role, set_role_policy, \
        set_role_rule, remove_user_role, remove_role_policy, remove_role_rule

    from wazuh.core.cluster import local_client
    from wazuh.core.cluster.common import WazuhJSONEncoder
    from wazuh.core.cluster.common import as_wazuh_object

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

    lc = local_client.LocalClient()

    input_json = {
        'f': func[method][resource_type],
        'f_kwargs': f_arguments,
        'from_cluster': False,
        'wait_for_complete': False
    }

    # Distribute function to master node
    response = json.loads(await lc.execute(command=b'dapi',
                                           data=json.dumps(input_json, cls=WazuhJSONEncoder).encode(),
                                           wait_for_complete=False),
                          object_hook=as_wazuh_object)

    if isinstance(response, Exception):
        raise response

    return response


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
                                         '-unrru ROLE_ID [RULE_ID]'
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
    arg_parser.add_argument("-unur", "--unlink-user-roles", nargs='+', type=str, action='store', dest='unlink_user-role',
                            help="Unlink reserved security user from roles.")
    arg_parser.add_argument("-unrp", "--unlink-role-policies", nargs='+', type=str, action='store',
                            dest='unlink_role-policy',
                            help="Unlink reserved security role from policies.")
    arg_parser.add_argument("-unrru", "--unlink-role-rules", nargs='+', type=str, action='store', dest='unlink_role-rule',
                            help="Unlink reserved security role from rules.")
    args = arg_parser.parse_args()

    if not len(sys.argv) > 1:
        arg_parser.print_usage()
        sys.exit(0)

    try:
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
                elif method in ['link', 'unlink'] and values:
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
                result_table.append([resource_name.title(),
                                     method,
                                     ', '.join([str(item['id']) for item in result.affected_items]),
                                     '\n'.join(f"{', '.join(map(str, ids))} || {error}"
                                               for error, ids in result.failed_items.items())])

        table_headers = ['Resource', 'Method', 'Success', 'Failed']
        print(tabulate(result_table, headers=table_headers, tablefmt='fancy_grid'))
    except WazuhError as e:
        print(f"Error {e.code}: {e.message}")
    except Exception as e:
        print(f"Internal error: {e}")
