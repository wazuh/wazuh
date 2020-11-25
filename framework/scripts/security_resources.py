import argparse
import asyncio
import json
import logging
from json import JSONDecodeError
from tabulate import tabulate

from connexion import ProblemException

from api.models.security import RoleModel, RuleModel, PolicyModel, CreateUserModel, UpdateUserModel
from api.util import remove_nones_to_dict
from wazuh import WazuhError
from wazuh.core.cluster import local_client
from wazuh.core.cluster.common import WazuhJSONEncoder
from wazuh.core.cluster.common import as_wazuh_object
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.security import create_user, add_rule, add_role, add_policy, update_user, update_role, update_policy, \
    update_rule, remove_users, remove_roles, remove_policies, remove_rules, set_user_role, set_role_policy, \
    set_role_rule

logger = logging.getLogger('wazuh')


async def validate_resource(resource, r_type):
    resource_body = {
        'user': CreateUserModel,
        'role': RoleModel,
        'policy': PolicyModel,
        'rule': RuleModel,
        'update_user': UpdateUserModel
    }

    try:
        loaded_json = json.loads(resource)
    except JSONDecodeError:
        raise WazuhError(1018)
    return await resource_body[r_type].get_kwargs(loaded_json)


async def manage_reserved_security_resource(method, resource_type, f_arguments):
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
        }
    }

    lc = local_client.LocalClient()

    input_json = {
        'f': func[method][resource_type],
        'f_kwargs': f_arguments,
        'from_cluster': False,
        'wait_for_complete': False
    }

    response = json.loads(await lc.execute(command=b'dapi',
                                           data=json.dumps(input_json, cls=WazuhJSONEncoder).encode(),
                                           wait_for_complete=False),
                          object_hook=as_wazuh_object)

    if isinstance(response, Exception):
        raise response

    return response


def print_results(resource_name, full_result):
    print(resource_name.title())
    print(f"{'-' * len(resource_name)}")
    if not full_result.affected_items:
        print('No security resources were managed.\n')
    else:
        if full_result.failed_items:
            print('Some security resources could not be managed.\n')
        else:
            print('All security resources were managed.')
            return
    print('Failed resources:\n')
    for error, ids in full_result.failed_items.items():
        print(f"IDs: {', '.join(ids)}")
        print(f"\t{error}\n\n")


if __name__ == "__main__":

    arg_parser = argparse.ArgumentParser()
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
    arg_parser.add_argument("-lrp", "--link-role-policies", nargs='+', type=str, action='store', dest='link_role-policy',
                            help="Link reserved security role with policies.")
    arg_parser.add_argument("-lrru", "--link-role-rules", nargs='+', type=str, action='store', dest='link_role-rule',
                            help="Link reserved security role with rules.")
    args = arg_parser.parse_args()

    try:
        result_table = list()
        for key, values in args.__dict__.items():
            method, resource_name = key.split('_')
            result = AffectedItemsWazuhResult()
            if method == 'add' and values:
                for resource in values:
                    kwargs = remove_nones_to_dict(asyncio.run(validate_resource(resource, resource_name)))
                    result |= asyncio.run(manage_reserved_security_resource(method, resource_name, kwargs))
            elif method == 'update' and values:
                r_id, new_value = values
                kwargs = remove_nones_to_dict(asyncio.run(
                    validate_resource(new_value, resource_name if resource_name != 'user' else 'update_user')))
                kwargs[f'{resource_name}_id'] = r_id
                result |= asyncio.run(manage_reserved_security_resource(method, resource_name, kwargs))
            elif method == 'remove' and values:
                if not all(map(str.isnumeric, values)):
                    raise WazuhError(4019, extra_message='Remove methods only allow IDs')
                result |= asyncio.run(manage_reserved_security_resource(method, resource_name,
                                                                        {f'{resource_name}_ids': values}))

            if result.affected_items or result.failed_items:
                result_table.append([resource_name.title(),
                                     method,
                                     ', '.join([str(item['id']) for item in result.affected_items]),
                                     '\n'.join(f"{ids} || {error}" for error, ids in result.failed_items.items())])

        table_headers = ['Resource', 'Method', 'Success', 'Failed']
        print(tabulate(result_table, headers=table_headers, tablefmt='fancy_grid'))
    except WazuhError as e:
        print(f"Error {e.code}: {e.message}")
    except ProblemException as e:
        print(f'Bad format error: {e.detail}')
    except Exception as e:
        print(f"Internal error: {e}")
