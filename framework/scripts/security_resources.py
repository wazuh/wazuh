import argparse
import asyncio
import json
import logging
from functools import reduce
from json import JSONDecodeError
from operator import or_

from connexion import ProblemException

from api.models.security import RoleModel, RuleModel, PolicyModel, CreateUserModel
from api.util import remove_nones_to_dict
from wazuh import WazuhError
from wazuh.core.cluster import local_client
from wazuh.core.cluster.common import WazuhJSONEncoder
from wazuh.core.cluster.common import as_wazuh_object
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.security import create_user, add_rule, add_role, add_policy

logger = logging.getLogger('wazuh')


async def validate_resource(resource, r_type):
    resource_body = {
        'users': CreateUserModel,
        'roles': RoleModel,
        'policies': PolicyModel,
        'rules': RuleModel
    }

    try:
        loaded_json = json.loads(resource)
    except JSONDecodeError:
        raise WazuhError(1018)
    return await resource_body[r_type].get_kwargs(loaded_json)


async def add_reserved_security_resource(resource_type, f_kwargs):
    func = {
        'users': create_user,
        'roles': add_role,
        'policies': add_policy,
        'rules': add_rule
    }

    lc = local_client.LocalClient()

    input_json = {
        'f': func[resource_type],
        'f_kwargs': f_kwargs,
        'from_cluster': False,
        'wait_for_complete': False
    }

    repsonse = json.loads(await lc.execute(command=b'dapi',
                                           data=json.dumps(input_json, cls=WazuhJSONEncoder).encode(),
                                           wait_for_complete=False),
                          object_hook=as_wazuh_object)

    if isinstance(repsonse, Exception):
        raise repsonse

    return repsonse


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
    arg_parser.add_argument("-au", "--add-user", nargs='+', type=str, action='store', dest='add_users',
                            help="Add reserved security users.")
    arg_parser.add_argument("-ar", "--add-role", nargs='+', type=str, action='store', dest='add_roles',
                            help="Add reserved security roles.")
    arg_parser.add_argument("-ap", "--add-policy", nargs='+', type=str, action='store', dest='add_policies',
                            help="Add reserved security policies.")
    arg_parser.add_argument("-aru", "--add-rule", nargs='+', type=str, action='store', dest='add_rules',
                            help="Add reserved security rules.")
    arg_parser.add_argument("-ru", "--remove-user", nargs='+', type=str, action='store', dest='remove_users',
                            help="Add reserved security users.")
    arg_parser.add_argument("-rr", "--remove-role", nargs='+', type=str, action='store', dest='remove_roles',
                            help="Add reserved security roles.")
    arg_parser.add_argument("-rp", "--remove-policy", nargs='+', type=str, action='store', dest='remove_policies',
                            help="Add reserved security policies.")
    arg_parser.add_argument("-rru", "--remove-rule", nargs='+', type=str, action='store', dest='remove_rules',
                            help="Add reserved security rules.")
    args = arg_parser.parse_args()

    try:
        for key, values in args.__dict__.items():
            method, resource_name = key.split('_')
            result = AffectedItemsWazuhResult()
            for resource in (values or []):
                kwargs = remove_nones_to_dict(asyncio.run(validate_resource(resource, resource_name)))
                result |= asyncio.run(add_reserved_security_resource(resource_name, kwargs))

            if result.affected_items or result.failed_items:
                print_results(resource_name, result)

    except WazuhError as e:
        print(f"Error {e.code}: {e.message}")
    except ProblemException as e:
        print(f'Bad format error: {e.detail}')
    except Exception as e:
        print(f"Internal error: {e}")
