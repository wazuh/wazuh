import sys
import argparse
from importlib.metadata import metadata
from google.protobuf.json_format import ParseDict
from yaml import safe_load as yaml_load
from shared.default_settings import Constants as DefaultSettings
from api_communication.client import APIClient
from api_communication.proto import catalog_pb2 as api_catalog
from api_communication.proto import kvdb_pb2 as api_kvdb
from api_communication.proto import router_pb2 as api_router
from api_communication.proto import policy_pb2 as api_policy
from api_communication.proto import tester_pb2 as api_tester
from api_communication.proto.engine_pb2 import GenericStatus_Response

DEF_RESOURCES = ['kvdbs', 'decoders', 'rules',
                 'outputs', 'filters', 'integrations', 'policies', 'test_sessions', 'routes']
DEF_NAMESPACES = ['user', 'wazuh', 'system']


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-clear')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')
    parser.add_argument('--api-sock', default=DefaultSettings.SOCKET_PATH,
                        help='Path to the engine-api socket')
    parser.add_argument('-f, --force', action='store_true',
                        default=False, dest='force', help='Force the execution of the command')
    parser.add_argument('-n, --namespaces', nargs='*',
                        dest='namespaces', help=f'Namespace to delete the resources from. Default:{DEF_NAMESPACES}')
    parser.add_argument('resources', nargs='*',
                        help=f'Resources to clear. Default:{DEF_RESOURCES}')

    return parser.parse_args()


def prompt_confirmation(force: bool, resource_name: str, resources: list) -> bool:
    if force:
        return True
    else:
        print(f'\nThe following {resource_name} will be deleted:')
        print('\n'.join(f'  - {name}' for name in resources))
        print('Do you want to delete them? [y/N]')
    answer = input()
    if answer.lower() != 'y':
        return False
    return True


def main():
    args = parse_args()
    force = args.force
    namespaces = args.namespaces or DEF_NAMESPACES
    resources = args.resources or DEF_RESOURCES

    client = APIClient(args.api_sock)

    resource_name = 'routes'
    if resource_name in resources:
        request = dict()
        error, response = client.jsend(
            request, api_router.TableGet_Request(), api_router.TableGet_Response())
        if error:
            print(f'Error getting routes: {error}, skipping')
        else:
            proto_res: api_router.TableGet_Response = ParseDict(
                response, api_router.TableGet_Response())

            if len(proto_res.table) > 0:
                routes = [entry.name for entry in proto_res.table]
                if prompt_confirmation(force, resource_name, routes):
                    for route in routes:
                        request = dict()
                        request['name'] = route

                        error, response = client.jsend(
                            request, api_router.RouteDelete_Request(), GenericStatus_Response())
                        if error:
                            print(f'Error deleting route {route}: {error}')
                        else:
                            print(f'Route {route} deleted')
        resources.remove('routes')

    resource_name = 'test_sessions'
    if resource_name in resources:
        request = dict()
        error, response = client.jsend(
            request, api_tester.TableGet_Request(), api_tester.TableGet_Response())
        if error:
            print(f'Error getting test sessions: {error}, skipping')
        else:
            proto_res: api_tester.TableGet_Response = ParseDict(
                response, api_tester.TableGet_Response())

            if len(proto_res.sessions) > 0:
                sessions = [session.name for session in proto_res.sessions]
                if prompt_confirmation(force, resource_name, sessions):
                    for session in sessions:
                        request = dict()
                        request['name'] = session

                        error, response = client.jsend(
                            request, api_tester.SessionDelete_Request(), GenericStatus_Response())
                        if error:
                            print(f'Error deleting session {session}: {error}')
                        else:
                            print(f'Test session {session} deleted')
        resources.remove('test_sessions')

    resource_name = 'policies'
    if resource_name in resources:
        request = dict()
        error, response = client.jsend(
            request, api_policy.PoliciesGet_Request(), api_policy.PoliciesGet_Response())
        if error:
            print(f'Error getting policies: {error}, skipping')
        else:
            proto_res: api_policy.PoliciesGet_Response = ParseDict(
                response, api_policy.PoliciesGet_Response())

            if len(proto_res.data) > 0:
                policies = proto_res.data
                if prompt_confirmation(force, resource_name, policies):
                    for policy in policies:
                        request = dict()
                        request['policy'] = policy

                        error, response = client.jsend(
                            request, api_policy.StoreDelete_Request(), GenericStatus_Response())
                        if error:
                            print(f'Error deleting policy {policy}: {error}')
                        else:
                            print(f'Policy {policy} deleted')
        resources.remove('policies')

    resource_name = 'kvdbs'
    if resource_name in resources:
        request = dict()
        request['must_be_loaded'] = False
        error, response = client.jsend(
            request, api_kvdb.managerGet_Request(), api_kvdb.managerGet_Response())
        if error:
            print(f'Error getting kvdbs: {error}, skipping')
        else:
            proto_res: api_kvdb.managerGet_Response = ParseDict(
                response, api_kvdb.managerGet_Response())

            if len(proto_res.dbs) > 0:
                kvdbs = proto_res.dbs
                if prompt_confirmation(force, resource_name, kvdbs):
                    for kvdb in kvdbs:
                        request = dict()
                        request['name'] = kvdb

                        error, response = client.jsend(
                            request, api_kvdb.managerDelete_Request(), GenericStatus_Response())
                        if error:
                            print(f'Error deleting kvdb {kvdb}: {error}')
                        else:
                            print(f'Kvdb {kvdb} deleted')
        resources.remove('kvdbs')

    assets = [['integrations', 'integration'], ['decoders', 'decoder'], ['rules', 'rule'], [
        'outputs', 'output'], ['filters', 'filter']]
    for asset in assets:
        resource_name = asset[0]
        collection_name = asset[1]

        if resource_name in resources:
            for namespace in namespaces:
                to_delete = list()
                request = dict()
                request['namespaceid'] = namespace
                request['name'] = collection_name
                request['format'] = 'yaml'
                error, response = client.jsend(
                    request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())
                if error:
                    continue
                proto_res: api_catalog.ResourceGet_Response = ParseDict(
                    response, api_catalog.ResourceGet_Response())
                partial_assets = yaml_load(proto_res.content)

                for partial in partial_assets:
                    request = dict()
                    request['namespaceid'] = namespace
                    request['name'] = partial
                    request['format'] = 'yaml'
                    error, response = client.jsend(
                        request, api_catalog.ResourceGet_Request(), api_catalog.ResourceGet_Response())
                    if error:
                        print(f'Error getting {partial}: {error}, skipping')
                        continue

                    proto_res: api_catalog.ResourceGet_Response = ParseDict(
                        response, api_catalog.ResourceGet_Response())
                    versions = yaml_load(proto_res.content)

                    to_delete.extend(versions)

                if len(to_delete) > 0:
                    if prompt_confirmation(force, resource_name, to_delete):
                        for asset_to_delete in to_delete:
                            request = dict()
                            request['namespaceid'] = namespace
                            request['name'] = asset_to_delete

                            error, response = client.jsend(
                                request, api_catalog.ResourceDelete_Request(), GenericStatus_Response())
                            if error:
                                print(f'Error deleting {asset_to_delete}: {error}')
                            else:
                                print(f'{asset_to_delete} deleted')
            resources.remove(resource_name)

    if len(resources) > 0:
        print('The following resources were not found: {resources}')
        print(f'Available resources: {DEF_RESOURCES}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
