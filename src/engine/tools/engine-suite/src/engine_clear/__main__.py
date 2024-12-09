import sys
import argparse
from importlib.metadata import metadata
from shared.default_settings import Constants as DefaultSettings

import shared.resource_handler as rs

DEF_RESOURCES = ['kvdbs', 'decoder', 'rule',
                 'output', 'filter', 'integration', 'policy']
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


def prompt_confirmation():
    print('\nAre you sure you want to delete them? [y/N]')
    answer = input()
    if answer.lower() != 'y':
        return False
    return True


def main():
    args = parse_args()
    resource_handler = rs.ResourceHandler()
    force = args.force
    namespaces = args.namespaces
    if not namespaces or len(namespaces) == 0:
        namespaces = resource_handler._get_all_namespaces(args.api_sock)['data']['namespaces']
    resources = args.resources if len(args.resources) > 0 else DEF_RESOURCES

    if 'kvdbs' in resources:
        response = resource_handler.get_kvdb_list(args.api_sock)
        to_delete = response['data']['dbs']
        if not force and len(to_delete) > 0:
            print('The following kvdbs will be deleted:')
            print('\n'.join(to_delete))
            if not prompt_confirmation():
                return 0

        for kvdb in to_delete:
            try:
                resource_handler.delete_kvdb(args.api_sock, kvdb)
            except Exception as e:
                print(f'Error deleting kvdb {kvdb}: {e}')

        remaining = resource_handler.get_kvdb_list(args.api_sock)[
            'data']['dbs']
        if len(remaining) > 0:
            print('\nThe following kvdbs could not be deleted:')
            print('\n'.join(remaining))

        resources.remove('kvdbs')

    for asset in resources:
        if asset == "policy":
            policies = []
            try:
                policies = resource_handler.get_policies_command(args.api_sock)['data']['data']
            except Exception as e:
                pass
            for policy in policies:
                try:
                    print(f'Deleting policy {policy}')
                    resource_handler.policy_store_delete(args.api_sock, policy)
                except Exception as e:
                    print(f'Error deleting {policy}: {e}')
        else:
            for namespace in namespaces:
                asset_partial = []
                try:
                    asset_partial += resource_handler.list_catalog(
                        args.api_sock, asset, namespace)
                except:
                    pass
                else:
                    assets = []
                    for partial in asset_partial:
                        versions = resource_handler.list_catalog(
                            args.api_sock, partial, namespace)
                        assets.extend(versions)

                    if not force and len(assets) > 0:
                        print(f'[{namespace}] The following assets will be deleted:')
                        print('\n'.join(assets))
                        if not prompt_confirmation():
                            continue

                    for asset_del in assets:
                        try:
                            resource_handler.delete_catalog_file(
                                args.api_sock, asset, asset_del, namespace)
                        except Exception as e:
                            print(f'Error deleting {asset_del}: {e}')
                    try:
                        remaining = resource_handler.list_catalog(
                            args.api_sock, asset, namespace)
                    except:
                        pass
                    else:
                        if len(remaining) > 0:
                            print('\nThe following assets could not be deleted:')
                            print('\n'.join(remaining))

    return 0


if __name__ == '__main__':
    sys.exit(main())
