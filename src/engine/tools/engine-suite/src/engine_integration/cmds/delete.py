import shared.resource_handler as rs
import json
from shared.default_settings import Constants as DefaultSettings


def run(args, resource_handler: rs.ResourceHandler):
    api_socket = args['api_sock']
    namespace = args['namespace']

    on_dry_run = False
    if args['dry-run']:
        on_dry_run = True

    if args['integration-name']:
        integration_name = args['integration-name']
    else:
        print(f'Error: Needs an integration name to delete')
        return -1

    print(f'Removing integration named: {integration_name}')

    # Get integration from store
    available_integration_assets_list = []

    available_integration_assets = resource_handler.get_store_integration(
        api_socket, integration_name, namespace)
    if available_integration_assets['data']['content']:
        available_integration_assets_json = json.loads(
            available_integration_assets['data']['content'])
    else:
        print(
            f'Error can\'t update if the integration named {integration_name} does not exist')
        exit(1)

    # Get all assets from integration
    asset_type = ['decoders', 'rules', 'outputs', 'filters']
    for type_name in asset_type:
        if type_name in available_integration_assets_json.keys():
            for asset in available_integration_assets_json[type_name]:
                name = str(asset)
                available_integration_assets_list.append(name)
                print(f'Deleting asset {name}')
                if not on_dry_run:
                    try:
                        resource_handler.delete_catalog_file(
                            api_socket, type_name, name, namespace)
                    except Exception as err_inst:
                        print(
                            f'Will continue deleting, despite error: "{err_inst}"')
                        continue

    print(f'Deleting integration [{integration_name}]')
    try:
        if not on_dry_run:
            resource_handler.delete_catalog_file(
                api_socket, 'integration', f'integration/{integration_name}/0', namespace)
    except:
        print('Could not remove integration from the store')

    if on_dry_run:
        print('Finished dry-run.')


def configure(subparsers):
    parser_rm = subparsers.add_parser(
        'delete', help='Delete integration assets from the Engine Catalog. If a step fails it continue with the next')
    parser_rm.add_argument('-a', '--api-sock', type=str, default=DefaultSettings.SOCKET_PATH, dest='api_sock',
                           help=f'[default="{DefaultSettings.SOCKET_PATH}"] Engine instance API socket path')

    parser_rm.add_argument('integration-name', type=str,
                           help=f'Integration name to be deleted')

    parser_rm.add_argument('--dry-run', dest='dry-run', action='store_true',
                           help=f'default False, When True will print all the steps to apply without affecting the store')

    parser_rm.add_argument('-n', '--namespace', type=str, dest='namespace', default=DefaultSettings.DEFAULT_NS,
                           help=f'[default="{DefaultSettings.DEFAULT_NS}"] Namespace of the integration')

    parser_rm.set_defaults(func=run)
