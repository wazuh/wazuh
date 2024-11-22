import sys
import shared.resource_handler as rs


def run(args, resource_handler: rs.ResourceHandler):

    # Get the params
    api_socket: str = args['api_socket']
    namespace: str = args['namespace']
    asset: str = args['asset']

    # Create the api request
    try:
        resource_handler.delete_catalog_file(api_socket, '', asset, namespace)
    except Exception as e:
        sys.exit(f'Error deleting asset or collection: {e}')

    return 0


def configure(subparsers):
    parser_delete = subparsers.add_parser(
        'delete', help='delete asset-type[/asset-name[/version]]: Delete an asset or a collection.')

    parser_delete.add_argument('asset', type=str,
                               help=f'asset or collection to delete: asset-type[/asset-name[/version]]')

    parser_delete.set_defaults(func=run)
