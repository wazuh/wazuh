import sys
import shared.resource_handler as rs
from shared.resource_handler import Format, StringToFormat


def run(args, resource_handler: rs.ResourceHandler):

    # Get the params
    api_socket: str = args['api_socket']
    namespace: str = args['namespace']
    asset: str = args['asset']
    outFormat: Format = StringToFormat(args['format'])

    # Create the api request
    try:
        result = resource_handler.get_catalog_file(
            api_socket, '', asset, namespace, outFormat)['data']['content']
        print(result)

    except Exception as e:
        sys.exit(f'Error getting asset or collection: {e}')


    return 0


def configure(subparsers):
    parser_get = subparsers.add_parser(
        'get', help='Get asset-type[/asset-id[/item-version]]: Get an asset or list a collection.')

    parser_get.add_argument('asset', type=str,
                            help=f'asset or collection to list: item-type[/item-id]')

    parser_get.set_defaults(func=run)
