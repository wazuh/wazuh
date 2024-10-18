import sys
import shared.resource_handler as rs
from shared.resource_handler import Format, StringToFormat


def run(args, resource_handler: rs.ResourceHandler):

    # Get the params
    api_socket: str = args['api_socket']
    namespace: str = args['namespace']
    name: str = args['asset-name']
    inFormat: Format = StringToFormat(args['format'])
    content = args['content']

    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    # Create the api request
    try:
        resource_handler.update_catalog_file(
            api_socket, '', name, content, namespace, inFormat)
    except Exception as e:
        sys.exit(f'Error updating asset: {e}')

    return 0


def configure(subparsers):
    parser_update = subparsers.add_parser(
        'update', help='Update an asset.')

    parser_update.add_argument('asset-name', type=str,
                               help=f'Name of asset to update.')

    parser_update.add_argument('-c', '--content', type=str, default='',
                               help='Content of the item, can be passed as argument or '
                               'redirected from a file using the "|" operator or the "<" '
                               'operator.')

    parser_update.set_defaults(func=run)
