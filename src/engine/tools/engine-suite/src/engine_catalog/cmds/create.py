import sys
import shared.resource_handler as rs
from shared.resource_handler import Format, StringToFormat


def run(args, resource_handler: rs.ResourceHandler):

    # Get the params
    api_socket: str = args['api_socket']
    namespace: str = args['namespace']
    type: str = args['asset-type']
    inFormat: Format = StringToFormat(args['format'])
    content = args['content']

    # Read all content from stdin
    if not content:
        content = sys.stdin.read()

    # Create the api request
    try:
        resource_handler.add_catalog_file(
            api_socket, type, '', content, namespace, inFormat)
    except Exception as e:
        sys.exit(f'Error updating asset: {e}')

    return 0


def configure(subparsers):
    parser_create = subparsers.add_parser(
        'create', help='Create an asset.')

    parser_create.add_argument('asset-type', type=str,
                               help=f'Type of asset to create.')

    parser_create.add_argument('-c', '--content', type=str, default='',
                               help='Content of the item, can be passed as argument or '
                               'redirected from a file using the "|" operator or the "<" '
                               'operator.')

    parser_create.set_defaults(func=run)
