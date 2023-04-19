import shared.resource_handler as rs

DEFAULT_API_SOCK = '/var/ossec/queue/sockets/engine-api'


def run(args, resource_handler: rs.ResourceHandler):
    api_socket = args['api_sock']

    # Create kvdbs
    print('Creating kvdbs...')
    resource_handler.recursive_create_kvdbs(
        api_socket, resource_handler.cwd(), True)

    # Recursively add all components to the catalog
    print('Loading decoders...')
    resource_handler.recursive_load_catalog(
        api_socket, resource_handler.cwd(), 'decoders', True)
    print('Loading rules...')
    resource_handler.recursive_load_catalog(
        api_socket, resource_handler.cwd(), 'rules', True)
    print('Loading outputs...')
    resource_handler.recursive_load_catalog(
        api_socket, resource_handler.cwd(), 'outputs', True)
    print('Loading filters...')
    resource_handler.recursive_load_catalog(
        api_socket, resource_handler.cwd(), 'filters', True)

    # Add integration manifest
    try:
        print('Loading integration manifest...')
        manifest = resource_handler.load_file('manifest.yml', rs.Format.YML)
    except FileNotFoundError:
        print('No manifest.yml file found in the integration directory. Use the generate-manifest command to generate it and manually add it to the Catalog.')
        return -1
    else:
        resource_handler.add_catalog_file(
            api_socket, 'integration', f'integration/{resource_handler.current_dir_name()}/0', manifest, rs.Format.YML)


def configure(subparsers):
    parser_add = subparsers.add_parser(
        'add', help='Add integration components to the Engine\' Catalog')
    parser_add.add_argument('--api-sock', type=str, default=DEFAULT_API_SOCK,
                            help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_add.set_defaults(func=run)
