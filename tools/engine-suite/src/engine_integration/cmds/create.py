import shared.resource_handler as rs


def run(args, resource_handler: rs.ResourceHandler):
    integration_name = args['name']

    resource_handler.create_dir(integration_name)
    resource_handler.create_dir(f'{integration_name}/test')
    resource_handler.create_dir(f'{integration_name}/decoders')
    resource_handler.create_dir(f'{integration_name}/rules')
    resource_handler.create_dir(f'{integration_name}/outputs')
    resource_handler.create_dir(f'{integration_name}/filters')
    resource_handler.create_dir(f'{integration_name}/agent')
    resource_handler.create_file(f'{integration_name}/fields.yml')
    resource_handler.create_file(f'{integration_name}/logpar.yml')
    resource_handler.create_file(f'{integration_name}/documentation.yml')
    resource_handler.create_dir(f'{integration_name}/kvdbs')

def configure(subparsers):
    parser_create = subparsers.add_parser(
        'create', help='Create a new integration project scaffold on the current directory')

    parser_create.add_argument('name', type=str,
                               help=f'Name of the integration')

    parser_create.set_defaults(func=run)
