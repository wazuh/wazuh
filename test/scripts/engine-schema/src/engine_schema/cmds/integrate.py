from engine_schema.generate import generate
import engine_schema.resource_handler as rs
from ._modules import configure as modules_configure
from ._modules import get_args as modules_get_args


DEFAULT_ECS_VERSION = 'v8.5.0-rc1'
DEFAULT_API_SOCK = '/var/ossec/queue/sockets/engine-api'
DEFAULT_INDEXER_FILE = '/etc/filebeat/wazuh-template.json'


def run(args, resource_handler: rs.ResourceHandler):

    ecs_version = args['ecs_version']
    api_socket = args['api_sock']
    indexer_path = args['indexer_file']
    modules_dir, modules = modules_get_args(args)
    jproperties, jmappings, jlogpar = generate(
        ecs_version, modules_dir, modules, resource_handler)

    # Apply changes to Engine instance
    print(f'Overriding "{indexer_path}/{wazuh-template.json}"...')
    resource_handler.save_file(
        indexer_path, 'wazuh-template', jproperties, rs.Format.JSON)
    print(f'Updating logpar configuration...')
    # TODO Send and receive api message

    print('Restart the manager to make changes effective, run:')
    print('     systemctl restart wazuh-manager')


def configure(subparsers):
    """Configure the console arguments of the generate sub-command

    Args:
        subparsers (_SubParsersAction): argparser subparser object in which this sub-command is added
    """
    parser_integrate = subparsers.add_parser(
        'integrate', help='Generate the schema and associated configuration and apply them to an Engine instance')

    parser_integrate.add_argument('--ecs-version', type=str, default=DEFAULT_ECS_VERSION,
                                  help=f'[default="{DEFAULT_ECS_VERSION}"] ECS version to use for the schema generation')

    parser_integrate.add_argument('--api-sock', type=str, default=DEFAULT_API_SOCK,
                                  help=f'[default="{DEFAULT_API_SOCK}"] Engine instance API socket path')

    parser_integrate.add_argument('--indexer-file', type=str, default=DEFAULT_INDEXER_FILE,
                                  help=f'[default="{DEFAULT_INDEXER_FILE}"] Path to the indexer mapping file being used by the enfine instance')

    integrate_subparsers = parser_integrate.add_subparsers(title='subcommands')
    modules_configure(integrate_subparsers)

    parser_integrate.set_defaults(func=run)
