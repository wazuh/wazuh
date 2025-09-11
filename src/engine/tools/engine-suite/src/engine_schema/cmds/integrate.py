from engine_schema.generate import generate
import shared.resource_handler as rs
from ._modules import configure as modules_configure
from ._modules import get_args as modules_get_args
from shared.default_settings import Constants as DefaultSettings


DEFAULT_ECS_VERSION = 'v8.17.0'
DEFAULT_INDEXER_DIR = '/etc/filebeat/'
DEFAULT_FIELDS_DIR = '/home/vagrant/engine/wazuh/src/engine/ruleset/schemas/'


def run(args, resource_handler: rs.ResourceHandler):

    ecs_version = args['ecs_version']
    api_socket = args['api_sock']
    indexer_path = args['indexer_dir']
    fields_path = args['schema_dir']
    modules = modules_get_args(args)
    jproperties, jmappings, jlogpar, jengine = generate(
        ecs_version, modules, resource_handler)

    # Apply changes to Engine instance
    print(f'Overriding wazuh-template.json in {indexer_path}...')
    resource_handler.save_file(
        indexer_path, 'wazuh-template', jmappings, rs.Format.JSON)
    # Update logpar_types in the catalog
    print(f'Updating logpar configuration...')
    resource_handler.update_catalog_file(
        api_socket, 'schema', 'schema/wazuh-logpar-types/0', jlogpar, rs.Format.JSON)
    # Update schema
    # TODO Update in catalog also when the Engine is updated to handle schemas
    print(f'Overriding fields.json in {fields_path}...')
    resource_handler.save_file(
        fields_path, 'fields', jproperties, rs.Format.JSON)
    # Update engine-schema in the catalog
    print(f'Updating engine-schema configuration...')
    resource_handler.update_catalog_file(
        api_socket, 'schema', 'schema/engine-schema/0', jengine, rs.Format.JSON)

    print('Success.')

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

    parser_integrate.add_argument('--api-sock', type=str, default=DefaultSettings.SOCKET_PATH,
                                  help=f'[default="{DefaultSettings.SOCKET_PATH}"] Engine instance API socket path')

    parser_integrate.add_argument('--indexer-dir', type=str, default=DEFAULT_INDEXER_DIR,
                                  help=f'[default="{DEFAULT_INDEXER_DIR}"] Path to directory where the wazuh-template.json indexer file is located')

    parser_integrate.add_argument('--schema-dir', type=str, default=DEFAULT_FIELDS_DIR,
                                  help=f'[default="{DEFAULT_FIELDS_DIR}"] Path to the director where the fields.json schema file is located')

    integrate_subparsers = parser_integrate.add_subparsers(title='subcommands')
    modules_configure(integrate_subparsers)

    parser_integrate.set_defaults(func=run)
