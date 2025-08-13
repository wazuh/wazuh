from engine_schema.generate import generate
import shared.resource_handler as rs
from ._modules import configure as modules_configure
from ._modules import get_args as modules_get_args

DEFAULT_ECS_VERSION = 'v8.17.0'
DEFAULT_OUTPUT_DIR = './'


def run(args, resource_handler: rs.ResourceHandler):
    """Execute the generate sub-command, callback function.

    Generates the wazuh schema and all needed configuration, optionally add \
ECS field modules and apply changes on an engine instance through the API socket

    Args:
        args (Namespace): Cli parsed arguments
        resources (Optional[List[PackagePath]]): Data resources of this package
    """

    ecs_version = args['ecs_version']
    output_dir = args['output_dir']
    allowed_fields_path = args['allowed_fields_path']
    modules = modules_get_args(args)
    decoder_fields_schema, rule_fields_schema, jmappings, jlogpar, jengine = generate(
        ecs_version, modules, resource_handler, allowed_fields_path)

    # Save generated files
    print(f'Saving files to "{output_dir}"...')
    resource_handler.save_file(
        output_dir, 'fields_decoder', decoder_fields_schema, rs.Format.JSON)
    resource_handler.save_file(
        output_dir, 'fields_rule', rule_fields_schema, rs.Format.JSON)
    resource_handler.save_file(
        output_dir, 'wazuh-template', jmappings, rs.Format.JSON)
    resource_handler.save_file(
        output_dir, 'wazuh-logpar-overrides', jlogpar, rs.Format.JSON)
    resource_handler.save_file(
        output_dir, 'engine-schema', jengine, rs.Format.JSON)
    print('Success.')


def configure(subparsers):
    """Configure the console arguments of the generate sub-command

    Args:
        subparsers (_SubParsersAction): argparser subparser object in which this sub-command is added
    """
    parser_generate = subparsers.add_parser(
        'generate', help='Generate the schema and associated configuration')

    parser_generate.add_argument('--ecs-version', type=str, default=DEFAULT_ECS_VERSION,
                                 help=f'[default="{DEFAULT_ECS_VERSION}"] ECS version to use for the schema generation')

    parser_generate.add_argument('--output-dir', type=str, default=DEFAULT_OUTPUT_DIR,
                                 help=f'[default="{DEFAULT_OUTPUT_DIR}"] Root directory to store generated files')

    parser_generate.add_argument('--allowed-fields-path', type=str, required=True,
                                 help='Path to the allowed fields JSON file. It will be used to filter \
                                the generated schema.')

    generate_subparsers = parser_generate.add_subparsers(title='subcommands')
    modules_configure(generate_subparsers)

    parser_generate.set_defaults(func=run)
