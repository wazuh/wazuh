from pathlib import Path

from engine_schema.generate import generate
import shared.resource_handler as rs
from ._types import update_types_file

DEFAULT_OUTPUT_DIR = './'
DEFAULT_TYPES_PATH = None


def run(args, resource_handler: rs.ResourceHandler):
    """Execute the generate sub-command, callback function."""

    wcs_path = args['wcs_path']
    output_dir = args['output_dir']
    allowed_fields_path = args['allowed_fields_path']
    types_output = args['types_output']

    decoder_fields_schema, rule_fields_schema, jmappings, jlogpar, jengine = generate(
        wcs_path, resource_handler, allowed_fields_path)

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

    if types_output is not None:
        update_types_file(jmappings, types_output)
    print('Success.')


def configure(subparsers):
    """Configure the console arguments of the generate sub-command."""

    parser_generate = subparsers.add_parser(
        'generate', help='Generate the schema and associated configuration')

    parser_generate.add_argument('--wcs-path', type=str, required=True,
                                 help='Path to the Wazuh Common Schema (wcs_flat.yml) YAML file.')

    parser_generate.add_argument('--output-dir', type=str, default=DEFAULT_OUTPUT_DIR,
                                 help=f'[default="{DEFAULT_OUTPUT_DIR}"] Root directory to store generated files')

    parser_generate.add_argument('--allowed-fields-path', type=str, required=True,
                                 help='Path to the allowed fields JSON file used to filter the generated schema.')

    parser_generate.add_argument('--types-output', type=Path, default=DEFAULT_TYPES_PATH,
                                 help='Path to write the list of ECS field types. Provide a destination file when using this option. If omitted, the list is not generated.')

    parser_generate.set_defaults(func=run)
