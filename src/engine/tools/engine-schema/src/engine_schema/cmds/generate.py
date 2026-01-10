from pathlib import Path

from engine_schema.generate import generate
from engine_schema import resource_handler as rs
from ._types import update_types_file

DEFAULT_OUTPUT_DIR = './'
DEFAULT_TYPES_PATH = None


def run(args, resource_handler: rs.ResourceHandler):
    """Execute the generate sub-command, callback function."""

    wcs_path = args['wcs_path']
    output_dir = args['output_dir']
    types_output = args['types_output']
    decoder_template = args['decoder_template']

    decoder_fields_schema, jmappings, jlogpar, jengine = generate(
        wcs_path, resource_handler)

    # Save generated files
    print(f'Saving files to "{output_dir}"...')

    _inline_decoder_template(
        decoder_template, decoder_fields_schema, output_dir, resource_handler)

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
                                 help='Path to the Wazuh Common Schema YAML file, directory containing YAML files, or comma-separated list of YAML files. If a directory is provided, all .yml and .yaml files will be merged. If comma-separated paths are provided, all specified files will be merged.')

    parser_generate.add_argument('--output-dir', type=str, default=DEFAULT_OUTPUT_DIR,
                                 help=f'[default="{DEFAULT_OUTPUT_DIR}"] Root directory to store generated files')

    parser_generate.add_argument('--decoder-template', type=str, required=True,
                                 help='Path to wazuh-decoders.json template file for fields injection.')

    parser_generate.add_argument('--types-output', type=Path, default=DEFAULT_TYPES_PATH,
                                 help='Path to write the list of ECS field types. Provide a destination file when using this option. If omitted, the list is not generated.')

    parser_generate.set_defaults(func=run)


def _inline_decoder_template(template_path: str, fields_decoder: dict, output_dir: str,
                              resource_handler: rs.ResourceHandler) -> None:
    template = resource_handler.load_file(template_path, rs.Format.JSON)
    definitions = template.get('definitions')
    if not isinstance(definitions, dict):
        raise ValueError('Template has no definitions block')
    if definitions.get('_fieldsDecoder') != "__FIELDS_DECODER_PLACEHOLDER__":
        raise ValueError('Template placeholder not found in definitions')
    definitions['_fieldsDecoder'] = fields_decoder
    resource_handler.save_file(output_dir, 'wazuh-decoders', template, rs.Format.JSON)
    print('Generated wazuh-decoders.json')
