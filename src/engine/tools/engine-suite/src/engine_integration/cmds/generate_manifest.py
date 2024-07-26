import shared.resource_handler as rs
from pathlib import Path


def get_asset_names_fn(resource_handler: rs.ResourceHandler, results: list):
    def fn(file_path: str):
        asset = resource_handler.load_file(file_path, rs.Format.YML)
        results.append(asset['name'])

    return fn


def run(args, resource_handler: rs.ResourceHandler):

    output_path = resource_handler.cwd()
    if args['output-path']:
        output_path = args['output-path']
        path = Path(output_path)
        if path.is_dir():
            output_path = str(path.resolve())
        else:
            print(f'Error: Directory does not exist ')
            return -1

    name = Path(output_path).resolve().name

    manifest = {}
    manifest['name'] = f'integration/{name}/0'

    # Gets a list of the names of each asset type
    decoders = []
    resource_handler.walk_dir(
        output_path + "/decoders", get_asset_names_fn(resource_handler, decoders), recursive=True)
    if len(decoders) > 0:
        manifest['decoders'] = decoders

    rules = []
    resource_handler.walk_dir(
        output_path + "/rules", get_asset_names_fn(resource_handler, rules), recursive=True)
    if len(rules) > 0:
        manifest['rules'] = rules

    outputs = []
    resource_handler.walk_dir(
        output_path + "/outputs", get_asset_names_fn(resource_handler, outputs), recursive=True)
    if len(outputs) > 0:
        manifest['outputs'] = outputs

    filters = []
    resource_handler.walk_dir(
        output_path + "/filters", get_asset_names_fn(resource_handler, filters), recursive=True)
    if len(filters) > 0:
        manifest['filters'] = filters

    resource_handler.save_file(
        output_path, 'manifest.yml', manifest, rs.Format.YML)
    
    return 0


def configure(subparsers):
    parser_generate_manifest = subparsers.add_parser(
        'generate-manifest', help='Generate the manifest file of all assets of the '
        'currentintegration. Name of the integration is taken from the name of the'
        'directory used')

    parser_generate_manifest.add_argument('-p', '--output-path', type=str,
        dest='output-path', help=f'[default=current directory] Where to place'
        'the resultant manifest.yml')

    parser_generate_manifest.set_defaults(func=run)
