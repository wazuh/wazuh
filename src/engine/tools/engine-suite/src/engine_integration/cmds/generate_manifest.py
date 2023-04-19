import shared.resource_handler as rs


def get_asset_names_fn(resource_handler: rs.ResourceHandler, results: list):
    def fn(file_path: str):
        asset = resource_handler.load_file(file_path, rs.Format.YML)
        results.append(asset['name'])

    return fn


def run(args, resource_handler: rs.ResourceHandler):
    manifest = {}
    manifest['name'] = f'integration/{resource_handler.current_dir_name()}/0'

    # Gets a list of the names of each asset type
    decoders = []
    resource_handler.walk_dir(
        "decoders", get_asset_names_fn(resource_handler, decoders), recursive=True)
    if len(decoders) > 0:
        manifest['decoders'] = decoders

    rules = []
    resource_handler.walk_dir(
        "rules", get_asset_names_fn(resource_handler, rules), recursive=True)
    if len(rules) > 0:
        manifest['rules'] = rules

    outputs = []
    resource_handler.walk_dir(
        "outputs", get_asset_names_fn(resource_handler, outputs), recursive=True)
    if len(outputs) > 0:
        manifest['outputs'] = outputs

    filters = []
    resource_handler.walk_dir(
        "filters", get_asset_names_fn(resource_handler, filters), recursive=True)
    if len(filters) > 0:
        manifest['filters'] = filters

    resource_handler.save_file('.', 'manifest.yml', manifest, rs.Format.YML)


def configure(subparsers):
    parser_generate_manifest = subparsers.add_parser(
        'generate-manifest', help='Generate the manifest file of all assets of the current integration')

    parser_generate_manifest.set_defaults(func=run)
