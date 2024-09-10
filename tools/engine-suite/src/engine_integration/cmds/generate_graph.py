import shared.resource_handler as rs
import graphviz as gv
from pathlib import Path


def get_asset_sources_fn(resource_handler: rs.ResourceHandler, results: list):
    # load manifest file
    manifest = resource_handler.load_file('manifest.yml', rs.Format.YML)

    def fn(file_path: str):
        decoder = resource_handler.load_file(file_path, rs.Format.YML)
        for type in manifest:
            if type is not 'name':
                if decoder['name'] in manifest[type]:
                    print(f'Loading {file_path}')
                    results.append(
                        (decoder['name'], decoder['parents'] if 'parents' in decoder else []))

    return fn


def create_dot_graph(data):
    # Initialize a directed graph
    dot = gv.Digraph(engine='neato')
    dot.attr('node', shape='ellipse', width='0.5', height='0.5')
    dot.attr(splines='true', overlap='scale', rankdir='LR', concentrate='true')

    # Iterate through the data list
    for item in data:
        node_name, parents = item

        # Create the node
        dot.node(node_name)

        # Add edges between node and its parents
        for parent in parents:
            dot.edge(parent, node_name)

    return dot


def run(args, resource_handler: rs.ResourceHandler):
    assets = []
    type_name = args['type']
    # Gets a list of tuples with the name and parents of the assets
    type_path = Path(resource_handler.cwd()).parent.parent / type_name
    type_path = type_path.resolve()
    print(f'Walking through {type_path}')
    for file in type_path.rglob('*.yml'):
        process = get_asset_sources_fn(resource_handler, assets)
        process(file.as_posix())


    dot_graph = create_dot_graph(assets)

    resource_handler.create_file(f'{type_name}.dot', dot_graph.source)


def configure(subparsers):
    parser_generate_graph = subparsers.add_parser(
        'generate-graph', help='Generate dot graph for the integration, must be run from the integration directory')

    parser_generate_graph.add_argument("type", type=str, help="Component type to generate the graph", choices=[
                                       "decoders", "rules", "outputs"])

    parser_generate_graph.set_defaults(func=run)
