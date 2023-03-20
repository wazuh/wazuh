import shared.resource_handler as rs
import graphviz as gv


def get_asset_sources_fn(resource_handler: rs.ResourceHandler, results: list):
    def fn(file_path: str):
        decoder = resource_handler.load_file(file_path, rs.Format.YML)
        results.append(
            (decoder['name'], decoder['sources'] if 'sources' in decoder else []))

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
    # Gets a list of tuples with the name and sources of the assets
    resource_handler.walk_dir(
        type_name, get_asset_sources_fn(resource_handler, assets), recursive=True)

    dot_graph = create_dot_graph(assets)

    resource_handler.create_file(f'{type_name}.dot', dot_graph.source)


def configure(subparsers):
    parser_generate_graph = subparsers.add_parser(
        'generate-graph', help='Generate dot graph for the integration, must be run from the integration directory')

    parser_generate_graph.add_argument("type", type=str, help="Component type to generate the graph", choices=[
                                       "decoders", "rules", "outputs"])

    parser_generate_graph.set_defaults(func=run)
