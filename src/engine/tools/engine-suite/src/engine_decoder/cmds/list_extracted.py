import re

import shared.resource_handler as rs


def get_logpar_fields(expr: str) -> list:
    ret = set()

    field_re_pattern = r'<([\w\.@~]+)?[\/\w\s:]*>'
    field_re = re.compile(field_re_pattern)
    ret = set(field_re.findall(expr))

    return ret


def run(args, resource_handler: rs.ResourceHandler):
    decoder_path = args['decoder']
    decoder = resource_handler.load_file(decoder_path, rs.Format.YML)

    extracted = set()

    if 'parse' in decoder:
        for entry in decoder['parse']['logpar']:
            for _, expr in entry.items():
                extracted = extracted.union(get_logpar_fields(expr))

    if 'normalize' in decoder:
        for block in decoder['normalize']:
            if 'logpar' in block:
                for entry in block['logpar']:
                    for _, expr in entry.items():
                        extracted = extracted.union(get_logpar_fields(expr))
            if 'map' in block:
                for entry in block['map']:
                    for f, _ in entry.items():
                        extracted.add(f)

    for f in sorted(extracted):
        print(f)


def configure(subparsers):
    parser_list_ext = subparsers.add_parser(
        'list-extracted', help='List all extracted fields from a decoder    ')

    parser_list_ext.add_argument('decoder', type=str,
                                 help=f'Decoder to analyze')

    parser_list_ext.set_defaults(func=run)
