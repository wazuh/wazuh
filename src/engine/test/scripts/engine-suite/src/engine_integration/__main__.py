import sys
import argparse
from importlib.metadata import metadata

import shared.resource_handler as rs
from .cmds.create import configure as create_configure
from .cmds.generate_doc import configure as generate_doc_configure
from .cmds.generate_graph import configure as generate_graph_configure
from .cmds.generate_manifest import configure as generate_manifest_configure


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-integration')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')
    create_configure(subparsers)
    generate_doc_configure(subparsers)
    generate_graph_configure(subparsers)
    generate_manifest_configure(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    resource_handler = rs.ResourceHandler()
    args.func(vars(args), resource_handler)


if __name__ == '__main__':
    sys.exit(main())
