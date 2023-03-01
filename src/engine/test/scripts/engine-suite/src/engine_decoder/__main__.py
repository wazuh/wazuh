import sys
import argparse
from importlib.metadata import metadata

import shared.resource_handler as rs
from .cmds.list_extracted import configure as list_ext_configure
from .cmds.syntax_update import configure as syntax_ext_configure


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-decoder')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(
        title='subcommands', required=True, dest='subcommand')
    list_ext_configure(subparsers)
    syntax_ext_configure(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    resource_handler = rs.ResourceHandler()
    args.func(vars(args), resource_handler)


if __name__ == '__main__':
    sys.exit(main())
