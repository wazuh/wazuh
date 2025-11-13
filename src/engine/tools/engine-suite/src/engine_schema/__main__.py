import sys
import argparse
from importlib.metadata import metadata

from engine_schema.cmds.generate import configure as configure_generate_parser
import shared.resource_handler as rs


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-schema')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    subparsers = parser.add_subparsers(title='subcommands', required=True, dest='subcommand')
    configure_generate_parser(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    resource_handler = rs.ResourceHandler()
    args.func(vars(args), resource_handler)


if __name__ == '__main__':
    sys.exit(main())
