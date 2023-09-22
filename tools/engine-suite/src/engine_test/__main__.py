import sys
import argparse
from importlib.metadata import metadata
from engine_test.cmds.run import configure as configure_parser_run
from engine_test.cmds.add import configure as configure_parser_add
from engine_test.cmds.get import configure as configure_parser_get
from engine_test.cmds.list import configure as configure_parser_list

def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-test')

    parser.add_argument('-v', '--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(title='subcommands', required=True, dest='subcommand')

    configure_parser_run(subparsers)
    #configure_parser_add(subparsers)
    configure_parser_get(subparsers)
    configure_parser_list(subparsers)

    return parser.parse_args()

def main():
    args = parse_args()
    args.func(vars(args))

if __name__ == '__main__':
    sys.exit(main())
