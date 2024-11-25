#!/usr/bin/env python3
import sys
import argparse
from importlib.metadata import metadata
from engine_test.cmds.add import configure as configure_add
from engine_test.cmds.run import configure as configure_run
from engine_test.cmds.get import configure as configure_get
from engine_test.cmds.list import configure as configure_list
from engine_test.cmds.delete import configure as configure_delete
from engine_test.conf.store import DEFAULT_CONFIG_FILE
from engine_test.cmds.session import configure as configure_session


def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-test')

    parser.add_argument('-c', '--config', help=f'Configuration file. Default: {DEFAULT_CONFIG_FILE}',
                        type=str, default=DEFAULT_CONFIG_FILE, dest='config_file')

    parser.add_argument('-v', '--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(title='subcommands', required=True, dest='subcommand')

    configure_run(subparsers)
    configure_add(subparsers)
    configure_get(subparsers)
    configure_list(subparsers)
    configure_delete(subparsers)

    # Session commands
    configure_session(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    sys.exit(main())
