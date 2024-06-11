#!/usr/bin/env python3
import sys
import argparse
from importlib.metadata import metadata
from engine_test.cmds.run import RunCommand
from engine_test.cmds.add import AddCommand
from engine_test.cmds.get import GetCommand
from engine_test.cmds.list import ListCommand
from engine_test.cmds.delete import DeleteCommand
from engine_test.config import Config

def parse_args():
    meta = metadata('engine-suite')
    parser = argparse.ArgumentParser(prog='engine-test')

    parser.add_argument('-c', '--config', help=f'Configuration file. Default: {Config.get_config_file()}',
                            type=str, default=Config.get_config_file(), dest='config_file')

    parser.add_argument('-v', '--version', action='version',
                        version=f'%(prog)s {meta.get("Version")}')

    # dest used because of bug: https://bugs.python.org/issue29298
    subparsers = parser.add_subparsers(title='subcommands', required=True, dest='subcommand')

    run_command = RunCommand()
    run_command.configure(subparsers)

    add_command = AddCommand()
    add_command.configure(subparsers)

    get_command = GetCommand()
    get_command.configure(subparsers)

    list_command = ListCommand()
    list_command.configure(subparsers)

    delete_command = DeleteCommand()
    delete_command.configure(subparsers)

    return parser.parse_args()

def main():
    args = parse_args()
    args.func(vars(args))

if __name__ == '__main__':
    sys.exit(main())
