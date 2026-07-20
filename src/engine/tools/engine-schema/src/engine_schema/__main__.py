import sys
import argparse

from engine_schema.cmds.generate import configure as configure_generate_parser
from engine_schema import resource_handler as rs


def parse_args():

    parser = argparse.ArgumentParser(prog='engine-schema')

    subparsers = parser.add_subparsers(title='subcommands', required=True, dest='subcommand')
    configure_generate_parser(subparsers)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    resource_handler = rs.ResourceHandler()

    try:
        args.func(vars(args), resource_handler)
        return 0
    except ValueError as e:
        # Errores "esperados" (validación, inputs, etc.)
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        # Errores inesperados
        print(f"Error: Failed to generate schema files. {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
