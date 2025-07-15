#!/usr/bin/env python3
import argparse

from helper_test.initial_state import configure as init_configure
from helper_test.test_cases_generator.validate import configure as validate_configure
from helper_test.test_cases_generator.generate import configure as generate_configure
from helper_test.runner import configure as run_configure
from helper_test.documentation_generator.generate import configure as generate_documentation_configure


def parse_args():
    parser = argparse.ArgumentParser(
        description="Utility to perform the helper test on the Engine")
    parser.add_argument("-e", "--environment", required=True,
                        help="Environment directory")

    subparsers = parser.add_subparsers(dest='command')

    init_configure(subparsers)
    validate_configure(subparsers)
    generate_configure(subparsers)
    run_configure(subparsers)
    generate_documentation_configure(subparsers)

    return parser.parse_args()


def main():
    args = parse_args()
    args.func(vars(args))


if __name__ == '__main__':
    main()
