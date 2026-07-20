#!/usr/bin/env python3

from pathlib import Path
from argparse import ArgumentParser
from typing import Callable
from json import loads, dumps


def visitor(path: Path, pattern: str, visit: Callable):
    for file in path.rglob(pattern):
        if file.is_file():
            visit(file)
        elif file.is_dir():
            visitor(file, pattern, visit)


def dict_merge(dct, merge_dct):
    """ Recursive dict merge. Inspired by :meth:``dict.update()``, instead of
    updating only top-level keys, dict_merge recurses down into dicts nested
    to an arbitrary depth, updating keys. The ``merge_dct`` is merged into
    ``dct``.

    :param dct: dict onto which the merge is executed
    :param merge_dct: dct merged into dct
    :return: None
    """
    for k, v in merge_dct.items():
        if (k in dct and isinstance(dct[k], dict) and isinstance(merge_dct[k], dict)):  # noqa
            dict_merge(dct[k], merge_dct[k])
        else:
            dct[k] = merge_dct[k]


def get_acumulator(fields: dict, key: str):
    def acumulator(file):
        try:
            data = loads(file.read_text())
            # Verify data is an array
            if not isinstance(data, list):
                raise Exception(f'Expected an array, got {type(data)}')

            if len(key) != 0:
                for expected in data:
                    dict_merge(fields, expected[key])
                print(f'{file.name} -> {key}')
            else:
                for expected in data:
                    dict_merge(fields, expected)
                print(f'{file.name} -> root')
        except Exception as e:
            print(f'{file.name} -> {e}')
    return acumulator


if __name__ == '__main__':
    try:
        arg_parser = ArgumentParser(
            description='Flattens the output json of a root field')
        arg_parser.add_argument(
            'path', type=Path, help='Path to the input directory')
        arg_parser.add_argument('pattern', help='Pattern for the output files')
        arg_parser.add_argument(
            '-r', '--root', help='Root field to flatten. Default fllattens all fields', default='')

        args = arg_parser.parse_args()

        path = args.path
        pattern = args.pattern
        root = args.root

        # Iterate over files, visiting subfolders recursively
        fields = {}
        visitor(path, pattern, get_acumulator(fields, root))

        # In order visit the fiels printing leaf keys with their parents separated by dots
        # A leaf key is a key that does not contain a dict
        def visit(keys, fields, prefix=''):
            for key, value in fields.items():
                if isinstance(value, dict):
                    visit(keys, value, prefix + key + '.')
                else:
                    keys.append(prefix + key)

        print()
        print()
        final = dict()
        keys = []
        if len(root) != 0:
            final[root] = fields
        else:
            final = fields
        visit(keys, final)

        # Sort keys alphabetically
        keys.sort()
        for key in keys:
            print(key)
    except KeyboardInterrupt:
        print('Interrupted by the user')
    except Exception as e:
        print(f'Unexpected error: {e}')
