#!/usr/bin/env python3
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Edit a YAML mapping file in place (the manager configuration, etc/wazuh-manager.yml) from the test environment.

    yaml_merge.py merge <target.yml> <fragment.yml>       deep-merge the fragment into the target
    yaml_merge.py set <target.yml> <dotted.key> <value>   set one option; the value is parsed as YAML

Mappings are merged key by key; scalars and lists of the fragment replace the target's. `set` creates the missing
intermediate mappings. Comments of the target are not preserved (the environment does not need them).
"""

import sys

import yaml


def deep_merge(target: dict, fragment: dict) -> dict:
    for key, value in fragment.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            deep_merge(target[key], value)
        else:
            target[key] = value
    return target


def set_option(document: dict, dotted_key: str, value):
    node = document
    *parents, last = dotted_key.split('.')
    for part in parents:
        if not isinstance(node.get(part), dict):
            node[part] = {}
        node = node[part]
    node[last] = value


def load(path: str) -> dict:
    try:
        with open(path) as f:
            document = yaml.safe_load(f)
    except FileNotFoundError:
        document = None
    if document is None:
        return {}
    if not isinstance(document, dict):
        raise SystemExit(f'{path}: the document root must be a mapping')
    return document


def save(path: str, document: dict):
    with open(path, 'w') as f:
        yaml.safe_dump(document, f, sort_keys=False, default_flow_style=False)


def main(argv):
    if len(argv) >= 4 and argv[1] == 'merge':
        target = load(argv[2])
        save(argv[2], deep_merge(target, load(argv[3])))
    elif len(argv) >= 5 and argv[1] == 'set':
        target = load(argv[2])
        set_option(target, argv[3], yaml.safe_load(argv[4]))
        save(argv[2], target)
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    main(sys.argv)
