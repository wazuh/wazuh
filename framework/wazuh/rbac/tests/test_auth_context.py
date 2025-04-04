# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from unittest.mock import patch

from wazuh.rbac.auth_context import RBAChecker

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')


class Map(dict):
    """Map contanins a mapping of the authorization contexts, roles and results."""

    def __init__(self, *args, **kwargs):
        super(Map, self).__init__(*args, **kwargs)
        for arg in args:
            if isinstance(arg, dict):
                for k, v in arg.items():
                    self[k] = v

        if kwargs:
            for k, v in kwargs.items():
                self[k] = v

    def __getattr__(self, attr):
        return self.get(attr)

    def __setattr__(self, key, value):
        self.__setitem__(key, value)

    def __setitem__(self, key, value):
        super(Map, self).__setitem__(key, value)
        self.__dict__.update({key: value})

    def __delattr__(self, item):
        self.__delitem__(item)

    def __delitem__(self, key):
        super(Map, self).__delitem__(key)
        del self.__dict__[key]


def values():
    """Mock values."""
    authorization_contexts = list()
    roles = list()
    results = list()
    with open(test_data_path + 'RBAC_authorization_contexts.json') as f:
        for auth in json.load(f):
            authorization_contexts.append(Map(auth))
    with open(test_data_path + 'RBAC_rules_roles.json') as f:
        for role in json.load(f):
            roles.append(Map(role))
    with open(test_data_path + 'RBAC_auth-roles.json') as f:
        for result in json.load(f):
            results.append(Map(result))

    return authorization_contexts, roles, results


def test_load_files():
    """Validate that files are parsed correctly."""
    authorization_contexts, roles, results = values()
    assert len(authorization_contexts) > 0
    assert len(roles)
    for auth in authorization_contexts:
        assert type(auth) is Map
    for role in roles:
        assert type(role) is Map


@patch('wazuh.rbac.auth_context.RBACManager')
def test_auth_roles(rbac_manager_mock):
    """Validate that `RBAChecker` works as expected."""
    authorization_contexts, roles, results = values()
    for index, auth in enumerate(authorization_contexts):
        for role in roles:
            checker = RBAChecker(rbac_manager=rbac_manager_mock, auth_context=auth.auth, role=role)
            list_rules = [{'rule': role.rules[i]} for i, _ in enumerate(role.rules)]
            role.rules = list_rules

            initial_index = 100
            for rule in role['rules']:
                rule['id'] = initial_index
                initial_index += 1

            if role.name in results[index].roles:
                for rule in role.rules:
                    if checker.check_rule(rule):
                        assert checker.get_user_roles()[0] == role.name
            else:
                assert len(checker.get_user_roles()) == 0
        roles = values()[1]
