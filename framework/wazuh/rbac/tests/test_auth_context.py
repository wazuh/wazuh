# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os

import pytest

from wazuh.rbac.auth_context import RBAChecker as checker

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')


class Map(dict):
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
    authorization_contexts = list()
    roles = list()
    results = list()
    with open(test_data_path + 'RBAC_authorization_contexts.json') as f:
        for auth in json.load(f):
            authorization_contexts.append(Map(auth))
    with open(test_data_path + 'RBAC_rules_roles.json') as f:
        for role in json.load(f):
            roles.append(Map(role))
            roles[-1].rule = json.dumps(roles[-1].rule)
    with open(test_data_path + 'RBAC_auth-roles.json') as f:
        for result in json.load(f):
            results.append(Map(result))

    return authorization_contexts, roles, results


@pytest.fixture(scope='module')
def import_auth_RBAC():
    db_path = os.path.join(test_data_path, 'rbac.db')
    assert (os.path.exists(db_path))
    os.unlink(db_path)


def test_load_files():
    authorization_contexts, roles, results = values()
    assert (len(authorization_contexts) > 0)
    assert (len(roles))
    for auth in authorization_contexts:
        assert (type(auth) == Map)
    for role in roles:
        assert (type(role) == Map)


def test_simple1_1():
    authorization_contexts, roles, results = values()
    test = checker(json.dumps(authorization_contexts[0]),
                   roles[0])
    assert (test.run() == [roles[0].name])


def test_auth_roles():
    authorization_contexts, roles, results = values()
    for index, auth in enumerate(authorization_contexts):
        for role in roles:
            test = checker(json.dumps(auth.auth),
                           role)
            if role.name in results[index].roles:
                assert (test.run() == [role.name])
            else:
                assert (len(test.run()) == 0)
        roles = values()[1]
