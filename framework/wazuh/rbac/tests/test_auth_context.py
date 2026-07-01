# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from unittest.mock import patch, MagicMock
from wazuh.rbac.auth_context import AuthContextDepthExceeded, RBAChecker, MAX_FIND_ITEM_DEPTH

import pytest
from sqlalchemy import create_engine

from wazuh.rbac.tests.utils import init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    from wazuh.rbac.auth_context import RBAChecker
    init_db('schema_security_test.sql', test_data_path)

    yield RBAChecker


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
    with open(test_data_path + 'RBAC_auth-roles.json') as f:
        for result in json.load(f):
            results.append(Map(result))

    return authorization_contexts, roles, results


def test_load_files(db_setup):
    authorization_contexts, roles, results = values()
    assert len(authorization_contexts) > 0
    assert len(roles)
    for auth in authorization_contexts:
        assert type(auth) == Map
    for role in roles:
        assert type(role) == Map


def test_auth_roles(db_setup):
    authorization_contexts, roles, results = values()
    for index, auth in enumerate(authorization_contexts):
        for role in roles:
            with patch('wazuh.rbac.orm.RolesManager.get_role_id') as _role_rules:
                with patch('wazuh.rbac.orm.RulesManager.get_rule') as _rule:
                    list_rules = [{'rule': role.rules[i]} for i, _ in enumerate(role.rules)]
                    role.rules = list_rules
                    _role_rules.return_value = {'rules': list_rules}
                    _rule.side_effect = role.rules
                    initial_index = 100
                    for rule in role['rules']:
                        rule['id'] = initial_index
                        initial_index += 1
                    test = db_setup(json.dumps(auth.auth), role)
                    if role.name in results[index].roles:
                        assert test.get_user_roles()[0] == role.id
                    else:
                        assert len(test.get_user_roles()) == 0
        roles = values()[1]


def _make_checker(auth_context=None):
    """Return an RBAChecker with no DB interaction."""
    with patch('wazuh.rbac.auth_context.orm.RolesManager') as mock_rm, \
         patch('wazuh.rbac.auth_context.orm.RulesManager'):
        mock_rm.return_value.__enter__.return_value.get_roles.return_value = []
        return RBAChecker(auth_context=auth_context or {})


def test_find_item_depth_limit_raises():
    """find_item must raise AuthContextDepthExceeded when nesting exceeds MAX_FIND_ITEM_DEPTH."""
    checker = _make_checker()
    # Build a dict nested one level deeper than the allowed maximum
    deep = {"leaf": "value"}
    for _ in range(MAX_FIND_ITEM_DEPTH + 1):
        deep = {"level": deep}

    with pytest.raises(AuthContextDepthExceeded):
        checker.find_item({"leaf": "value"}, auth_context=deep, mode='FIND')


def test_get_user_roles_denies_when_depth_exceeded():
    """get_user_roles must not grant a role when find_item hits the depth limit.

    A NOT+FIND rule would incorrectly grant access if the truncated search returned
    False (no match found), because NOT(False) evaluates to True. Raising
    AuthContextDepthExceeded instead causes get_user_roles to skip the role entirely.
    """
    deep = {"leaf": "value"}
    for _ in range(MAX_FIND_ITEM_DEPTH + 1):
        deep = {"level": deep}
    checker = _make_checker(auth_context=deep)
    checker.user_id = 2
    checker.roles_list = [{"id": 1, "rules": [{"id": 1, "rule": {"NOT": [{"FIND": {"leaf": "value"}}]}}]}]

    assert checker.get_user_roles() == []
