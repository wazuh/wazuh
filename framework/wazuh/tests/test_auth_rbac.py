# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import json
from unittest.mock import patch
from ..auth_rbac import RBAChecker as checker

import pytest

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')

authorization_contexts = None
rules = None
with open(test_data_path + 'RBAC_authorization_contexts.json') as f:
    authorization_contexts = json.load(f)
with open(test_data_path + 'RBAC_rules_roles.json') as f:
    rules = json.load(f)

@pytest.fixture(scope='module')
def import_auth_RBAC():
    db_path = os.path.join(test_data_path, 'RBAC.db')
    assert (os.path.exists(db_path))
    os.unlink(db_path)


def test_load_files():
    assert(len(authorization_contexts) > 0)
    assert(len(rules))
    for key in authorization_contexts.keys():
        assert(type(authorization_contexts[key]) == dict)
    for key in rules.keys():
        assert(type(rules[key]) == dict)


def test_simple1_1():
    test = checker(json.dumps(authorization_contexts[list(authorization_contexts.keys())[0]]),
                   json.dumps(rules))
    assert(test.run() == ['FirstTest'])
