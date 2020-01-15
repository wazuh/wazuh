#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import glob
import json
import os
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from wazuh.exception import WazuhError
from wazuh.rbac.decorators import expose_resources

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import security
        from wazuh.results import WazuhResult

# Params

security_cases = list()
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'security/')
os.chdir(test_data_path)

for file in glob.glob('*.json'):
    with open(os.path.join(test_data_path + file)) as f:
        tests_cases = json.load(f)

    for function_, test_cases in tests_cases.items():
        for test_case in test_cases:
            security_cases.append((function_, test_case['params'], test_case['result']))


def create_memory_db(sql_file, session):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            line = line.strip()
            if '* ' not in line and '/*' not in line and '*/' not in line and line != '':
                session.execute(line)
                session.commit()


def affected_are_equal(target_dict, expected_dict):
    return target_dict['affected_items'] == expected_dict['affected_items']


def failed_are_equal(target_dict, expected_dict):
    if len(target_dict['failed_items'].keys()) == 0 and len(expected_dict['failed_items'].keys()) == 0:
        return True
    result = False
    for target_key, target_value in target_dict['failed_items'].items():
        for expected_key, expected_value in expected_dict['failed_items'].items():
            result = expected_key in str(target_key) and set(target_value) == set(expected_value)
            if result:
                break

    return result


@pytest.fixture
def db_setup():
    def _method(session):
        try:
            create_memory_db('schema_security_test.sql', session)
        except OperationalError:
            pass

    return _method


@pytest.mark.parametrize('security_function, params, expected_result', security_cases)
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_get_users(db_setup, security_function, params, expected_result):
    """Checks that the dict returned is correct

    Parameters
    ----------
    db_setup : callable
        This function creates the rbac.db file.
    security_function : list of str
        This is the name of the tested function.
    params : list of str
        Arguments for the tested function.
    expected_result : list of dict
        This is a list that contains the expected results .
    """
    with patch('wazuh.security.orm._engine', create_engine(f'sqlite://')):
        with patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://'))):
            db_setup(security.orm._Session())
            try:
                result = getattr(security, security_function)(**params).to_dict()
                assert affected_are_equal(result, expected_result)
                assert failed_are_equal(result, expected_result)
            except WazuhError as e:
                assert str(e.code) == list(expected_result['failed_items'].keys())[0]


def test_revoke_tokens():
    """Checks that the return value of revoke_tokens is a WazuhResult."""
    result = security.revoke_tokens()
    assert isinstance(result, WazuhResult)
