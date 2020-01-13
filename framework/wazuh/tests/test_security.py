#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
import os
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from wazuh.rbac.decorators import expose_resources

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import security

# all necessary params
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
with open(test_data_path + '/security/users_test_cases.json') as f:
    file = json.load(f)
get_users_username_lists = [test_case['params']['username_list'] for test_case in file['get_users']]
get_users_expected_results = [test_case['result'] for test_case in file['get_users']]

create_users_username = [test_case['params']['username'] for test_case in file['create_users']]
create_users_password = [test_case['params']['password'] for test_case in file['create_users']]
create_users_expected_result = [test_case['result'] for test_case in file['create_users']]

update_users_username = [test_case['params']['username'] for test_case in file['update_users']]
update_users_password = [test_case['params']['password'] for test_case in file['update_users']]
update_users_expected_result = [test_case['result'] for test_case in file['update_users']]

delete_users_username_lists = [test_case['params']['username_list'] for test_case in file['delete_users']]
delete_users_expected_results = [test_case['result'] for test_case in file['delete_users']]


def create_memory_db(sql_file, session):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            if '*' not in line:
                session.execute(line)
                session.commit()


def are_equal(result, expected):
    result_username_list = {user['username'] for user in result['affected_items']}
    affected_result = result_username_list == set(expected['affected_items']) or len(result_username_list) == 0
    failed_result = True
    if isinstance(expected['failed_items'], dict):
        for key, value in expected['failed_items'].items():
            for expected_key, expected_value in result['failed_items'].items():
                if key in str(expected_key):
                    failed_result = set(value) == set(expected_value)
                if not failed_result:
                    return False

    return affected_result == failed_result


@pytest.fixture
def db_setup():
    def _method(session):
        try:
            create_memory_db('security/schema_security_test.sql', session)
        except OperationalError:
            pass

    return _method


@pytest.mark.parametrize('username_list, expected_result', zip(get_users_username_lists, get_users_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_get_users(db_setup, username_list, expected_result):
    db_setup(security.orm._Session())
    result = security.get_users(username_list=username_list)
    assert are_equal(result.to_dict(), expected_result)


@pytest.mark.parametrize('username, password, expected_result', zip(create_users_username, create_users_password,
                                                                    create_users_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_create_users(db_setup, username, password, expected_result):
    db_setup(security.orm._Session())
    result = security.create_user(username=username, password=password)
    assert are_equal(result.to_dict(), expected_result)


@pytest.mark.parametrize('username, password, expected_result', zip(update_users_username, update_users_password,
                                                                    update_users_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_update_users(db_setup, username, password, expected_result):
    db_setup(security.orm._Session())
    result = security.update_user(username=[username], password=password)
    assert are_equal(result.to_dict(), expected_result)


@pytest.mark.parametrize('username_list, expected_result', zip(delete_users_username_lists,
                                                               delete_users_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_delete_users(db_setup, username_list, expected_result):
    db_setup(security.orm._Session())
    result = security.delete_users(username_list=username_list)
    assert are_equal(result.to_dict(), expected_result)
