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

from wazuh.exception import WazuhError
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

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
with open(test_data_path + '/security/roles_test_cases.json') as f:
    file = json.load(f)
get_roles_role_lists = [test_case['params']['role_ids'] for test_case in file['get_roles']]
get_roles_expected_results = [test_case['result'] for test_case in file['get_roles']]

add_roles_name = [test_case['params']['name'] for test_case in file['add_roles']]
add_roles_rule = [test_case['params']['rule'] for test_case in file['add_roles']]
add_roles_expected_result = [test_case['result'] for test_case in file['add_roles']]

update_roles_id = [test_case['params']['role_id'] for test_case in file['update_roles']]
update_roles_rule = [test_case['params']['rule'] for test_case in file['update_roles']]
update_roles_expected_result = [test_case['result'] for test_case in file['update_roles']]

delete_roles_role_lists = [test_case['params']['role_ids'] for test_case in file['delete_roles']]
delete_roles_expected_results = [test_case['result'] for test_case in file['delete_roles']]


def create_memory_db(sql_file, session):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            if '*' not in line:
                session.execute(line)
                session.commit()


def are_equal(result, expected, key_result='username'):
    result_list = {str(user[key_result]) for user in result['affected_items']}
    affected_result = result_list == set(expected['affected_items']) or len(result_list) == 0
    failed_result = True
    if isinstance(expected['failed_items'], dict):
        for key, value in expected['failed_items'].items():
            for expected_key, expected_value in result['failed_items'].items():
                if key in str(expected_key):
                    expected_value = map(str, expected_value)
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

# Users

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
    try:
        result = security.create_user(username=username, password=password)
        assert are_equal(result.to_dict(), expected_result)
    except WazuhError as e:
        assert str(e.code) == list(expected_result['failed_items'].keys())[0]


@pytest.mark.parametrize('username, password, expected_result', zip(update_users_username, update_users_password,
                                                                    update_users_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_update_users(db_setup, username, password, expected_result):
    db_setup(security.orm._Session())
    try:
        result = security.update_user(username=username, password=password)
        assert are_equal(result.to_dict(), expected_result)
    except WazuhError as e:
        assert str(e.code) == list(expected_result['failed_items'].keys())[0]


@pytest.mark.parametrize('username_list, expected_result', zip(delete_users_username_lists,
                                                               delete_users_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_delete_users(db_setup, username_list, expected_result):
    db_setup(security.orm._Session())
    result = security.remove_users(username_list=username_list)
    assert are_equal(result.to_dict(), expected_result)


# Roles

@pytest.mark.parametrize('role_ids, expected_result', zip(get_roles_role_lists, get_roles_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_get_roles(db_setup, role_ids, expected_result):
    db_setup(security.orm._Session())
    result = security.get_roles(role_ids=role_ids)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


@pytest.mark.parametrize('name, rule, expected_result', zip(add_roles_name, add_roles_rule, add_roles_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_add_roles(db_setup, name, rule, expected_result):
    db_setup(security.orm._Session())
    result = security.add_role(name=name, rule=rule)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


@pytest.mark.parametrize('id_, rule, expected_result', zip(update_roles_id, update_roles_rule,
                                                          update_roles_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_update_roles(db_setup, id_, rule, expected_result):
    db_setup(security.orm._Session())
    result = security.update_role(role_id=id_, rule=rule)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


@pytest.mark.parametrize('role_ids, expected_result', zip(delete_roles_role_lists, delete_roles_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_delete_roles(db_setup, role_ids, expected_result):
    db_setup(security.orm._Session())
    result = security.remove_roles(role_ids=role_ids)
    assert are_equal(result.to_dict(), expected_result, key_result='id')
