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

# Users

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

# Roles

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
with open(test_data_path + '/security/roles_test_cases.json') as f:
    file = json.load(f)
get_roles_role_lists = [test_case['params']['role_ids'] for test_case in file['get_roles']]
get_roles_expected_results = [test_case['result'] for test_case in file['get_roles']]

add_roles_name = [test_case['params']['name'] for test_case in file['add_roles']]
add_roles_rule = [test_case['params']['rule'] for test_case in file['add_roles']]
add_roles_expected_result = [test_case['result'] for test_case in file['add_roles']]

update_roles_id = [test_case['params']['role_id'] for test_case in file['update_roles']]
update_roles_name = [test_case['params']['name'] for test_case in file['update_roles']]
update_roles_rule = [test_case['params']['rule'] for test_case in file['update_roles']]
update_roles_expected_result = [test_case['result'] for test_case in file['update_roles']]

delete_roles_role_lists = [test_case['params']['role_ids'] for test_case in file['delete_roles']]
delete_roles_expected_results = [test_case['result'] for test_case in file['delete_roles']]


# Policies

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
with open(test_data_path + '/security/policies_test_cases.json') as f:
    file = json.load(f)
get_policies_policy_lists = [test_case['params']['policy_ids'] for test_case in file['get_policies']]
get_policies_expected_results = [test_case['result'] for test_case in file['get_policies']]

add_policies_name = [test_case['params']['name'] for test_case in file['add_policies']]
add_policies_policy = [test_case['params']['policy'] for test_case in file['add_policies']]
add_policies_expected_result = [test_case['result'] for test_case in file['add_policies']]

update_policies_id = [test_case['params']['policy_id'] for test_case in file['update_policies']]
update_policies_name = [test_case['params']['name'] for test_case in file['update_policies']]
update_policies_policy = [test_case['params']['policy'] for test_case in file['update_policies']]
update_policies_expected_result = [test_case['result'] for test_case in file['update_policies']]

delete_policies_policy_lists = [test_case['params']['policy_ids'] for test_case in file['delete_policies']]
delete_policies_expected_results = [test_case['result'] for test_case in file['delete_policies']]


# User-Roles

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
with open(test_data_path + '/security/users_roles_test_cases.json') as f:
    file = json.load(f)
create_user_roles_id_lists = [test_case['params']['user_id'] for test_case in file['create_user_roles']]
create_user_roles_role_lists = [test_case['params']['role_ids'] for test_case in file['create_user_roles']]
create_user_expected_results = [test_case['result'] for test_case in file['create_user_roles']]

delete_user_roles_id_lists = [test_case['params']['user_id'] for test_case in file['delete_user_roles']]
delete_user_roles_role_lists = [test_case['params']['role_ids'] for test_case in file['delete_user_roles']]
delete_user_expected_results = [test_case['result'] for test_case in file['delete_user_roles']]


def create_memory_db(sql_file, session):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            line = line.strip()
            if '* ' not in line and '/*' not in line and '*/' not in line and line != '':
                session.execute(line)
                session.commit()


def are_equal(result, expected, key_result='username'):
    result_list = set()
    for r in result['affected_items']:
        if not isinstance(r[key_result], list):
            result_list.add(str(r[key_result]))
        else:
            result_list.update(set(map(str, r[key_result])))
    affected_result = result_list == set(expected['affected_items']) or \
                      (len(result_list) == 0 and len(expected['affected_items']) == 0)
    failed_result = False
    if isinstance(expected['failed_items'], dict):
        for key, value in expected['failed_items'].items():
            for key_result in result['failed_items'].keys():
                if str(key) == str(key_result.code):
                    expected_value = map(str, result['failed_items'][key_result])
                    failed_result = set(value) == set(expected_value)
                    break
                else:
                    failed_result = False
            if not failed_result:
                return False

    return affected_result is True and (failed_result is True or
                                        len(expected['failed_items'].keys()) == 0 and len(result['failed_items']) == 0)


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


@pytest.mark.parametrize('id_, name, rule, expected_result', zip(update_roles_id, update_roles_name, update_roles_rule,
                                                                 update_roles_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_update_roles(db_setup, id_, name, rule, expected_result):
    db_setup(security.orm._Session())
    result = security.update_role(role_id=id_, name=name, rule=rule)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


@pytest.mark.parametrize('role_ids, expected_result', zip(delete_roles_role_lists, delete_roles_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_delete_roles(db_setup, role_ids, expected_result):
    db_setup(security.orm._Session())
    result = security.remove_roles(role_ids=role_ids)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


# Policies

@pytest.mark.parametrize('policy_ids, expected_result', zip(get_policies_policy_lists, get_policies_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_get_policies(db_setup, policy_ids, expected_result):
    db_setup(security.orm._Session())
    result = security.get_policies(policy_ids=policy_ids)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


@pytest.mark.parametrize('name, policy, expected_result', zip(add_policies_name, add_policies_policy,
                                                              add_policies_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_add_policies(db_setup, name, policy, expected_result):
    db_setup(security.orm._Session())
    result = security.add_policy(name=name, policy=policy)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


@pytest.mark.parametrize('id_, name, policy, expected_result', zip(
    update_policies_id, update_policies_name, update_policies_policy, update_policies_expected_result))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_update_policies(db_setup, id_, name, policy, expected_result):
    db_setup(security.orm._Session())
    result = security.update_policy(policy_id=id_, name=name, policy=policy)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


@pytest.mark.parametrize('policy_ids, expected_result', zip(delete_policies_policy_lists,
                                                            delete_policies_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_delete_roles(db_setup, policy_ids, expected_result):
    db_setup(security.orm._Session())
    result = security.remove_policies(policy_ids=policy_ids)
    assert are_equal(result.to_dict(), expected_result, key_result='id')


# User-Roles

@pytest.mark.parametrize('user_id, role_ids, expected_result', zip(
    create_user_roles_id_lists, create_user_roles_role_lists, create_user_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_create_user_roles(db_setup, user_id, role_ids, expected_result):
    db_setup(security.orm._Session())
    result = security.set_user_role(user_id=user_id, role_ids=role_ids)
    assert are_equal(result.to_dict(), expected_result, key_result='roles')


@pytest.mark.parametrize('user_id, role_ids, expected_result', zip(
    delete_user_roles_id_lists, delete_user_roles_role_lists, delete_user_expected_results))
@patch('wazuh.security.orm._engine', create_engine(f'sqlite://'))
@patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://')))
def test_delete_user_roles(db_setup, user_id, role_ids, expected_result):
    db_setup(security.orm._Session())
    result = security.remove_user_role(user_id=user_id, role_ids=role_ids)
    assert are_equal(result.to_dict(), expected_result, key_result='roles')
