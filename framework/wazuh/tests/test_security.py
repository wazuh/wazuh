#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import glob
import os
from importlib import reload
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy import orm as sqlalchemy_orm
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import text
from yaml import safe_load

from wazuh.core.exception import WazuhError, WazuhPermissionError

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'security/')

# Params

security_cases = list()
rbac_cases = list()
default_orm_engine = create_engine("sqlite:///:memory:")
os.chdir(test_data_path)

for file in glob.glob('*.yml'):
    with open(os.path.join(test_data_path, file)) as f:
        tests_cases = safe_load(f)

    for function_, test_cases in tests_cases.items():
        for test_case in test_cases:
            if file != 'rbac_catalog.yml':
                security_cases.append((function_, test_case['params'], test_case['result']))
            else:
                rbac_cases.append((function_, test_case['params'], test_case['result']))

with open(os.path.join(test_data_path, 'sanitize_policies.yaml')) as f:
    sanitize_policies = safe_load(f)


def create_memory_db(sql_file, session):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            line = line.strip()
            if '* ' not in line and '/*' not in line and '*/' not in line and line != '':
                session.execute(text(line))
                session.commit()


def reload_default_rbac_resources():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=default_orm_engine):
            with patch('shutil.chown'), patch('os.chmod'):
                import wazuh.rbac.orm as orm
                reload(orm)
                orm.db_manager.connect(orm.DB_FILE)
                orm.db_manager.create_database(orm.DB_FILE)
                orm.db_manager.insert_default_resources(orm.DB_FILE)
                import wazuh.rbac.decorators as decorators
                from wazuh.tests.util import RBAC_bypasser

                decorators.expose_resources = RBAC_bypasser
                from wazuh import security
    return security, orm


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                    import wazuh.rbac.orm as orm
                    # Clear mappers
                    sqlalchemy_orm.clear_mappers()
                    # Invalidate in-memory database
                    orm.db_manager.close_sessions()
                    orm.db_manager.connect(orm.DB_FILE)
                    orm.db_manager.sessions[orm.DB_FILE].close()
                    orm.db_manager.engines[orm.DB_FILE].dispose()

                    reload(orm)
                    orm.db_manager.connect(orm.DB_FILE)
                    orm.db_manager.create_database(orm.DB_FILE)
                    orm.db_manager.insert_default_resources(orm.DB_FILE)
                    import wazuh.rbac.decorators as decorators
                    from wazuh.tests.util import RBAC_bypasser

                    decorators.expose_resources = RBAC_bypasser
                    from wazuh import security
                    from wazuh.core.results import WazuhResult
                    from wazuh.core import security as core_security
    try:
        create_memory_db('schema_security_test.sql', orm.db_manager.sessions[orm.DB_FILE])
    except OperationalError:
        pass

    yield security, WazuhResult, core_security
    orm.db_manager.close_sessions()


@pytest.fixture(autouse=True)
def default_rbac_context():
    """Run every case under the default RBAC context, whatever an earlier test module left set.

    The functions under test read the caller's permissions themselves (`require_role_update`), not only
    through the bypassed decorator, and modules such as rbac/tests/test_decorators.py set the context
    without resetting it.
    """
    from wazuh.core.common import rbac
    token = rbac.set({'rbac_mode': 'black'})
    yield
    rbac.reset(token)


@pytest.fixture(scope='function')
def new_default_resources():
    global default_orm_engine
    default_orm_engine = create_engine("sqlite:///:memory:")

    security, orm = reload_default_rbac_resources()

    with open(os.path.join(test_data_path, 'default', 'default_cases.yml')) as f:
        new_resources = safe_load(f)

    for function_, cases in new_resources.items():
        for case in cases:
            getattr(security, function_)(**case['params']).to_dict()

    return security, orm


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


@pytest.mark.parametrize('security_function, params, expected_result', security_cases)
def test_security(db_setup, security_function, params, expected_result):
    """Verify the entire security module.

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
    try:
        security, _, _ = db_setup
        result = getattr(security, security_function)(**params).to_dict()
        assert affected_are_equal(result, expected_result)
        assert failed_are_equal(result, expected_result)
    except WazuhError as e:
        assert str(e.code) == list(expected_result['failed_items'].keys())[0]


@pytest.mark.parametrize('security_function, params, expected_result', rbac_cases)
def test_rbac_catalog(db_setup, security_function, params, expected_result):
    """Verify RBAC catalog functions.

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
    security, _, _ = db_setup
    final_params = dict()
    for param, value in params.items():
        if value.lower() != 'none':
            final_params[param] = value
    result = getattr(security, security_function)(**final_params).to_dict()
    assert result['result']['data'] == expected_result


@pytest.mark.parametrize('policy_case', sanitize_policies['policies'])
def test_sanitize_rbac_policy(db_setup, policy_case):
    _, _, core_security = db_setup
    policy = policy_case['policy']
    core_security.sanitize_rbac_policy(policy)
    for element in ('actions', 'resources', 'effect'):
        if element in policy:
            if element != 'resources':
                assert all(p.islower() for p in policy[element])
            else:
                assert all(':'.join(p.split(':')[:-1]) for p in policy[element])



@pytest.mark.parametrize('password, error_code', [
    ('Password1234', None),
    ('lowercase1234', None),
    ('Short1', 5009),
    ('P' * 60 + '12345', 5009),
    ('OnlyLettersHere', 5007),
    ('123456789012', 5007),
    ('Password1234\n', 5007),
    ('Pass\nword1234', 5007),
    ('Aa1.,_+:@%^=~-', None),
    ('Contraseña1234', 5007),
    ('Password 1234', 5007),
    ('Pass"word1234', None),
    ('Admin!2026secure', None),
    ('Rotate*Pass?12', None),
])
def test_validate_password(db_setup, password, error_code):
    """Check the PCI DSS v4.0 8.3.6 rule: 12 to 64 printable ASCII characters with a letter and a digit."""
    security, _, _ = db_setup
    if error_code is None:
        security.validate_password(password)
    else:
        with pytest.raises(WazuhError, match=str(error_code)):
            security.validate_password(password)

def test_rbac_catalog_getters_are_not_memoized(db_setup):
    """The RBAC catalog getters must not cache their own result.

    An `lru_cache` above `expose_resources` hands back the memoized result without evaluating the
    permissions again, and the caller's RBAC context is not part of the key, so the first authorized
    call would answer for everyone after it. Only `load_spec` is cached: it is the expensive part and
    it carries no authorization.
    """
    security, _, core_security = db_setup

    for getter in (security.get_rbac_resources, security.get_rbac_actions):
        assert not hasattr(getter, 'cache_info'), f'{getter.__name__} memoizes its own result'

    assert hasattr(core_security.load_spec, 'cache_info')


# Users of schema_security_test.sql: 'administrator' (100, roles 100 and 101, run_as on), 'normal' (101,
# roles 103 to 105), 'guest' (105, no roles). Roles 100 to 105 each carry one rule above the reserved range.
RUN_AS_REACHABLE = {100, 101, 102, 103, 104, 105}


def _white_role_update(role_ids):
    """RBAC context of a white-mode caller holding 'security:update' over the given roles only."""
    return {'rbac_mode': 'white',
            'security:update': {f'role:id:{role_id}': 'allow' for role_id in role_ids}}


@pytest.fixture
def rbac_context():
    from wazuh.core.common import rbac
    tokens = []

    def set_context(context):
        tokens.append(rbac.set(context))

    yield set_context
    for token in reversed(tokens):
        rbac.reset(token)


def test_run_as_reachable_roles(db_setup):
    """Every role with a rule above the reserved range is reachable; wazuh-internal-client reaches the reserved rules too."""
    security, _, _ = db_setup

    assert security._run_as_reachable_roles(105) == RUN_AS_REACHABLE
    wui = security._run_as_reachable_roles(2)
    assert RUN_AS_REACHABLE < wui
    # The extra ones are the default roles, linked only to reserved rules.
    assert all(role_id <= 99 for role_id in wui - RUN_AS_REACHABLE)


@pytest.mark.parametrize('granted, denied', [
    (set(), RUN_AS_REACHABLE),
    ({100, 101, 102, 103, 104}, {105}),
])
def test_edit_run_as_enable_requires_every_reachable_role(db_setup, rbac_context, granted, denied):
    """Enabling run_as on an account, the caller's own included, needs 'security:update' over every reachable role."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(granted))

    with pytest.raises(WazuhPermissionError) as exc:
        security.edit_run_as(user_id='105', allow_run_as=True, current_user='guest')

    assert exc.value.code == 4000
    assert exc.value.ids == denied


def test_edit_run_as_enable_with_every_reachable_role(db_setup, rbac_context):
    """A caller that could link every reachable role to the account may enable its run_as flag."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(RUN_AS_REACHABLE))

    result = security.edit_run_as(user_id='105', allow_run_as=True, current_user='guest').to_dict()

    assert result['affected_items'][0]['allow_run_as'] is True


def test_edit_run_as_disable_needs_no_role(db_setup, rbac_context):
    """Disabling run_as removes privilege, so it is never refused over roles."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(set()))

    result = security.edit_run_as(user_id='100', allow_run_as=False, current_user='guest').to_dict()

    assert result['affected_items'][0]['allow_run_as'] is False


@pytest.mark.parametrize('user_id, granted, denied', [
    ('101', set(), {103, 104, 105}),
    ('101', {103, 104}, {105}),
    # run_as is on for 'administrator': its reachable roles count besides its linked ones.
    ('100', {100, 101}, {102, 103, 104, 105}),
])
def test_update_user_requires_the_target_roles(db_setup, rbac_context, user_id, granted, denied):
    """Resetting another account's password needs 'security:update' over every role that account reaches."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(granted))

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_user(user_id=[user_id], password='Password1234', current_user='guest')

    assert exc.value.code == 4000
    assert exc.value.ids == denied


@pytest.mark.parametrize('user_id, granted, current_user', [
    ('101', {103, 104, 105}, 'guest'),
    ('100', RUN_AS_REACHABLE, 'guest'),
    # An account without roles reaches nothing.
    ('105', set(), 'normal'),
    # The caller's own account: it already holds every one of its roles.
    ('101', set(), 'normal'),
])
def test_update_user_allowed(db_setup, rbac_context, user_id, granted, current_user):
    """The password is reset when the caller covers the target's roles, or is the target."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(granted))

    result = security.update_user(user_id=[user_id], password='Password1234', current_user=current_user).to_dict()

    assert result['affected_items'][0]['id'] == int(user_id)


def test_update_user_black_mode_honours_a_deny(db_setup, rbac_context):
    """In black mode everything is allowed but an explicit deny, which still refuses the reset."""
    security, _, _ = db_setup
    rbac_context({'rbac_mode': 'black', 'security:update': {'role:id:103': 'deny'}})

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_user(user_id=['101'], password='Password1234', current_user='guest')

    assert exc.value.ids == {103}


NEW_RULE_BODY = {'MATCH': {'definition': 'attackerContext'}}


@pytest.mark.parametrize('context', [
    _white_role_update(set()),
    {'rbac_mode': 'black', 'security:update': {'role:id:103': 'deny'}},
])
def test_update_rule_body_requires_the_linked_roles(db_setup, rbac_context, context):
    """Rewriting a rule's body remaps every linked role, so it needs 'security:update' over each of them."""
    security, _, _ = db_setup
    rbac_context(context)

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_rule(rule_id=['103'], rule=NEW_RULE_BODY)

    assert exc.value.code == 4000
    assert exc.value.ids == {103}
    with security.RulesManager() as rum:
        assert rum.get_rule(103)['rule'] == {'MATCH': {'definition': 'administratorRule'}}


def test_update_rule_body_with_the_linked_roles(db_setup, rbac_context):
    """A caller that could link the rule to its roles may rewrite its body."""
    security, _, _ = db_setup
    rbac_context(_white_role_update({103}))

    result = security.update_rule(rule_id=['103'], rule=NEW_RULE_BODY).to_dict()

    assert result['affected_items'][0]['rule'] == NEW_RULE_BODY


def test_update_rule_name_needs_no_role(db_setup, rbac_context):
    """A rename does not change which contexts the rule maps, so it is never refused over roles."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(set()))

    result = security.update_rule(rule_id=['103'], name='renamed').to_dict()

    assert result['affected_items'][0]['name'] == 'renamed'
