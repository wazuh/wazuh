#!/usr/bin/env python
# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


from copy import deepcopy
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
# 'security:update' over every role, those not created yet included: what a run_as account reaches.
EVERY_ROLE_UPDATE = {'rbac_mode': 'white', 'security:update': {'role:id:*': 'allow'}}


def _white_role_update(role_ids):
    """RBAC context of a white-mode caller holding 'security:update' over the given roles only."""
    return {'rbac_mode': 'white',
            'security:update': {f'role:id:{role_id}': 'allow' for role_id in role_ids}}


def _existing_role_ids(security):
    with security.RolesManager() as rm:
        return {role.id for role in rm.get_roles()}


@pytest.fixture
def rbac_context():
    from wazuh.core.common import rbac
    tokens = []

    def set_context(context):
        tokens.append(rbac.set(context))

    yield set_context
    for token in reversed(tokens):
        rbac.reset(token)


@pytest.mark.parametrize('granted', [set(), RUN_AS_REACHABLE])
def test_edit_run_as_enable_requires_every_existing_role(db_setup, rbac_context, granted):
    """Enabling run_as on an account, the caller's own included, needs 'security:update' over every role.

    Covering the roles a custom rule reaches today is not enough: any other role can gain one later.
    """
    security, _, _ = db_setup
    rbac_context(_white_role_update(granted))

    with pytest.raises(WazuhPermissionError) as exc:
        security.edit_run_as(user_id='105', allow_run_as=True, current_user='guest')

    assert exc.value.code == 4000
    assert exc.value.ids == _existing_role_ids(security) - granted
    # The missing roles are named in the message too: a raised exception's ids never reach the response.
    assert exc.value.message.endswith(
        'resources: ' + ', '.join(f'role:id:{i}' for i in sorted(_existing_role_ids(security) - granted)))


def test_edit_run_as_enable_requires_roles_not_created_yet(db_setup, rbac_context):
    """Listing every existing role is not enough in white mode: a role created later is reachable too."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(_existing_role_ids(security)))

    with pytest.raises(WazuhPermissionError) as exc:
        security.edit_run_as(user_id='105', allow_run_as=True, current_user='guest')

    assert exc.value.code == 4000
    with security.AuthenticationManager() as auth:
        assert auth.get_user_id(105)['allow_run_as'] is False


def test_edit_run_as_enable_refused_before_any_custom_rule(db_setup, rbac_context):
    """The check does not depend on the rules that exist when the flag is enabled.

    Enabling it while no custom rule is linked, then linking one to a role, must not put that role
    within reach of a caller that could not assign it.
    """
    security, _, _ = db_setup
    with security.RulesManager() as rum:
        rum.delete_all_rules()
    rbac_context(_white_role_update(set()))

    with pytest.raises(WazuhPermissionError) as exc:
        security.edit_run_as(user_id='105', allow_run_as=True, current_user='guest')

    assert exc.value.code == 4000
    assert exc.value.ids == _existing_role_ids(security)


@pytest.mark.parametrize('context', [EVERY_ROLE_UPDATE, {'rbac_mode': 'black'}])
def test_edit_run_as_enable_with_every_role(db_setup, rbac_context, context):
    """A caller that could link any role, present or future, to the account may enable its run_as flag."""
    security, _, _ = db_setup
    rbac_context(context)

    result = security.edit_run_as(user_id='105', allow_run_as=True, current_user='guest').to_dict()

    assert result['affected_items'][0]['allow_run_as'] is True


def test_edit_run_as_enable_black_mode_honours_a_deny(db_setup, rbac_context):
    """In black mode a deny over any role refuses the flag."""
    security, _, _ = db_setup
    rbac_context({'rbac_mode': 'black', 'security:update': {'role:id:102': 'deny'}})

    with pytest.raises(WazuhPermissionError) as exc:
        security.edit_run_as(user_id='105', allow_run_as=True, current_user='guest')

    assert exc.value.ids == {102}


def test_edit_run_as_disable_needs_no_role(db_setup, rbac_context):
    """Disabling run_as removes privilege, so it is never refused over roles."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(set()))

    result = security.edit_run_as(user_id='100', allow_run_as=False, current_user='guest').to_dict()

    assert result['affected_items'][0]['allow_run_as'] is False


@pytest.mark.parametrize('user_id, granted, denied', [
    ('101', set(), {103, 104, 105}),
    ('101', {103, 104}, {105}),
])
def test_update_user_requires_the_target_roles(db_setup, rbac_context, user_id, granted, denied):
    """Resetting another account's password needs 'security:update' over every role that account reaches."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(granted))

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_user(user_id=[user_id], password='Password1234', current_user='guest')

    assert exc.value.code == 4000
    assert exc.value.ids == denied


@pytest.mark.parametrize('delete_custom_rules', [False, True])
def test_update_user_of_a_run_as_account_requires_every_role(db_setup, rbac_context, delete_custom_rules):
    """run_as is on for 'administrator': its password is held to every role, those not created yet included.

    Whether a custom rule is linked when the password is reset does not matter: one linked later would
    reach the account whose password the caller now knows.
    """
    security, _, _ = db_setup
    if delete_custom_rules:
        with security.RulesManager() as rum:
            rum.delete_all_rules()
    rbac_context(_white_role_update(_existing_role_ids(security)))

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_user(user_id=['100'], password='Password1234', current_user='guest')

    assert exc.value.code == 4000


@pytest.mark.parametrize('user_id, context, current_user', [
    ('101', _white_role_update({103, 104, 105}), 'guest'),
    ('100', EVERY_ROLE_UPDATE, 'guest'),
    # An account without roles reaches nothing.
    ('105', _white_role_update(set()), 'normal'),
    # The caller's own account: it already holds every one of its roles.
    ('101', _white_role_update(set()), 'normal'),
])
def test_update_user_allowed(db_setup, rbac_context, user_id, context, current_user):
    """The password is reset when the caller covers the target's roles, or is the target."""
    security, _, _ = db_setup
    rbac_context(context)

    result = security.update_user(user_id=[user_id], password='Password1234', current_user=current_user).to_dict()

    assert result['affected_items'][0]['id'] == int(user_id)


@pytest.mark.parametrize('user_id, current_user, context, denied', [
    # A run_as account (flag on): its run_as token is held to every role, those not created yet included.
    ('100', 'administrator', _white_role_update(set()), None),
    ('100', 'administrator', _white_role_update(RUN_AS_REACHABLE), None),
    # An account without the flag: its run_as token is held to the account's own roles.
    ('101', 'normal', _white_role_update(set()), {103, 104, 105}),
])
def test_update_user_run_as_token_is_not_its_own_account(db_setup, rbac_context, user_id, current_user, context,
                                                         denied):
    """A run_as token names the shared account it logged in through, not the end user who holds it.

    Its roles are only those the authorization context resolved to, so resetting the password of that
    account is resetting someone else's: exempting it would hand the account, and every role it reaches,
    to anyone mapped to a role with 'security:update' over it.
    """
    security, _, _ = db_setup
    rbac_context(context)

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_user(user_id=[user_id], password='Password1234', current_user=current_user, run_as=True)

    assert exc.value.code == 4000
    if denied is not None:
        assert exc.value.ids == denied


@pytest.mark.parametrize('user_id, current_user, context', [
    ('100', 'administrator', EVERY_ROLE_UPDATE),
    ('101', 'normal', _white_role_update({103, 104, 105})),
])
def test_update_user_run_as_token_with_the_roles(db_setup, rbac_context, user_id, current_user, context):
    """A run_as token that covers what the account reaches may reset its password, like any other caller."""
    security, _, _ = db_setup
    rbac_context(context)

    result = security.update_user(user_id=[user_id], password='Password1234', current_user=current_user,
                                  run_as=True).to_dict()

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


# Policy 106 is linked to role 105 only; policy 101 to roles 102, 104 and 105 (schema_security_test.sql).
ESCALATING_POLICY_BODY = {'actions': ['security:read', 'security:update'],
                          'resources': ['role:id:*', 'user:id:*'], 'effect': 'allow'}


def _white_role_delete(role_ids):
    """RBAC context of a white-mode caller holding 'security:delete' over the given roles only."""
    return {'rbac_mode': 'white',
            'security:delete': {f'role:id:{role_id}': 'allow' for role_id in role_ids}}


def _policy_body(security, policy_id):
    with security.PoliciesManager() as pm:
        return pm.get_policy_id(policy_id)['policy']


@pytest.mark.parametrize('context', [
    _white_role_update(set()),
    {'rbac_mode': 'black', 'security:update': {'role:id:105': 'deny'}},
])
def test_update_policy_body_requires_the_linked_roles(db_setup, rbac_context, context):
    """Rewriting a policy's body changes what every linked role grants, so it needs 'security:update' over each.

    Without it, update over a policy linked to one's own role is enough to grant oneself 'security:update'
    over every role and user, and then link 'administrator' to oneself.
    """
    security, _, _ = db_setup
    before = _policy_body(security, 106)
    rbac_context(context)

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_policy(policy_id=['106'], policy=deepcopy(ESCALATING_POLICY_BODY))

    assert exc.value.code == 4000
    assert exc.value.ids == {105}
    assert _policy_body(security, 106) == before


def test_update_policy_body_lists_every_missing_role(db_setup, rbac_context):
    """All or nothing: covering some of the linked roles is not enough, and the refusal names the rest."""
    security, _, _ = db_setup
    rbac_context(_white_role_update({102}))

    with pytest.raises(WazuhPermissionError) as exc:
        security.update_policy(policy_id=['101'], policy=deepcopy(ESCALATING_POLICY_BODY))

    assert exc.value.ids == {104, 105}


def test_update_policy_body_with_the_linked_roles(db_setup, rbac_context):
    """A caller that could link the policy to its roles may rewrite its body."""
    security, _, _ = db_setup
    rbac_context(_white_role_update({105}))

    result = security.update_policy(policy_id=['106'], policy=deepcopy(ESCALATING_POLICY_BODY)).to_dict()

    assert result['affected_items'][0]['id'] == 106
    assert _policy_body(security, 106)['resources'] == ESCALATING_POLICY_BODY['resources']


def test_update_policy_name_needs_no_role(db_setup, rbac_context):
    """A rename does not change what the policy grants, so it is never refused over roles."""
    security, _, _ = db_setup
    rbac_context(_white_role_update(set()))

    result = security.update_policy(policy_id=['106'], name='renamed').to_dict()

    assert result['affected_items'][0]['name'] == 'renamed'


@pytest.mark.parametrize('context', [
    _white_role_delete(set()),
    {'rbac_mode': 'black', 'security:delete': {'role:id:105': 'deny'}},
])
def test_remove_policies_requires_deleting_from_the_linked_roles(db_setup, rbac_context, context):
    """Deleting a policy unlinks it from every role it is on, and dropping a deny widens those roles.

    It therefore asks for what `remove_role_policy` asks: 'security:delete' over each linked role. A refused
    policy fails on its own and is kept.
    """
    security, _, _ = db_setup
    rbac_context(context)

    result = security.remove_policies(policy_ids=['106']).to_dict()

    assert result['affected_items'] == []
    assert list(result['failed_items'].keys())[0].code == 4000
    with security.PoliciesManager() as pm:
        assert isinstance(pm.get_policy_id(106), dict)


def test_remove_policies_with_the_linked_roles(db_setup, rbac_context):
    """A caller that could unlink the policy from its roles may delete it."""
    security, _, _ = db_setup
    rbac_context(_white_role_delete({105}))

    result = security.remove_policies(policy_ids=['106']).to_dict()

    assert [item['id'] for item in result['affected_items']] == [106]


def test_remove_policies_reserved_is_still_refused_as_reserved(db_setup, rbac_context):
    """A reserved policy keeps its own refusal (4008), not a role one."""
    security, _, _ = db_setup
    rbac_context(_white_role_delete(set()))

    result = security.remove_policies(policy_ids=['1']).to_dict()

    assert list(result['failed_items'].keys())[0].code == 4008


def test_remove_policies_unlinked_needs_no_role(db_setup, rbac_context):
    """A policy on no role grants nothing to anyone, so deleting it asks for no role."""
    security, _, _ = db_setup
    added = security.add_policy(name='unlinked', policy={'actions': ['agent:read'], 'resources': ['agent:id:001'],
                                                         'effect': 'allow'}).to_dict()
    policy_id = added['affected_items'][0]['id']
    rbac_context(_white_role_delete(set()))

    result = security.remove_policies(policy_ids=[str(policy_id)]).to_dict()

    assert [item['id'] for item in result['affected_items']] == [policy_id]


# Rule 103 is linked to role 103 only, and rule 104 to role 104 only (schema_security_test.sql).
@pytest.mark.parametrize('context', [
    _white_role_delete(set()),
    {'rbac_mode': 'black', 'security:delete': {'role:id:103': 'deny'}},
])
def test_remove_rules_requires_deleting_from_the_linked_roles(db_setup, rbac_context, context):
    """Deleting a rule unlinks it from every role it is on, and dropping a deny role widens its users.

    It therefore asks for what `remove_role_rule` asks: 'security:delete' over each linked role. A refused
    rule fails on its own, is kept and stays linked.
    """
    security, _, _ = db_setup
    rbac_context(context)

    result = security.remove_rules(rule_ids=['103']).to_dict()

    assert result['affected_items'] == []
    assert list(result['failed_items'].keys())[0].code == 4000
    with security.RulesManager() as rum:
        assert rum.get_rule(103)['roles'] == [103]


def test_remove_rules_refuses_only_the_rules_of_uncovered_roles(db_setup, rbac_context):
    """In one request, the rule whose role is covered is deleted and the other is kept."""
    security, _, _ = db_setup
    rbac_context(_white_role_delete({104}))

    result = security.remove_rules(rule_ids=['103', '104']).to_dict()

    assert [item['id'] for item in result['affected_items']] == [104]
    assert list(result['failed_items'].keys())[0].code == 4000
    with security.RulesManager() as rum:
        assert rum.get_rule(103)['roles'] == [103]


def test_remove_rules_with_the_linked_roles(db_setup, rbac_context):
    """A caller that could unlink the rule from its roles may delete it."""
    security, _, _ = db_setup
    rbac_context(_white_role_delete({103}))

    result = security.remove_rules(rule_ids=['103']).to_dict()

    assert [item['id'] for item in result['affected_items']] == [103]


def test_remove_rules_reserved_is_still_refused_as_reserved(db_setup, rbac_context):
    """A reserved rule keeps its own refusal (4008), not a role one."""
    security, _, _ = db_setup
    rbac_context(_white_role_delete(set()))

    result = security.remove_rules(rule_ids=['1']).to_dict()

    assert list(result['failed_items'].keys())[0].code == 4008


def test_remove_rules_unlinked_needs_no_role(db_setup, rbac_context):
    """A rule on no role maps nobody to anything, so deleting it asks for no role."""
    security, _, _ = db_setup
    added = security.add_rule(name='unlinked', rule={'MATCH': {'definition': 'unlinkedRule'}}).to_dict()
    rule_id = added['affected_items'][0]['id']
    rbac_context(_white_role_delete(set()))

    result = security.remove_rules(rule_ids=[str(rule_id)]).to_dict()

    assert [item['id'] for item in result['affected_items']] == [rule_id]
