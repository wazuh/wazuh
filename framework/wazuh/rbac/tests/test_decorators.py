# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from importlib import reload

from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.tests.utils import init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    import wazuh.rbac.decorators as decorator

    init_db('schema_security_test.sql', test_data_path)
    reload(decorator)

    yield decorator


permissions = list()
results = list()
with open(test_data_path + 'RBAC_decorators_permissions_white.json') as f:
    configurations_white = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
                             config.get('result', None),
                             'white') for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_permissions_black.json') as f:
    configurations_black = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
                             config.get('result', None),
                             'black') for config in json.load(f)]

with open(test_data_path + 'RBAC_decorators_resourceless_white.json') as f:
    configurations_resourceless_white = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed'],
                                          'white') for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_resourceless_black.json') as f:
    configurations_resourceless_black = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed'],
                                          'black') for config in json.load(f)]


def get_identifier(resources):
    list_params = list()
    for resource in resources:
        resource = resource.split('&')
        for r in resource:
            try:
                list_params.append(re.search(r'^([a-z*]+:[a-z*]+:)(\*|{(\w+)})$', r).group(3))
            except AttributeError:
                pass

    return list_params


@pytest.mark.parametrize('decorator_params, function_params, rbac, '
                         'fake_system_resources, allowed_resources, result, mode',
                         configurations_black + configurations_white)
def test_expose_resources(db_setup, decorator_params, function_params, rbac, fake_system_resources, allowed_resources,
                          result, mode):
    rbac['rbac_mode'] = mode
    db_setup.rbac.set(rbac)

    def mock_expand_resource(resource):
        fake_values = fake_system_resources.get(resource, resource.split(':')[-1])
        return {fake_values} if isinstance(fake_values, str) else set(fake_values)

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @db_setup.expose_resources(**decorator_params)
        def framework_dummy(**kwargs):
            for target_param, allowed_resource in zip(get_identifier(decorator_params['resources']), allowed_resources):
                assert set(kwargs[target_param]) == set(allowed_resource)
                assert 'call_func' not in kwargs
                return True

        try:
            output = framework_dummy(**function_params)
            assert (result is None or result == "allow")
            assert output == function_params.get('call_func', True) or isinstance(output, AffectedItemsWazuhResult)
        except WazuhError as e:
            assert (result is None or result == "deny")
            for allowed_resource in allowed_resources:
                assert (len(allowed_resource) == 0)
            assert (e.code == 4000)


@pytest.mark.parametrize('decorator_params, rbac, allowed, mode',
                         configurations_resourceless_white + configurations_resourceless_black)
def test_expose_resourcesless(db_setup, decorator_params, rbac, allowed, mode):
    rbac['rbac_mode'] = mode
    db_setup.rbac.set(rbac)

    def mock_expand_resource(resource):
        return {'*'}

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @db_setup.expose_resources(**decorator_params)
        def framework_dummy():
            pass

        try:
            framework_dummy()
            assert allowed
        except WazuhError as e:
            assert (not allowed)
            assert (e.code == 4000)


def _conf_payload():
    return {
        "auth": {
            "use_password": "yes",
            "ssl_manager_key": "etc/sslmanager.key",
            "key_request": {"enabled": "no"}
        },
        "integration": {
            "secret": "topsecret",
            "token": "abcd-1234"
        },
        "authd.pass": "P4ssW0rd!"
    }


def _conf_result_payload():
    r = AffectedItemsWazuhResult(all_msg="ok", some_msg="ok", none_msg="ok")
    r.affected_items.append({
        "auth": {"use_password": "no", "ssl_manager_key": "etc/sslmanager.key"},
        "integration": {"secret": "topsecret"},
        "authd.pass": "P4ssW0rd!"
    })
    r.total_affected_items = 1
    return r


def test_mask_sensitive_config_without_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    result = get_conf()
    assert result["authd.pass"] == "*****"
    assert result["integration"]["secret"] == "topsecret"


def test_mask_sensitive_config_with_permissions(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white', 'manager:update_config': {'*:*': 'allow'}})

    @db_setup.mask_sensitive_config()
    def get_conf():
        return _conf_payload()

    result = get_conf()
    assert result["authd.pass"] == "P4ssW0rd!"


def test_mask_sensitive_config_on_affected_items_result(db_setup):
    db_setup.rbac.set({'rbac_mode': 'white'})

    @db_setup.mask_sensitive_config()
    def get_conf_result():
        return _conf_result_payload()

    res = get_conf_result()
    item = res.affected_items[0]
    assert item["authd.pass"] == "*****"
    assert item["integration"]["secret"] == "topsecret"
