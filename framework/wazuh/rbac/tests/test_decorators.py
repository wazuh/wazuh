# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import json
import os
import pytest
import re

import wazuh.rbac.decorators
from wazuh.exception import WazuhError


test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')
permissions = list()
results = list()
with open(test_data_path + 'RBAC_decorators_permissions_white.json') as f:
    configurations_white = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
                             'white') for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_permissions_black.json') as f:
    configurations_black = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources'],
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
        try:
            list_params.append(re.search(r'^([a-z*]+:[a-z*]+:)(\w+|\*|{(\w+)})$', resource).group(3))
        except:
            list_params.append(re.search(r'^([a-z*]+:[a-z*]+:)(\w+|\*|{(\w+)})$', resource).group(2))

    return list_params


@pytest.mark.parametrize('decorator_params, function_params, rbac, fake_system_resources, allowed_resources, mode',
                         configurations_black + configurations_white)
@patch('wazuh.rbac.orm.create_engine')
@patch('wazuh.rbac.orm.declarative_base')
@patch('wazuh.rbac.orm.sessionmaker')
def test_expose_resources(mock_create_engine, mock_declarative_base, mock_session_maker,
                          decorator_params, function_params, rbac, fake_system_resources, allowed_resources, mode):
    wazuh.rbac.decorators.switch_mode(mode)
    def mock_expand_resource(resource):
        fake_values = fake_system_resources.get(resource, resource.split(':')[-1])
        return {fake_values} if isinstance(fake_values, str) else set(fake_values)

    with patch('wazuh.rbac.decorators.rbac') as mock_rbac:
        mock_rbac.get.return_value = rbac
        with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
            @wazuh.rbac.decorators.expose_resources(**decorator_params)
            def framework_dummy(*args, **kwargs):
                for target_param, allowed_resource in zip(get_identifier(decorator_params['resources']),
                                                          allowed_resources):
                    assert (set(kwargs[target_param]) == set(allowed_resource))

            try:
                framework_dummy(rbac=rbac, **function_params)
            except WazuhError as e:
                for allowed_resource in allowed_resources:
                    print(allowed_resource)
                    assert (len(allowed_resource) == 0)
                assert (e.code == 4000)


@pytest.mark.parametrize('decorator_params, rbac, allowed, mode',
                         configurations_resourceless_white + configurations_resourceless_black)
@patch('wazuh.rbac.orm.create_engine')
@patch('wazuh.rbac.orm.declarative_base')
@patch('wazuh.rbac.orm.sessionmaker')
def test_expose_resourcesless(mock_create_engine, mock_declarative_base, mock_session_maker,
                              decorator_params, rbac, allowed, mode):
    wazuh.rbac.decorators.switch_mode(mode)
    def mock_expand_resource(resource):
        return set()

    with patch('wazuh.rbac.decorators.rbac') as mock_rbac:
        mock_rbac.get.return_value = rbac
        with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
            @wazuh.rbac.decorators.expose_resources(**decorator_params)
            def framework_dummy(*args, **kwargs):
                pass

            try:
                framework_dummy(rbac=rbac)
                assert allowed
            except WazuhError as e:
                assert (not allowed)
                assert (e.code == 4000)
