# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import json
import os
import pytest

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
                             config['allowed_resources']) for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_permissions_black.json') as f:
    configurations_black = [(config['decorator_params'],
                             config['function_params'],
                             config['rbac'],
                             config['fake_system_resources'],
                             config['allowed_resources']) for config in json.load(f)]

with open(test_data_path + 'RBAC_decorators_resourceless_white.json') as f:
    configurations_resourceless_white = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed']) for config in json.load(f)]
with open(test_data_path + 'RBAC_decorators_resourceless_black.json') as f:
    configurations_resourceless_black = [(config['decorator_params'],
                                          config['rbac'],
                                          config['allowed']) for config in json.load(f)]


@pytest.mark.parametrize('decorator_params, function_params, rbac, fake_system_resources, allowed_resources',
                         configurations_black)
@patch('wazuh.rbac.orm.create_engine')
@patch('wazuh.rbac.orm.declarative_base')
@patch('wazuh.rbac.orm.sessionmaker')
def test_expose_resources_black(mock_create_engine, mock_declarative_base, mock_session_maker,
                                decorator_params, function_params, rbac, fake_system_resources, allowed_resources):
    wazuh.rbac.decorators.mode_changer('black')
    def mock_expand_resource(resource):
        fake_values = fake_system_resources.get(resource, resource.split(':')[-1])
        return {fake_values} if isinstance(fake_values, str) else set(fake_values)

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @wazuh.rbac.decorators.expose_resources(**decorator_params)
        def framework_dummy(*args, **kwargs):
            for target_param, allowed_resource in zip(decorator_params['target_params'], allowed_resources):
                assert (set(kwargs[target_param]) == set(allowed_resource))

        try:
            framework_dummy(rbac=rbac, **function_params)
        except WazuhError as e:
            for allowed_resource in allowed_resources:
                print(allowed_resource)
                assert (len(allowed_resource) == 0)
            assert (e.code == 4000)


@pytest.mark.parametrize('decorator_params, function_params, rbac, fake_system_resources, allowed_resources',
                         configurations_white)
@patch('wazuh.rbac.orm.create_engine')
@patch('wazuh.rbac.orm.declarative_base')
@patch('wazuh.rbac.orm.sessionmaker')
def test_expose_resources_white(mock_create_engine, mock_declarative_base, mock_session_maker,
                                decorator_params, function_params, rbac, fake_system_resources, allowed_resources):
    wazuh.rbac.decorators.mode_changer('white')
    def mock_expand_resource(resource):
        fake_values = fake_system_resources.get(resource, resource.split(':')[-1])
        return {fake_values} if isinstance(fake_values, str) else set(fake_values)

    with patch('wazuh.rbac.decorators._expand_resource', side_effect=mock_expand_resource):
        @wazuh.rbac.decorators.expose_resources(**decorator_params)
        def framework_dummy(*args, **kwargs):
            for target_param, allowed_resource in zip(decorator_params['target_params'], allowed_resources):
                assert (set(kwargs[target_param]) == set(allowed_resource))

        try:
            framework_dummy(rbac=rbac, **function_params)
        except WazuhError as e:
            for allowed_resource in allowed_resources:
                assert (len(allowed_resource) == 0)
            assert (e.code == 4000)


@pytest.mark.parametrize('decorator_params, rbac, allowed', configurations_resourceless_white)
@patch('wazuh.rbac.orm.create_engine')
@patch('wazuh.rbac.orm.declarative_base')
@patch('wazuh.rbac.orm.sessionmaker')
def test_expose_resourcesless_black(mock_create_engine, mock_declarative_base, mock_session_maker,
                                    decorator_params, rbac, allowed):
    wazuh.rbac.decorators.mode_changer('white')
    def mock_expand_resource(resource):
        return set()

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


@pytest.mark.parametrize('decorator_params, rbac, allowed', configurations_resourceless_black)
@patch('wazuh.rbac.orm.create_engine')
@patch('wazuh.rbac.orm.declarative_base')
@patch('wazuh.rbac.orm.sessionmaker')
def test_expose_resourcesless_black(mock_create_engine, mock_declarative_base, mock_session_maker,
                                    decorator_params, rbac, allowed):
    wazuh.rbac.decorators.mode_changer('black')
    def mock_expand_resource(resource):
        return set()

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
