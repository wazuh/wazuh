# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""The manager configuration surface of spec.yaml follows the configuration schema (etc/wazuh-manager.conf)."""

import json
import os

import pytest
import yaml

api_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
repo_dir = os.path.abspath(os.path.join(api_dir, '..', '..'))
SPEC_PATH = os.path.join(api_dir, 'spec', 'spec.yaml')
# Single source of truth of the manager configuration: the schema shared_modules/manager_config embeds and the
# installer copies to etc/wazuh-manager.schema.json
SCHEMA_PATH = os.path.join(repo_dir, 'src', 'shared_modules', 'manager_config', 'schema', 'wazuh-manager.schema.json')


@pytest.fixture(scope='module')
def spec():
    with open(SPEC_PATH) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope='module')
def schema_sections():
    with open(SCHEMA_PATH) as f:
        return set(json.load(f)['properties'])


def test_wazuh_manager_configuration_schema_matches_the_sections(spec, schema_sections):
    """WazuhManagerConfiguration has exactly one property per top-level section of the schema."""
    properties = spec['components']['schemas']['WazuhManagerConfiguration']['properties']

    assert set(properties) == schema_sections
    assert all(definition == {'type': 'object'} for definition in properties.values())


def test_section_parameter_enum_matches_the_sections(spec, schema_sections):
    """The `section` query parameter accepts exactly the top-level sections of the schema."""
    assert set(spec['components']['parameters']['section']['schema']['enum']) == schema_sections


def test_put_configuration_accepts_yaml_and_octet_stream(spec):
    """PUT /cluster/{node_id}/configuration declares both content types the controller accepts."""
    content = spec['paths']['/cluster/{node_id}/configuration']['put']['requestBody']['content']

    assert set(content) == {'application/xml', 'application/octet-stream'}
    assert all(body['schema'] == {'type': 'string', 'format': 'binary'} for body in content.values())


def test_get_configuration_example_is_effective_document(spec, schema_sections):
    """The GET example only shows sections of the schema, with native types (no XML-era strings)."""
    example = spec['paths']['/cluster/{node_id}/configuration']['get']['responses']['200']['content']
    example = example['application/json']['example']['data']['affected_items'][0]

    assert set(example) <= schema_sections
    assert example['cluster']['hidden'] is False
    assert isinstance(example['cluster']['port'], int)
    assert isinstance(example['remote'], dict)
