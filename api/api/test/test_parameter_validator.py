# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

"""Verify a rejected parameter is reported by naming the violated constraint, without jsonschema's
exception text: neither the submitted value nor the subschema that rejected it."""

import pytest

import api.validator  # noqa: F401  registers the specification's custom formats
from api.parameter_validator import WazuhParameterValidator


@pytest.mark.parametrize('name, schema, value, expected', [
    ('limit', {'type': 'integer', 'format': 'int32', 'default': 500, 'minimum': 1, 'maximum': 100000}, -1,
     "Invalid value for query parameter 'limit': must be greater than or equal to 1"),
    ('offset', {'type': 'integer', 'format': 'int32', 'default': 0, 'minimum': 0, 'maximum': 2147483647},
     99999999999999999999, "Invalid value for query parameter 'offset': must be less than or equal to 2147483647"),
    ('limit', {'type': 'integer', 'format': 'int32', 'default': 500, 'minimum': 1, 'maximum': 100000}, 'abc',
     "Invalid value for query parameter 'limit': must be of type integer"),
    ('search', {'type': 'string', 'maxLength': 1024}, 'a' * 1025,
     "Invalid value for query parameter 'search': must be at most 1024 characters long"),
    ('group_id', {'type': 'string', 'minLength': 1}, '',
     "Invalid value for query parameter 'group_id': must be at least 1 characters long"),
    ('order', {'type': 'string', 'enum': ['asc', 'desc']}, 'sideways',
     "Invalid value for query parameter 'order': must be one of: asc, desc"),
    ('groups_list', {'type': 'array', 'items': {'type': 'string', 'format': 'group_names'}}, ['\x00'],
     "Invalid value for query parameter 'groups_list': must match the 'group_names' format"),
    ('agent_list', {'type': 'array', 'minItems': 1, 'items': {'type': 'string'}}, [],
     "Invalid value for query parameter 'agent_list': must contain at least 1 item"),
])
def test_validate_parameter_names_the_violated_constraint(name, schema, value, expected):
    """A rejected parameter reports which parameter failed and which constraint it violated."""
    assert WazuhParameterValidator.validate_parameter('query', value, {'name': name, 'schema': schema}) == expected


@pytest.mark.parametrize('schema, value', [
    ({'type': 'string', 'maxLength': 8}, 'secret-value-echoed-back'),
    ({'type': 'array', 'items': {'type': 'string', 'format': 'group_names'}}, ['\x00']),
    ({'type': 'integer', 'minimum': 0}, -1),
    ({'type': 'string', 'enum': ['asc']}, "<script>alert(1)</script>"),
])
def test_validate_parameter_does_not_echo_the_submitted_value(schema, value):
    """The submitted value is never quoted back: the message is what the caller receives."""
    error = WazuhParameterValidator.validate_parameter('query', value, {'name': 'param', 'schema': schema})

    assert str(value) not in error
    for leaked in ('Failed validating', 'On instance', str(schema)):
        assert leaked not in error


def test_validate_parameter_unknown_keyword_does_not_disclose_the_subschema():
    """A keyword with no wording of its own is named, without the schema value behind it."""
    error = WazuhParameterValidator.validate_parameter(
        'query', 'bbb', {'name': 'param', 'schema': {'type': 'string', 'pattern': '^a+$'}})

    assert error == "Invalid value for query parameter 'param': does not satisfy 'pattern'"


@pytest.mark.parametrize('param, value, expected', [
    ({'name': 'limit', 'schema': {'type': 'integer', 'minimum': 1}}, 500, None),
    ({'name': 'limit', 'schema': {'type': 'integer', 'nullable': True}}, 'null', None),
    ({'name': 'agent_id', 'required': True, 'schema': {'type': 'string'}}, None,
     "Missing path parameter 'agent_id'"),
    ({'name': 'limit', 'schema': {'type': 'integer'}}, None, None),
])
def test_validate_parameter_accepted_values(param, value, expected):
    """An accepted value reports nothing, and a missing one keeps connexion's own message."""
    assert WazuhParameterValidator.validate_parameter('path', value, param) == expected
